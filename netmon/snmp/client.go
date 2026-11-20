package snmp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Credential describes how to authenticate to an agent. Secrets are plain
// text here; they are encrypted at rest by core and never logged.
type Credential struct {
	Version   string `json:"version"` // "1", "2c", "3"
	Community string `json:"community,omitempty"`
	// SNMPv3
	Username     string `json:"username,omitempty"`
	AuthProtocol string `json:"auth_protocol,omitempty"` // md5 sha sha224 sha256 sha384 sha512
	AuthPassword string `json:"auth_password,omitempty"`
	PrivProtocol string `json:"priv_protocol,omitempty"` // des aes aes192 aes256 aes192c aes256c
	PrivPassword string `json:"priv_password,omitempty"`
	Context      string `json:"context,omitempty"`
}

// Redacted returns a copy safe to log.
func (c Credential) Redacted() Credential {
	if c.Community != "" {
		c.Community = "***"
	}
	if c.AuthPassword != "" {
		c.AuthPassword = "***"
	}
	if c.PrivPassword != "" {
		c.PrivPassword = "***"
	}
	return c
}

// Options tune the transport for one device. Zero values mean defaults.
type Options struct {
	Port           uint16
	Timeout        time.Duration // per request; default 3s
	Retries        int           // default 1
	MaxRepetitions uint32        // GetBulk size; default 10 (gosnmp default of 50 breaks some agents)
	UseGetNext     bool          // never use GetBulk (TP-Link)
	MaxOIDsPerGet  int           // default 20
}

func (o Options) withDefaults() Options {
	if o.Port == 0 {
		o.Port = 161
	}
	if o.Timeout == 0 {
		o.Timeout = 3 * time.Second
	}
	if o.Retries == 0 {
		o.Retries = 1
	}
	if o.MaxRepetitions == 0 {
		o.MaxRepetitions = 10
	}
	if o.MaxOIDsPerGet == 0 {
		o.MaxOIDsPerGet = 20
	}
	return o
}

// Client is a live Session backed by gosnmp. A Client is NOT safe for
// concurrent use; the collector uses one Client per device per worker.
type Client struct {
	g    *gosnmp.GoSNMP
	opts Options
	// BulkFallbacks counts walks where GetBulk returned nothing but GetNext
	// returned rows; the collector persists this as a per-device quirk.
	BulkFallbacks atomic.Int64
	Varbinds      atomic.Int64
}

var authProtocols = map[string]gosnmp.SnmpV3AuthProtocol{
	"": gosnmp.NoAuth, "md5": gosnmp.MD5, "sha": gosnmp.SHA, "sha224": gosnmp.SHA224,
	"sha256": gosnmp.SHA256, "sha384": gosnmp.SHA384, "sha512": gosnmp.SHA512,
}

var privProtocols = map[string]gosnmp.SnmpV3PrivProtocol{
	"": gosnmp.NoPriv, "des": gosnmp.DES, "aes": gosnmp.AES, "aes128": gosnmp.AES,
	"aes192": gosnmp.AES192, "aes256": gosnmp.AES256,
	// "C" variants use the Reeder/Cisco key extension; FortiGate calls it aes256cisco.
	"aes192c": gosnmp.AES192C, "aes256c": gosnmp.AES256C,
}

// Dial creates a Client. No packets are sent until the first request.
func Dial(address string, cred Credential, opts Options) (*Client, error) {
	opts = opts.withDefaults()
	host, port := address, opts.Port
	if h, p, err := net.SplitHostPort(address); err == nil {
		host = h
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err == nil {
			port = uint16(n)
		}
	}
	// A name with both A and AAAA records: UDP can't tell a dead address
	// from a slow one, and network gear often answers SNMP on IPv4 only, so
	// IPv4 comes first. Resolved at every dial, so a moved device is found.
	if net.ParseIP(host) == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("snmp: can't resolve %s: %v", host, err)
		}
		host = ips[0].String()
		for _, ip := range ips {
			if ip.To4() != nil {
				host = ip.String()
				break
			}
		}
	}
	g := &gosnmp.GoSNMP{
		Target:             host,
		Port:               port,
		Transport:          "udp",
		Timeout:            opts.Timeout,
		Retries:            opts.Retries,
		MaxRepetitions:     opts.MaxRepetitions,
		MaxOids:            opts.MaxOIDsPerGet,
		ExponentialTimeout: false,
	}
	switch cred.Version {
	case "1":
		g.Version, g.Community = gosnmp.Version1, cred.Community
	case "2c", "2", "":
		g.Version, g.Community = gosnmp.Version2c, cred.Community
	case "3":
		ap, ok := authProtocols[strings.ToLower(cred.AuthProtocol)]
		if !ok {
			return nil, fmt.Errorf("snmp: unknown auth protocol %q", cred.AuthProtocol)
		}
		pp, ok := privProtocols[strings.ToLower(cred.PrivProtocol)]
		if !ok {
			return nil, fmt.Errorf("snmp: unknown priv protocol %q", cred.PrivProtocol)
		}
		flags := gosnmp.NoAuthNoPriv
		if ap != gosnmp.NoAuth {
			flags = gosnmp.AuthNoPriv
			if pp != gosnmp.NoPriv {
				flags = gosnmp.AuthPriv
			}
		}
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = flags
		g.ContextName = cred.Context
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 cred.Username,
			AuthenticationProtocol:   ap,
			AuthenticationPassphrase: cred.AuthPassword,
			PrivacyProtocol:          pp,
			PrivacyPassphrase:        cred.PrivPassword,
		}
	default:
		return nil, fmt.Errorf("snmp: unsupported version %q", cred.Version)
	}
	if err := g.Connect(); err != nil {
		return nil, fmt.Errorf("snmp: connect %s: %w", host, err)
	}
	return &Client{g: g, opts: opts}, nil
}

// Close implements Session.
func (c *Client) Close() error {
	if c.g.Conn != nil {
		return c.g.Conn.Close()
	}
	return nil
}

// Get implements Session.
func (c *Client) Get(ctx context.Context, oids []string) ([]PDU, error) {
	c.g.Context = ctx
	var out []PDU
	for start := 0; start < len(oids); start += c.opts.MaxOIDsPerGet {
		end := min(start+c.opts.MaxOIDsPerGet, len(oids))
		c.Varbinds.Add(1)
		pkt, err := c.g.Get(oids[start:end])
		if err != nil {
			return out, wrapErr(err)
		}
		if pkt.Error != gosnmp.NoError {
			// v1 agents fail the whole request on one missing OID; retry individually.
			if pkt.Error == gosnmp.NoSuchName && end-start > 1 {
				for _, o := range oids[start:end] {
					one, err := c.Get(ctx, []string{o})
					if err != nil {
						return out, err
					}
					out = append(out, one...)
				}
				continue
			}
			return out, &AgentError{Status: pkt.Error.String(), OID: oids[start]}
		}
		for _, v := range pkt.Variables {
			if p, ok := convert(v); ok {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// Walk implements Session. It uses GetBulk unless the device is known to
// mishandle it, and falls back to GetNext when GetBulk silently returns
// nothing but the subtree exists.
func (c *Client) Walk(ctx context.Context, root string, fn func(PDU) error) error {
	c.g.Context = ctx
	root = NormalizeOID(root)
	n := 0
	walkFn := func(v gosnmp.SnmpPDU) error {
		c.Varbinds.Add(1)
		if p, ok := convert(v); ok {
			n++
			return fn(p)
		}
		return nil
	}
	if c.opts.UseGetNext || c.g.Version == gosnmp.Version1 {
		return wrapErr(c.g.Walk("."+root, walkFn))
	}
	err := c.g.BulkWalk("."+root, walkFn)
	if err == nil && n == 0 {
		// Probe with a single GetNext: if the subtree has data the agent's
		// GetBulk is broken for this table.
		c.g.Context = ctx
		pkt, gerr := c.g.GetNext([]string{"." + root})
		if gerr == nil && len(pkt.Variables) > 0 && HasPrefix(pkt.Variables[0].Name, root) {
			c.BulkFallbacks.Add(1)
			return wrapErr(c.g.Walk("."+root, walkFn))
		}
	}
	return wrapErr(err)
}

func wrapErr(err error) error {
	if err == nil {
		return nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || strings.Contains(err.Error(), "timeout") {
		return fmt.Errorf("%w: %v", ErrTimeout, err)
	}
	if s := err.Error(); strings.Contains(s, "GenErr") || strings.Contains(s, "genErr") {
		return &AgentError{Status: "genErr", OID: s}
	}
	return err
}

func convert(v gosnmp.SnmpPDU) (PDU, bool) {
	p := PDU{OID: NormalizeOID(v.Name)}
	switch v.Type {
	case gosnmp.Integer:
		p.Kind = KindInteger
		p.Int = gosnmp.ToBigInt(v.Value).Int64()
	case gosnmp.OctetString:
		p.Kind = KindOctetString
		b, _ := v.Value.([]byte)
		p.Bytes = b
	case gosnmp.ObjectIdentifier:
		p.Kind = KindOID
		s, _ := v.Value.(string)
		p.Str = NormalizeOID(s)
	case gosnmp.IPAddress:
		p.Kind = KindIPAddress
		s, _ := v.Value.(string)
		p.Str = s
	case gosnmp.Counter32:
		p.Kind, p.Uint = KindCounter32, gosnmp.ToBigInt(v.Value).Uint64()
	case gosnmp.Gauge32, gosnmp.Uinteger32:
		p.Kind, p.Uint = KindGauge32, gosnmp.ToBigInt(v.Value).Uint64()
	case gosnmp.TimeTicks:
		p.Kind, p.Uint = KindTimeTicks, gosnmp.ToBigInt(v.Value).Uint64()
	case gosnmp.Counter64:
		p.Kind, p.Uint = KindCounter64, gosnmp.ToBigInt(v.Value).Uint64()
	case gosnmp.Opaque:
		p.Kind = KindOpaque
		if b, ok := v.Value.([]byte); ok {
			p.Bytes = b
		}
	default: // NoSuchObject, NoSuchInstance, EndOfMibView, Null
		return p, false
	}
	return p, true
}

// ValidAuthProtocol reports whether an SNMPv3 auth protocol name is supported.
func ValidAuthProtocol(p string) bool { _, ok := authProtocols[strings.ToLower(p)]; return ok }

// ValidPrivProtocol reports whether an SNMPv3 privacy protocol name is supported.
func ValidPrivProtocol(p string) bool { _, ok := privProtocols[strings.ToLower(p)]; return ok }
