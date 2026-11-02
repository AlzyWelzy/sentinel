package plugins

// SNMP: poll a network device (switch, router, firewall, UPS, printer)
// from this server. One file per device:
//
//	type = snmp
//	address = 10.0.0.2          (port 161 unless given)
//	community = public          (v2c, the default)
//	version = 3                 (or v3 with the settings below)
//	user = monitor
//	auth_protocol = sha256      (md5, sha, sha224, sha256, sha384, sha512)
//	auth_password = ...
//	priv_protocol = aes         (des, aes, aes192, aes256)
//	priv_password = ...
//	interfaces = true           (traffic and status per interface)
//	oids = ups_load=1.3.6.1.2.1.33.1.4.4.1.5.1, temp=1.3.6.1.4.1.9.9.13.1.3.1.3.1

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

const (
	oidSysUpTime   = ".1.3.6.1.2.1.1.3.0"
	oidIfName      = ".1.3.6.1.2.1.31.1.1.1.1"
	oidIfHCIn      = ".1.3.6.1.2.1.31.1.1.1.6"
	oidIfHCOut     = ".1.3.6.1.2.1.31.1.1.1.10"
	oidIfOper      = ".1.3.6.1.2.1.2.2.1.8"
	maxInterfaces  = 256
	maxCustomOIDs  = 50
	snmpTimeout    = 3 * time.Second
	snmpRetries    = 1
	customNamePart = `[a-z][a-z0-9_]{0,60}`
)

var customOIDName = regexp.MustCompile(`^` + customNamePart + `$`)
var oidRe = regexp.MustCompile(`^\.?[0-9]+(\.[0-9]+)+$`)

// SNMPClient builds a configured (not yet connected) client from settings.
func SNMPClient(set map[string]string) (*gosnmp.GoSNMP, error) {
	addr := set["address"]
	if addr == "" {
		return nil, errors.New("address is required")
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host, portStr = addr, "161"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("bad port in %q", addr)
	}
	g := &gosnmp.GoSNMP{Target: host, Port: uint16(port), Timeout: snmpTimeout, Retries: snmpRetries, MaxOids: 60, MaxRepetitions: 25}
	switch strings.TrimPrefix(strings.ToLower(orDefault(set["version"], "2c")), "v") {
	case "2c", "2":
		g.Version = gosnmp.Version2c
		g.Community = orDefault(set["community"], "public")
	case "1":
		g.Version = gosnmp.Version1
		g.Community = orDefault(set["community"], "public")
	case "3":
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		usm := &gosnmp.UsmSecurityParameters{UserName: set["user"]}
		if usm.UserName == "" {
			return nil, errors.New("v3 needs user")
		}
		flags := gosnmp.NoAuthNoPriv
		if p := set["auth_password"]; p != "" {
			proto, ok := map[string]gosnmp.SnmpV3AuthProtocol{
				"md5": gosnmp.MD5, "sha": gosnmp.SHA, "sha224": gosnmp.SHA224, "sha256": gosnmp.SHA256,
				"sha384": gosnmp.SHA384, "sha512": gosnmp.SHA512,
			}[strings.ToLower(orDefault(set["auth_protocol"], "sha256"))]
			if !ok {
				return nil, fmt.Errorf("unknown auth_protocol %q", set["auth_protocol"])
			}
			usm.AuthenticationProtocol, usm.AuthenticationPassphrase = proto, p
			flags = gosnmp.AuthNoPriv
			if pp := set["priv_password"]; pp != "" {
				priv, ok := map[string]gosnmp.SnmpV3PrivProtocol{
					"des": gosnmp.DES, "aes": gosnmp.AES, "aes192": gosnmp.AES192, "aes256": gosnmp.AES256,
				}[strings.ToLower(orDefault(set["priv_protocol"], "aes"))]
				if !ok {
					return nil, fmt.Errorf("unknown priv_protocol %q", set["priv_protocol"])
				}
				usm.PrivacyProtocol, usm.PrivacyPassphrase = priv, pp
				flags = gosnmp.AuthPriv
			}
		}
		g.MsgFlags = flags
		g.SecurityParameters = usm
	default:
		return nil, fmt.Errorf("version must be 1, 2c or 3")
	}
	return g, nil
}

// CustomOIDs parses "name=oid, name=oid".
func CustomOIDs(v string) (map[string]string, error) {
	out := map[string]string{}
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, oid, ok := strings.Cut(item, "=")
		name, oid = strings.TrimSpace(name), strings.TrimSpace(oid)
		if !ok || !customOIDName.MatchString(name) || !oidRe.MatchString(oid) {
			return nil, fmt.Errorf("oids: %q should be name=1.3.6.1... (lowercase name)", item)
		}
		if !strings.HasPrefix(oid, ".") {
			oid = "." + oid
		}
		out[name] = oid
	}
	if len(out) > maxCustomOIDs {
		return nil, fmt.Errorf("at most %d oids", maxCustomOIDs)
	}
	return out, nil
}

func snmpNumber(v gosnmp.SnmpPDU) (float64, bool) {
	switch v.Type {
	case gosnmp.Integer, gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks, gosnmp.Counter64, gosnmp.Uinteger32:
		f, _ := new(big.Float).SetInt(gosnmp.ToBigInt(v.Value)).Float64()
		return f, true
	case gosnmp.OctetString:
		// Some devices report numbers as strings.
		b, _ := v.Value.([]byte)
		f, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
		return f, err == nil
	}
	return 0, false
}

func collectSNMP(ctx context.Context, c Config) ([]proto.Sample, error) {
	g, err := SNMPClient(c.Settings)
	if err != nil {
		return nil, err
	}
	custom, err := CustomOIDs(c.Settings["oids"])
	if err != nil {
		return nil, err
	}
	g.Context = ctx
	if err := g.Connect(); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer g.Conn.Close()

	var out []proto.Sample
	res, err := g.Get([]string{oidSysUpTime})
	if err != nil {
		return nil, fmt.Errorf("no answer from %s: %w", c.Settings["address"], err)
	}
	if len(res.Variables) == 1 {
		if v, ok := snmpNumber(res.Variables[0]); ok {
			out = append(out, sample("pulsegrid_custom_snmp_uptime_seconds", v/100))
		}
	}

	if len(custom) > 0 {
		names := make([]string, 0, len(custom))
		oids := make([]string, 0, len(custom))
		for n, o := range custom {
			names = append(names, n)
			oids = append(oids, o)
		}
		if r, err := g.Get(oids); err == nil {
			for _, v := range r.Variables {
				for i, o := range oids {
					if v.Name == o {
						if f, ok := snmpNumber(v); ok {
							out = append(out, sample("pulsegrid_custom_snmp_"+names[i], f))
						}
					}
				}
			}
		}
	}

	if orDefault(c.Settings["interfaces"], "true") == "true" {
		names := map[string]string{}
		walk := func(root string, fn func(idx string, pdu gosnmp.SnmpPDU)) {
			n := 0
			g.BulkWalk(root, func(pdu gosnmp.SnmpPDU) error {
				n++
				if n > maxInterfaces {
					return errors.New("enough")
				}
				fn(strings.TrimPrefix(pdu.Name, root+"."), pdu)
				return nil
			})
		}
		walk(oidIfName, func(idx string, pdu gosnmp.SnmpPDU) {
			if b, ok := pdu.Value.([]byte); ok {
				names[idx] = string(b)
			}
		})
		label := func(idx string) string {
			if n := names[idx]; n != "" {
				return n
			}
			return "if" + idx
		}
		for _, m := range []struct{ oid, metric string }{
			{oidIfHCIn, "pulsegrid_custom_snmp_if_in_bytes_total"},
			{oidIfHCOut, "pulsegrid_custom_snmp_if_out_bytes_total"},
		} {
			walk(m.oid, func(idx string, pdu gosnmp.SnmpPDU) {
				if v, ok := snmpNumber(pdu); ok {
					out = append(out, sample(m.metric, v, "interface", label(idx)))
				}
			})
		}
		walk(oidIfOper, func(idx string, pdu gosnmp.SnmpPDU) {
			if v, ok := snmpNumber(pdu); ok {
				out = append(out, sample("pulsegrid_custom_snmp_if_up", boolValue(v == 1), "interface", label(idx)))
			}
		})
	}
	return out, nil
}
