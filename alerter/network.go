package main

// Network rules (kind "network"): conditions on network devices, chosen by
// Target from a catalog. Built-in ones cover interfaces; the rest come from
// the vendor profiles' alert templates (BGP, OSPF, VPN tunnels, SD-WAN,
// sensors, HA), translated to Sentinel's metric names. Each is a filter
// expression: the series it returns are what's wrong, so a device with none
// is fine (unlike metric rules, where no data means unknown).

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/AlzyWelzy/pulsegrid-beyond/netmon/profile"
	"github.com/AlzyWelzy/pulsegrid-beyond/netmon/profiles"
)

type netCondition struct {
	Key   string
	Name  string
	Expr  string // %[1]g is the rule's threshold, when Unit isn't ""
	Unit  string // the threshold's unit; "" means it takes none
	About string // what the series' labels name, for the detail line
}

var builtinNetConditions = []netCondition{
	{Key: "interface_down", Name: "Interface down", About: "ifname",
		// Only ports that were up at some point in the last day: unused ports never alert.
		Expr: `sentinel_net_if_oper_status == 2
			and on(host_id, ifname) sentinel_net_if_admin_status == 1
			and on(host_id, ifname) min_over_time(sentinel_net_if_oper_status[1d] offset 5m) == 1`},
	{Key: "interface_utilisation", Name: "Interface utilisation", Unit: "%", About: "ifname",
		Expr: `(rate(sentinel_net_if_in_octets_total[5m]) * 800 / on(host_id, ifname) (sentinel_net_if_speed_bps > 0) > %[1]g)
			or (rate(sentinel_net_if_out_octets_total[5m]) * 800 / on(host_id, ifname) (sentinel_net_if_speed_bps > 0) > %[1]g)`},
	{Key: "interface_errors", Name: "Interface errors", Unit: "errors/s", About: "ifname",
		Expr: `rate(sentinel_net_if_in_errors_total[5m]) + on(host_id, ifname) rate(sentinel_net_if_out_errors_total[5m]) > %[1]g`},
	{Key: "lag_member_down", Name: "LAG member down", About: "ifname",
		Expr: `(sentinel_net_if_oper_status == 2 and on(host_id, ifname) sentinel_net_if_admin_status == 1)
			* on(host_id, ifname) group_left(lag) sentinel_net_lag_member_info`},
	{Key: "device_rebooted", Name: "Device rebooted", About: "",
		Expr: `sentinel_net_device_uptime_seconds < 600`},
}

var (
	netCatalogOnce sync.Once
	netCatalog     map[string]netCondition
)

var (
	slugRe          = regexp.MustCompile(`[^a-z0-9]+`)
	profileLabelRe  = regexp.MustCompile(`,?\s*profile\s*=~?\s*"[^"]*"`)
	emptyMatchersRe = regexp.MustCompile(`\{\s*,?\s*\}`)
)

// translateExpr turns a profile's alert expression into Sentinel's names:
// beacon_x -> sentinel_net_x, device_id -> host_id; the profile label isn't
// stored (each vendor's metrics only exist on its devices anyway).
func translateExpr(expr string) string {
	e := strings.ReplaceAll(expr, "beacon_", "sentinel_net_")
	e = regexp.MustCompile(`\bdevice_id\b`).ReplaceAllString(e, "host_id")
	e = profileLabelRe.ReplaceAllString(e, "")
	e = strings.ReplaceAll(e, "{,", "{")
	return emptyMatchersRe.ReplaceAllString(e, "")
}

func networkConditions() map[string]netCondition {
	netCatalogOnce.Do(func() {
		netCatalog = map[string]netCondition{}
		for _, c := range builtinNetConditions {
			netCatalog[c.Key] = c
		}
		reg, err := profile.Load(profiles.FS)
		if err != nil {
			return
		}
		for _, name := range reg.Names() {
			p, _ := reg.Get(name)
			for _, a := range p.Alerts {
				key := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(a.Name), "_"), "_")
				if _, dup := netCatalog[key]; dup || key == "" {
					continue
				}
				netCatalog[key] = netCondition{Key: key, Name: a.Name, Expr: translateExpr(a.Expr)}
			}
		}
	})
	return netCatalog
}

func networkExpr(r rule) (string, netCondition, error) {
	c, ok := networkConditions()[r.Target]
	if !ok {
		return "", c, fmt.Errorf("unknown network condition %q", r.Target)
	}
	if c.Unit != "" {
		return fmt.Sprintf(c.Expr, r.Threshold), c, nil
	}
	return c.Expr, c, nil
}

// networkObservations evaluates a network rule for the devices it covers.
// Servers in its scope (an "all servers" rule) are left without data.
func (e *evaluator) networkObservations(ctx context.Context, r rule, hosts []host) (map[string]observation, error) {
	expr, _, err := networkExpr(r)
	if err != nil {
		return nil, err
	}
	series, err := e.querySeries(ctx, r.TenantID, expr)
	if err != nil {
		return nil, err // never resolve on a failed query
	}
	worst := map[string]float64{}
	for _, s := range series {
		h := s.labels["host_id"]
		if v, ok := worst[h]; !ok || s.value > v {
			worst[h] = s.value
		}
	}
	out := map[string]observation{}
	for _, h := range hosts {
		if !h.Network {
			continue
		}
		v, hit := worst[h.ID]
		out[h.ID] = observation{HasData: true, Breached: hit, Value: v}
	}
	return out, nil
}

// networkDetail names what a network alert is about on this device: the
// ports, peers, tunnels or sensors whose series matched, five at most.
func (e *evaluator) networkDetail(ctx context.Context, r rule, h host) string {
	expr, _, err := networkExpr(r)
	if err != nil {
		return ""
	}
	series, err := e.querySeries(ctx, r.TenantID, expr)
	if err != nil {
		return ""
	}
	var parts []string
	for _, s := range series {
		if s.labels["host_id"] != h.ID {
			continue
		}
		var labels []string
		for k, v := range s.labels {
			switch k {
			case "__name__", "host_id", "tenant_id", "index":
				continue
			}
			labels = append(labels, k+"="+v)
		}
		sort.Strings(labels)
		p := strings.Join(labels, " ")
		if p == "" {
			p = strconv.FormatFloat(s.value, 'g', 4, 64)
		}
		parts = append(parts, p)
	}
	sort.Strings(parts)
	more := ""
	if len(parts) > 5 {
		more = fmt.Sprintf(" (and %d more)", len(parts)-5)
		parts = parts[:5]
	}
	return strings.Join(parts, "; ") + more
}
