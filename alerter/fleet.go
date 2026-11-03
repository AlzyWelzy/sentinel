package main

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// When Sentinel itself can't receive data (ingest down, the edge proxy down,
// the server's network out), every customer's servers fall silent together.
// Sending each of them "not reporting" for every server would be wrong and
// loud, so host_down rules hold while the silence looks like ours: no server
// anywhere has reported for a while, and just before that servers in several
// organisations were. A single organisation's outage (say, 40 servers behind
// one NAT) still alerts: the others keep reporting, or if it's the only
// organisation there's nothing to tell it from ours.
const (
	fleetSeenKey = "pg:fleet:seen" // written by ingest/cache.go
	fleetWindow  = 24 * time.Hour  // what ingest keeps; a long outage still holds

	// Nobody reporting for this long is the outage signal: agents push every
	// 30 s, so a healthy fleet of any size never goes this long.
	fleetQuietFor = 90 * time.Second
	// Who counts: servers that reported within this long of the last push
	// anywhere. Servers that went dark earlier (uninstalled, abandoned
	// trials) don't make a silence look like ours.
	fleetVoters = 5 * time.Minute

	fleetMinHosts   = 5
	fleetMinTenants = 3
)

type seen struct {
	tenant string
	at     time.Time
}

// fleetOutage reports whether the silence looks like Sentinel's own.
func fleetOutage(hosts []seen, now time.Time) bool {
	var newest time.Time
	for _, h := range hosts {
		if h.at.After(newest) {
			newest = h.at
		}
	}
	if newest.IsZero() || now.Sub(newest) < fleetQuietFor {
		return false // someone is still getting through
	}
	voters, tenants := 0, map[string]bool{}
	for _, h := range hosts {
		if newest.Sub(h.at) <= fleetVoters {
			voters++
			tenants[h.tenant] = true
		}
	}
	return voters >= fleetMinHosts && len(tenants) >= fleetMinTenants
}

// platformSilent reads the fleet and decides once per evaluation pass. A
// Redis error isn't an outage: alert as usual.
func (e *evaluator) platformSilent(ctx context.Context) bool {
	now := time.Now()
	zs, err := e.rdb.ZRangeByScoreWithScores(ctx, fleetSeenKey, &redis.ZRangeBy{
		Min: strconv.FormatInt(now.Add(-fleetWindow).Unix(), 10), Max: "+inf",
	}).Result()
	if err != nil {
		e.log.Error("reading fleet heartbeats", "err", err)
		return false
	}
	hosts := make([]seen, 0, len(zs))
	for _, z := range zs {
		m, _ := z.Member.(string)
		tenant, _, _ := strings.Cut(m, ":")
		hosts = append(hosts, seen{tenant: tenant, at: time.Unix(int64(z.Score), 0)})
	}
	if fleetOutage(hosts, now) {
		e.log.Error("most servers in most organisations stopped reporting at once: "+
			"holding 'not reporting' alerts, check ingest and the edge proxy", "servers", len(hosts))
		return true
	}
	return false
}
