package main

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Key layout shared with the API (api/app/services/heartbeats.py). Change both together.
const (
	lastSeenKey       = "pg:last_seen:"
	hostTokenCacheKey = "pg:host_token:"

	hostTokenCacheTTL = 5 * time.Minute
	lastSeenTTL       = 7 * 24 * time.Hour
)

type cache struct {
	rdb *redis.Client
}

// cachedHost avoids a Postgres lookup on every push. The API deletes the entry
// when a host is removed or its tenant is suspended, so changes apply at once;
// the TTL only bounds staleness if that delete is ever missed.
func (c *cache) cachedHost(ctx context.Context, tokenHash string) (hostIdentity, bool) {
	v, err := c.rdb.Get(ctx, hostTokenCacheKey+tokenHash).Result()
	if err != nil {
		return hostIdentity{}, false
	}
	parts := strings.Split(v, "|")
	if len(parts) != 3 {
		return hostIdentity{}, false
	}
	return hostIdentity{HostID: parts[0], TenantID: parts[1], Active: parts[2] == "1"}, true
}

func (c *cache) storeHost(ctx context.Context, tokenHash string, id hostIdentity) {
	active := "0"
	if id.Active {
		active = "1"
	}
	c.rdb.Set(ctx, hostTokenCacheKey+tokenHash, id.HostID+"|"+id.TenantID+"|"+active, hostTokenCacheTTL)
}

func (c *cache) forgetHost(ctx context.Context, tokenHash string) {
	c.rdb.Del(ctx, hostTokenCacheKey+tokenHash)
}

func (c *cache) markSeen(ctx context.Context, hostID string, at time.Time) error {
	return c.rdb.Set(ctx, lastSeenKey+hostID, strconv.FormatInt(at.Unix(), 10), lastSeenTTL).Err()
}
