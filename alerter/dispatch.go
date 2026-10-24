package main

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// Retry schedule for transient failures; after the last one the message is
// marked failed. Roughly 1m, 5m, 15m, 1h, 3h.
var retryBackoff = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 3 * time.Hour}

type dispatcher struct {
	store   *store
	senders map[string]sender
	log     *slog.Logger
}

func (d *dispatcher) run(ctx context.Context) {
	for ctx.Err() == nil {
		n := d.dispatchOnce(ctx)
		if n == 0 {
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
		}
	}
}

func (d *dispatcher) dispatchOnce(ctx context.Context) int {
	items, err := d.store.claim(ctx, 50)
	if err != nil {
		d.log.Error("claiming outbound messages", "err", err)
		return 0
	}
	for _, it := range items {
		s, ok := d.senders[it.Channel.Type]
		var sendErr error
		if !ok {
			sendErr = permanent("no sender for channel type %q", it.Channel.Type)
		} else {
			sendCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
			if cs, ok := s.(configSender); ok {
				sendErr = cs.sendWithConfig(sendCtx, it.Channel.Target, it.Channel.Config, it.Payload)
			} else {
				sendErr = s.send(sendCtx, it.Channel.Target, it.Payload)
			}
			cancel()
		}
		if sendErr == nil {
			if err := d.store.markSent(ctx, it.ID); err != nil {
				d.log.Error("marking message sent", "id", it.ID, "err", err)
			}
			d.log.Info("message sent", "id", it.ID, "kind", it.Kind, "channel_type", it.Channel.Type)
			continue
		}
		var retryIn time.Duration
		if it.Attempts < len(retryBackoff) {
			retryIn = retryBackoff[it.Attempts]
		}
		d.log.Warn("message not sent", "id", it.ID, "kind", it.Kind, "attempt", it.Attempts+1, "err", sendErr)
		var gone *goneError
		if errors.As(sendErr, &gone) {
			// The browser dropped this subscription: remove the contact so
			// it isn't retried on every alert.
			if err := d.store.deleteChannel(ctx, it.Channel.ID); err != nil {
				d.log.Error("removing expired push subscription", "channel_id", it.Channel.ID, "err", err)
			}
		}
		if err := d.store.markFailed(ctx, it.ID, sendErr, retryIn); err != nil {
			d.log.Error("recording send failure", "id", it.ID, "err", err)
		}
	}
	return len(items)
}
