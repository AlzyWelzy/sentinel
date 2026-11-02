package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"
)

// Retry schedule for transient failures; after the last one the message is
// marked failed. The short first steps ride out a console redeploy.
var retryBackoff = []time.Duration{20 * time.Second, 40 * time.Second, 2 * time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 3 * time.Hour}

type dispatcher struct {
	store   *store
	senders map[string]sender
	mail    *emailSender // account emails (verify, reset, invitations)
	log     *slog.Logger
}

func (d *dispatcher) run(ctx context.Context) {
	for ctx.Err() == nil {
		n := d.dispatchOnce(ctx) + d.dispatchAccountEmails(ctx)
		if n == 0 {
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
		}
	}
}

func (d *dispatcher) dispatchOnce(ctx context.Context) int {
	if n, err := d.store.skipStaleHeld(ctx); err != nil {
		d.log.Warn("skipping stale held messages", "err", err)
	} else if n > 0 {
		d.log.Info("held messages skipped: incidents resolved during quiet hours", "count", n)
	}
	if n, err := d.store.skipBlips(ctx); err != nil {
		d.log.Warn("skipping brief outages", "err", err)
	} else if n > 0 {
		d.log.Info("not-reporting alerts skipped: servers were back within the hold", "count", n)
	}
	claimed, err := d.store.claim(ctx, 50)
	if err != nil {
		d.log.Error("claiming outbound messages", "err", err)
		return 0
	}
	for _, g := range groupHostDown(claimed) {
		it := g.item
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
			for _, id := range g.ids {
				if err := d.store.markSent(ctx, id); err != nil {
					d.log.Error("marking message sent", "id", id, "err", err)
				}
			}
			d.log.Info("message sent", "id", it.ID, "kind", it.Kind, "channel_type", it.Channel.Type, "grouped", len(g.ids))
			continue
		}
		var retryIn time.Duration
		if it.Attempts < len(retryBackoff) {
			retryIn = retryBackoff[it.Attempts]
		}
		level := slog.LevelWarn
		if it.Attempts == 0 && !isPermanent(sendErr) {
			level = slog.LevelInfo // the first retry usually gets it through
		}
		d.log.Log(ctx, level, "message not sent", "id", it.ID, "kind", it.Kind, "attempt", it.Attempts+1, "err", sendErr)
		var gone *goneError
		if errors.As(sendErr, &gone) {
			// The browser dropped this subscription: remove the contact so
			// it isn't retried on every alert.
			if err := d.store.deleteChannel(ctx, it.Channel.ID); err != nil {
				d.log.Error("removing expired push subscription", "channel_id", it.Channel.ID, "err", err)
			}
		}
		for _, id := range g.ids {
			if err := d.store.markFailed(ctx, id, sendErr, retryIn); err != nil {
				d.log.Error("recording send failure", "id", id, "err", err)
			}
		}
	}
	return len(claimed)
}

func isPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p)
}

// outgoing is one send: a message, or several merged, and the outbox rows
// it settles.
type outgoing struct {
	item outboxItem
	ids  []string
}

// groupHostDown merges "not reporting" (or "reporting again") emails bound
// for the same contact into one, so servers that drop together, usually a
// network problem in front of them, don't send a message each. Everything
// else goes out as is.
func groupHostDown(items []outboxItem) []outgoing {
	var out []outgoing
	at := map[string]int{}
	for _, it := range items {
		k, _ := it.Payload.Event["kind"].(string)
		groupable := it.Channel.Type == "email" && k == "host_down" &&
			(it.Kind == "alert_firing" || it.Kind == "alert_resolved") && it.Attempts == 0
		key := it.Channel.ID + "|" + it.Kind
		if i, ok := at[key]; ok && groupable {
			out[i].ids = append(out[i].ids, it.ID)
			out[i].item.Payload = mergeHostDown(out[i].item.Payload, it.Payload)
			continue
		}
		if groupable {
			at[key] = len(out)
		}
		out = append(out, outgoing{item: it, ids: []string{it.ID}})
	}
	return out
}

func mergeHostDown(a, b message) message {
	hosts := func(m message) []string {
		if hs, ok := m.Event["hosts"].([]string); ok {
			return hs
		}
		h, _ := m.Event["hostname"].(string)
		return []string{h}
	}
	all := append(append([]string{}, hosts(a)...), hosts(b)...)
	sort.Strings(all)
	resolved := a.Event["type"] == "alert_resolved"
	state, summary := "FIRING", fmt.Sprintf("%d servers are not reporting", len(all))
	condition := "They stopped sending data at the same time, which usually means a network problem in front of them."
	if resolved {
		state, summary = "RESOLVED", fmt.Sprintf("%d servers are reporting again", len(all))
		condition = "They are all sending data again."
	}
	ev := map[string]any{}
	for k, v := range a.Event {
		ev[k] = v
	}
	ev["summary"], ev["condition"], ev["hosts"] = summary, condition, all
	ev["hostname"], ev["detail"] = strings.Join(all, ", "), strings.Join(all, "\n")
	ev["incident_id"], ev["url"] = "", ""
	text := fmt.Sprintf("%s: %s\n\n%s\n\nServers:\n- %s\n\nTime: %s\n",
		state, summary, condition, strings.Join(all, "\n- "), time.Now().UTC().Format(time.RFC1123))
	return message{Subject: "[Sentinel] " + state + ": " + summary, Text: text, Event: ev}
}

// dispatchAccountEmails sends the API's account emails, with the same
// lease and backoff as alerts: a mail server outage delays them, it
// doesn't lose them.
func (d *dispatcher) dispatchAccountEmails(ctx context.Context) int {
	if d.mail == nil {
		return 0
	}
	claimed, err := d.store.claimAccountEmails(ctx, 50)
	if err != nil {
		d.log.Error("claiming account emails", "err", err)
		return 0
	}
	for _, m := range claimed {
		sendCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		sendErr := d.mail.sendMail(sendCtx, m.To, m.Subject, m.Text, m.HTML)
		cancel()
		if sendErr == nil {
			if err := d.store.markAccountEmailSent(ctx, m.ID); err != nil {
				d.log.Error("marking account email sent", "id", m.ID, "err", err)
			}
			d.log.Info("account email sent", "id", m.ID, "kind", m.Kind)
			continue
		}
		var retryIn time.Duration
		if m.Attempts < len(retryBackoff) {
			retryIn = retryBackoff[m.Attempts]
		}
		d.log.Warn("account email not sent", "id", m.ID, "kind", m.Kind, "attempt", m.Attempts+1, "err", sendErr)
		if err := d.store.markAccountEmailFailed(ctx, m.ID, sendErr, retryIn); err != nil {
			d.log.Error("recording account email failure", "id", m.ID, "err", err)
		}
	}
	return len(claimed)
}
