package proto

import (
	_ "embed"
	"encoding/json"
)

// The plan catalog, shared with the API (api/app/data/plans.json; a test
// keeps the two equal). A nil limit means none.

//go:embed plans.json
var plansJSON []byte

type PlanLimits struct {
	Hosts       *int `json:"hosts"`
	Checks      *int `json:"checks"`
	StatusPages *int `json:"status_pages"`
	Members     *int `json:"members"`
	IPDR        bool `json:"ipdr"`
}

type Plan struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	PriceMonthly int        `json:"price_monthly"`
	Hidden       bool       `json:"hidden,omitempty"`
	Limits       PlanLimits `json:"limits"`
}

var plans = func() map[string]Plan {
	var c struct {
		Plans []Plan `json:"plans"`
	}
	if err := json.Unmarshal(plansJSON, &c); err != nil {
		panic("proto/plans.json: " + err.Error())
	}
	m := make(map[string]Plan, len(c.Plans))
	for _, p := range c.Plans {
		m[p.ID] = p
	}
	return m
}()

// PlanByID returns the plan, or the free plan for an unknown id.
func PlanByID(id string) Plan {
	if p, ok := plans[id]; ok {
		return p
	}
	return plans["free"]
}
