package proto

import (
	"bytes"
	"os"
	"testing"
)

func TestPlanCatalogMatchesAPI(t *testing.T) {
	api, err := os.ReadFile("../api/app/data/plans.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(api, plansJSON) {
		t.Fatal("api/app/data/plans.json differs from proto/plans.json: copy it over")
	}
	if PlanByID("free").Limits.Hosts == nil || PlanByID("grandfathered").Limits.Hosts != nil {
		t.Fatal("free must be limited and grandfathered not")
	}
	if PlanByID("nope").ID != "free" {
		t.Fatal("unknown plans fall back to free")
	}
}
