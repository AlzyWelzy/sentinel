package main

import "testing"

// The same ids and buckets as api/tests (test_rollout.py): both sides of the
// rollout must pick the same servers for the canary.
func TestHostBucketMatchesTheAPI(t *testing.T) {
	cases := map[string]int{
		"00000000-0000-0000-0000-000000000000": 57,
		"6806cca1-0006-4afb-9288-c5cfc2a1c30b": 47,
	}
	for id, want := range cases {
		if got := hostBucket(id); got != want {
			t.Fatalf("bucket(%s) = %d, want %d", id, got, want)
		}
	}
	if hostBucket("ABC") != hostBucket("abc") {
		t.Fatal("ids are compared lowercase")
	}
}

func TestVersionFor(t *testing.T) {
	p := rolloutPlan{stable: "1.0.0", candidate: "1.1.0", percent: 100, pins: map[string]string{"t-pinned": "0.9.0"}}
	if v := p.versionFor(hostIdentity{HostID: "h", TenantID: "t-pinned"}); v != "0.9.0" {
		t.Fatalf("a pin wins: %s", v)
	}
	if v := p.versionFor(hostIdentity{HostID: "h", TenantID: "t"}); v != "1.1.0" {
		t.Fatalf("100%% candidate: %s", v)
	}
	p.percent = 0
	if v := p.versionFor(hostIdentity{HostID: "h", TenantID: "t"}); v != "1.0.0" {
		t.Fatalf("0%% candidate: %s", v)
	}
}
