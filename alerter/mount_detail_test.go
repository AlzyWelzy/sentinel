package main

import "testing"

func TestFormatMountsListsBreachingMountsFullestFirst(t *testing.T) {
	used := map[string]float64{"/": 50, "/var": 94.6, "/home": 91, "": 99}
	free := map[string]float64{"/var": 2.1 * 1024 * 1024 * 1024, "/home": 512 * 1024 * 1024}
	got := formatMounts(used, free, func(m string) bool { return used[m] > 90 })
	if want := "/var 94.6% used, 2.1 GB free; /home 91.0% used, 512.0 MB free"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFormatMountsWithoutFreeBytes(t *testing.T) {
	used := map[string]float64{"/data": 97}
	got := formatMounts(used, map[string]float64{}, func(string) bool { return true })
	if got != "/data 97.0% used" {
		t.Fatalf("got %q", got)
	}
}

func TestFormatMountsNothingBreaching(t *testing.T) {
	if got := formatMounts(map[string]float64{"/": 10}, nil, func(string) bool { return false }); got != "" {
		t.Fatalf("got %q", got)
	}
}
