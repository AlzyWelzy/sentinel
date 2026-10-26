//go:build !linux

package collector

import "github.com/example-org/pulsegrid/proto"

func platformActivity() []proto.Sample { return nil }

func linkInfo(string) (float64, float64, bool) { return 0, 0, false }

func platformUsers() (int, bool) { return 0, false }
