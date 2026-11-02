package collector

import (
	"context"

	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

// memoryDetail: where memory goes (used, cache, buffers, free, committed),
// swap in bytes, and paging activity as counters the dashboard turns into
// rates. Fields a platform doesn't fill stay out.
func memoryDetail(vm *mem.VirtualMemoryStat, sw *mem.SwapMemoryStat) []proto.Sample {
	var out []proto.Sample
	if vm != nil {
		for kind, v := range map[string]uint64{
			"used": vm.Used, "free": vm.Free, "cached": vm.Cached, "buffers": vm.Buffers,
			"committed": vm.CommittedAS, "slab": vm.Slab, "available": vm.Available,
		} {
			if v > 0 {
				out = append(out, sample("pulsegrid_memory_bytes", float64(v), "kind", kind))
			}
		}
	}
	if sw != nil {
		if sw.Total > 0 {
			out = append(out,
				sample("pulsegrid_swap_bytes", float64(sw.Used), "kind", "used"),
				sample("pulsegrid_swap_bytes", float64(sw.Free), "kind", "free"),
			)
		}
		// Linux reports these (from /proc/vmstat); elsewhere they're zero.
		// gopsutil scales the fault counts by 4 KiB as if they were bytes.
		if sw.PgFault > 0 || sw.PgIn > 0 {
			const gopsutilPage = 4 * 1024
			out = append(out,
				sample("pulsegrid_memory_page_faults_total", float64((sw.PgFault-sw.PgMajFault)/gopsutilPage), "kind", "minor"),
				sample("pulsegrid_memory_page_faults_total", float64(sw.PgMajFault/gopsutilPage), "kind", "major"),
				sample("pulsegrid_memory_pages_total", float64(sw.PgIn), "direction", "in"),
				sample("pulsegrid_memory_pages_total", float64(sw.PgOut), "direction", "out"),
				sample("pulsegrid_swap_io_bytes_total", float64(sw.Sin), "direction", "in"),
				sample("pulsegrid_swap_io_bytes_total", float64(sw.Sout), "direction", "out"),
			)
		}
	}
	return out
}

// systemActivity: processes by state, context switches, interrupts, logged-in
// users, TCP connections by state and pressure stall information.
func systemActivity(ctx context.Context) []proto.Sample {
	var out []proto.Sample
	if misc, err := load.MiscWithContext(ctx); err == nil {
		out = append(out,
			sample("pulsegrid_procs", float64(misc.ProcsRunning), "state", "running"),
			sample("pulsegrid_procs", float64(misc.ProcsBlocked), "state", "blocked"),
		)
		if misc.Ctxt > 0 {
			out = append(out, sample("pulsegrid_context_switches_total", float64(misc.Ctxt)))
		}
	}
	if n, ok := platformUsers(); ok {
		out = append(out, sample("pulsegrid_users_logged_in", float64(n)))
	} else if users, err := host.UsersWithContext(ctx); err == nil {
		out = append(out, sample("pulsegrid_users_logged_in", float64(len(users))))
	}
	out = append(out, platformActivity()...)
	return out
}
