package main

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

// processStart is set during package initialisation, as close to process
// start as this binary can observe.
var processStart = time.Now()

// stampHookLatency records how long a hook call took (#456). spawned marks a
// hook run as its own process, where startup time is meaningful; the engine
// daemon serves many calls from one process and records only hook_ms.
func stampHookLatency(rec *audit.Record, started time.Time, spawned bool) {
	rec.HookMS = millis(time.Since(started))
	if spawned {
		rec.StartupMS = millis(started.Sub(processStart))
	}
}

func millis(d time.Duration) float64 {
	// Microsecond resolution, never zero: 0 means "not measured" (a record
	// written before #456), and a fail-closed parse can finish in microseconds.
	return math.Max(0.001, float64(d.Microseconds())/1000)
}

// hookLatencyLatestPerPlane bounds the summary to recent behaviour.
const hookLatencyLatestPerPlane = 200

// hookLatencyLine summarizes recorded hook time per plane for doctor:
// p50/p95 over the latest measured records of real sessions. Selftest probes
// and records written before #456 are left out. Empty when nothing is
// measured yet.
func hookLatencyLine(recs []audit.Record) string {
	type sample struct {
		ms     []float64
		daemon int
	}
	byPlane := map[string]*sample{}
	for i := len(recs) - 1; i >= 0; i-- {
		r := recs[i]
		if r.HookMS <= 0 || strings.HasPrefix(r.SessionID, "selftest") {
			continue
		}
		s := byPlane[r.Plane]
		if s == nil {
			s = &sample{}
			byPlane[r.Plane] = s
		}
		if len(s.ms) >= hookLatencyLatestPerPlane {
			continue
		}
		s.ms = append(s.ms, r.HookMS)
		if r.Transport == "named-pipe-daemon" {
			s.daemon++
		}
	}
	if len(byPlane) == 0 {
		return ""
	}
	planes := make([]string, 0, len(byPlane))
	for p := range byPlane {
		planes = append(planes, p)
	}
	sort.Strings(planes)
	parts := make([]string, 0, len(planes))
	for _, p := range planes {
		s := byPlane[p]
		sort.Float64s(s.ms)
		part := fmt.Sprintf("%s p50 %s p95 %s ms (n=%d", p, trimMS(percentile(s.ms, 50)), trimMS(percentile(s.ms, 95)), len(s.ms))
		if s.daemon > 0 {
			part += fmt.Sprintf(", %d via daemon", s.daemon)
		}
		parts = append(parts, part+")")
	}
	return "hook latency (in-process, latest real calls): " + strings.Join(parts, "; ")
}

// percentile is nearest-rank on sorted values.
func percentile(sorted []float64, p int) float64 {
	rank := int(math.Ceil(float64(p) / 100 * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	return sorted[rank-1]
}

func trimMS(v float64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", v), "0"), ".")
}

// printHookLatency writes the per-plane summary when the audit log holds any
// measured calls. Informational: it is data for the spawn-versus-server
// question (#456), not a problem doctor counts.
func printHookLatency(stdout io.Writer, path string) {
	segments, err := audit.Segments(path)
	if err != nil {
		return
	}
	recs, _, err := audit.ReadRecords(segments)
	if err != nil {
		return
	}
	if line := hookLatencyLine(recs); line != "" {
		fmt.Fprintln(stdout, safetext.SingleLine(line))
	}
}
