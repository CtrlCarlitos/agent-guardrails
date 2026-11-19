package main

import (
	"math"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
)

// processStart is set during package initialisation, as close to process
// start as this binary can observe.
var processStart = time.Now()

// stampHookLatency records how long a hook call took (#456). spawned marks a
// hook run as its own process, where startup time is meaningful; the engine
// daemon serves many calls from one process and records only hook_ms.
func stampHookLatency(rec *audit.Record, started time.Time, spawned bool) {
	if !audit.TimingEnabled() {
		return
	}
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

// percentile is nearest-rank on sorted values.
func percentile(sorted []float64, p int) float64 {
	rank := int(math.Ceil(float64(p) / 100 * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	return sorted[rank-1]
}
