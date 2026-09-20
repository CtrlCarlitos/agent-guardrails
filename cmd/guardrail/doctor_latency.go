package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"time"
)

const (
	spawnProbeSamples      = 5
	spawnProbeWarnBelow    = 2 * time.Second
	spawnProbeSampleBudget = 15 * time.Second
)

// spawnLatencyVerdict returns the nearest-rank p95 of the samples and a
// warning when per-spawn cost is high enough to threaten planes' hook
// budgets — every tool call pays this cost, and at some budget it fails
// closed (the #132 failure mode).
func spawnLatencyVerdict(samples []time.Duration) (time.Duration, string) {
	if len(samples) == 0 {
		return 0, ""
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	rank := (len(sorted)*95+99)/100 - 1
	if rank < 0 {
		rank = 0
	}
	p95 := sorted[rank]
	if p95 < spawnProbeWarnBelow {
		return p95, ""
	}
	return p95, fmt.Sprintf("spawn latency: p95 %s over %d samples — per-spawn cost this high fails planes' hook budgets closed; check the AV/Defender exclusion for the binary path and system load, and see the runbook (#132)", p95, len(samples))
}

func printSpawnProbeWithSampler(stdout io.Writer, sampler func() time.Duration) {
	samples := make([]time.Duration, 0, spawnProbeSamples)
	for i := 0; i < spawnProbeSamples; i++ {
		samples = append(samples, sampler())
	}
	p95, warning := spawnLatencyVerdict(samples)
	if warning != "" {
		fmt.Fprintln(stdout, warning)
		return
	}
	fmt.Fprintf(stdout, "spawn latency: p95 %s over %d samples (ok)\n", p95, len(samples))
}

// selfSpawnSampler measures the wall time of spawning this binary's own
// `version` subcommand: CreateProcess, AV scan, and startup — the exact cost
// every plane's hook pays per tool call. `version` writes no audit record.
func selfSpawnSampler() func() time.Duration {
	return func() time.Duration {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), spawnProbeSampleBudget)
		defer cancel()
		_ = exec.CommandContext(ctx, os.Args[0], "version").Run()
		return time.Since(start)
	}
}

// printSpawnProbe reports self-spawn latency, except inside test binaries
// where re-exec would run the test suite recursively — the #58 rule: exec
// the installed binary, never the in-process test binary.
func printSpawnProbe(stdout io.Writer) {
	if flag.Lookup("test.v") != nil {
		return
	}
	printSpawnProbeWithSampler(stdout, selfSpawnSampler())
}
