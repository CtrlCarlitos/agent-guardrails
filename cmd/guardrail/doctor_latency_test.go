package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestSpawnLatencyVerdictHealthySamplesWarnNothing(t *testing.T) {
	samples := []time.Duration{
		90 * time.Millisecond,
		120 * time.Millisecond,
		150 * time.Millisecond,
		180 * time.Millisecond,
		210 * time.Millisecond,
	}
	p95, warning := spawnLatencyVerdict(samples)
	if p95 != 210*time.Millisecond {
		t.Fatalf("p95 = %v, want the nearest-rank 210ms", p95)
	}
	if warning != "" {
		t.Fatalf("healthy samples produced a warning: %q", warning)
	}
}

func TestSpawnLatencyVerdictSlowSamplesWarnWithIssueReference(t *testing.T) {
	samples := []time.Duration{
		3 * time.Second,
		4 * time.Second,
		5 * time.Second,
		6 * time.Second,
		7 * time.Second,
	}
	_, warning := spawnLatencyVerdict(samples)
	if warning == "" {
		t.Fatal("slow samples produced no warning")
	}
	if !strings.Contains(warning, "#132") {
		t.Fatalf("warning %q must reference #132 for the runbook path", warning)
	}
	if !strings.Contains(warning, "5.4s") && !strings.Contains(warning, "p95") {
		t.Fatalf("warning %q must carry the measured p95", warning)
	}
}

func TestSpawnLatencyVerdictEmptySamplesAreSilent(t *testing.T) {
	if _, warning := spawnLatencyVerdict(nil); warning != "" {
		t.Fatalf("no samples must not warn: %q", warning)
	}
}

func TestPrintSpawnProbeWithSamplerReportsOkLine(t *testing.T) {
	var out bytes.Buffer
	printSpawnProbeWithSampler(&out, func() time.Duration { return 150 * time.Millisecond })
	line := out.String()
	if !strings.HasPrefix(line, "spawn latency: ") {
		t.Fatalf("output %q lacks the spawn latency prefix", line)
	}
	if !strings.Contains(line, "ok") {
		t.Fatalf("output %q should report ok", line)
	}
}

func TestPrintSpawnProbeWithSamplerWarnsWhenSlow(t *testing.T) {
	var out bytes.Buffer
	printSpawnProbeWithSampler(&out, func() time.Duration { return 9 * time.Second })
	if !strings.Contains(out.String(), "#132") {
		t.Fatalf("output %q should carry the #132 warning", out.String())
	}
}
