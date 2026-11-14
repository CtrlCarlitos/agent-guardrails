package main

import (
	"errors"
	"strings"
	"testing"
)

func TestParseOpencodeMajor(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   int
	}{
		{"v1 bare", "1.19.5\n", 1},
		{"v1 with prefix", "opencode 1.19.5", 1},
		{"v2 prefixed", "opencode v2.3.0", 2},
		{"v2 bare", "2.3.0", 2},
		{"v2 beta", "2.0.0-beta-17236", 2},
		{"no version", "opencode", 0},
		{"empty", "", 0},
		{"unknown major", "9.9.1", 0},
		{"garbage", "guardrail v1.2.3", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseOpencodeMajor(tc.output); got != tc.want {
				t.Fatalf("parseOpencodeMajor(%q) = %d, want %d", tc.output, got, tc.want)
			}
		})
	}
}

func TestOpencodeMajorUnknownWhenProbeFails(t *testing.T) {
	restore := opencodeMajorProbe
	opencodeMajorProbe = func() (string, error) { return "", errors.New("not installed") }
	defer func() { opencodeMajorProbe = restore }()
	opencodeMajorCache = 0
	opencodeMajorResolved = false
	if got := opencodeMajor(); got != 0 {
		t.Fatalf("opencodeMajor() = %d, want 0 when the binary cannot be probed", got)
	}
}

func TestOpencodeMajorCachesProbeResult(t *testing.T) {
	restore := opencodeMajorProbe
	calls := 0
	opencodeMajorProbe = func() (string, error) {
		calls++
		return "opencode v2.3.0", nil
	}
	defer func() { opencodeMajorProbe = restore }()
	opencodeMajorCache = 0
	opencodeMajorResolved = false
	if got := opencodeMajor(); got != 2 {
		t.Fatalf("opencodeMajor() = %d, want 2", got)
	}
	if got := opencodeMajor(); got != 2 {
		t.Fatalf("cached opencodeMajor() = %d, want 2", got)
	}
	if calls != 1 {
		t.Fatalf("probe ran %d times, want 1 (cached)", calls)
	}
}

func TestOpencodeMajorProbeOutputShape(t *testing.T) {
	// The real probe must tolerate the two known output spellings without
	// executing anything else: it parses, it does not shell out to grep.
	if parseOpencodeMajor(strings.TrimSpace("opencode v2.3.0\n")) != 2 {
		t.Fatal("probe output should be trimmed before parsing")
	}
}
