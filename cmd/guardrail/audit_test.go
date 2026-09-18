package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
)

func TestAuditSummaryAggregatesAcrossSegments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	records := []audit.Record{
		{Plane: "opencode", Decision: "allow", RuleID: ""},
		{Plane: "opencode", Decision: "deny", RuleID: "P1.rm-rf"},
		{Plane: "claude", Decision: "deny", RuleID: "P1.rm-rf"},
		{Plane: "claude", Decision: "ask", RuleID: "unknown-native-tool", NativeTool: "brand_new_thing"},
		{Plane: "codex", Decision: "deny", RuleID: "P1.rm-rf"},
	}
	for _, rec := range records {
		if err := audit.Write(rec, path); err != nil {
			t.Fatal(err)
		}
	}
	// Force a rotated segment by moving the file and writing one more.
	if err := os.Rename(path, filepath.Join(dir, "audit-20260101-000000.000000000.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := audit.Write(audit.Record{Plane: "operator", Decision: "complete", RuleID: "operator-action"}, path); err != nil {
		t.Fatal(err)
	}

	var out, errb strings.Builder
	if code := run([]string{"audit", "--path", path}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d stderr %q", code, errb.String())
	}
	got := out.String()
	for _, want := range []string{
		"records: 6",
		"allow=1 ask=1 deny=3 complete=1",
		"claude=2 opencode=2 antigravity=0 codex=1 operator=1",
		"P1.rm-rf",
		"brand_new_thing",
		"segment(s)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary missing %q:\n%s", want, got)
		}
	}
}

func TestAuditRejectsBadArguments(t *testing.T) {
	var out, errb strings.Builder
	if code := run([]string{"audit", "--nope"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("exit = %d", code)
	}
}
