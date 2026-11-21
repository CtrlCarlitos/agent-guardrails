package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
)

func withTailContext(t *testing.T, fn func() (context.Context, context.CancelFunc)) {
	t.Helper()
	prev := tailContext
	tailContext = fn
	t.Cleanup(func() { tailContext = prev })
}

func TestTailCommandFormatsCompactAndJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	records := []audit.Record{
		{
			TS:         "2026-11-21T19:42:01.124Z",
			Plane:      "antigravity",
			Tool:       "Read",
			NativeTool: "read_file",
			Paths:      []string{"/src/main.go"},
			Decision:   "allow",
			HookMS:     0.2,
		},
		{
			TS:         "2026-11-21T19:42:05.482Z",
			Plane:      "antigravity",
			Tool:       "Read",
			NativeTool: "read_file",
			Paths:      []string{"/project/.env"},
			Decision:   "deny",
			RuleID:     "P4.secret-path",
			HookMS:     0.1,
		},
		{
			TS:       "2026-11-21T19:42:12.809Z",
			Plane:    "claude",
			Tool:     "Bash",
			Command:  "git push origin main",
			Decision: "ask",
			RuleID:   "P2.git-push-protected",
			HookMS:   0.4,
		},
	}
	for _, rec := range records {
		if err := audit.Write(rec, path); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("compact format", func(t *testing.T) {
		withTailContext(t, func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 120*time.Millisecond)
		})
		var out, errb strings.Builder
		code := run([]string{"tail", "--path", path, "--lines", "3"}, strings.NewReader(""), &out, &errb)
		if code != 0 {
			t.Fatalf("exit = %d stderr = %q", code, errb.String())
		}
		got := out.String()
		for _, want := range []string{
			"antigravity",
			"read_file",
			"/src/main.go",
			"ALLOW",
			"(0.2ms)",
			"/project/.env",
			"DENY",
			"[P4.secret-path]",
			"claude",
			"Bash",
			"git push origin main",
			"ASK",
			"[P2.git-push-protected]",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("compact output missing %q:\n%s", want, got)
			}
		}
	})

	t.Run("json format with plane and verdict filters", func(t *testing.T) {
		withTailContext(t, func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 120*time.Millisecond)
		})
		var out, errb strings.Builder
		code := run([]string{"tail", "--path", path, "--lines", "3", "--format", "json", "--plane", "antigravity", "--verdict", "deny"}, strings.NewReader(""), &out, &errb)
		if code != 0 {
			t.Fatalf("exit = %d stderr = %q", code, errb.String())
		}
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		if len(lines) != 1 {
			t.Fatalf("got %d JSON lines, want 1:\n%s", len(lines), out.String())
		}
		var rec audit.Record
		if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
			t.Fatalf("invalid JSON %q: %v", lines[0], err)
		}
		if rec.Plane != "antigravity" || rec.Decision != "deny" || rec.RuleID != "P4.secret-path" {
			t.Errorf("decoded = %+v, want antigravity deny P4.secret-path", rec)
		}
	})
}

func TestAuditFollowDelegatesToTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := audit.Write(audit.Record{
		TS:         "2026-11-21T19:42:05.482Z",
		Plane:      "antigravity",
		NativeTool: "read_file",
		Paths:      []string{"/project/.env"},
		Decision:   "deny",
		RuleID:     "P4.secret-path",
	}, path); err != nil {
		t.Fatal(err)
	}

	withTailContext(t, func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 120*time.Millisecond)
	})
	var out, errb strings.Builder
	code := run([]string{"audit", "--follow", "--path", path, "--lines", "1", "--plane", "antigravity"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d stderr = %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "P4.secret-path") {
		t.Errorf("audit --follow output missing P4.secret-path:\n%s", out.String())
	}
}

func TestTailRejectsInvalidFlagsAndShowsHelp(t *testing.T) {
	for _, args := range [][]string{
		{"tail", "--format", "xml"},
		{"tail", "--verdict", "maybe"},
		{"tail", "--plane", "unknown"},
		{"tail", "--lines", "-1"},
		{"tail", "--bogus"},
		{"tail", "extra-positional"},
		{"audit", "--follow", "--verdicts"},
	} {
		var out, errb strings.Builder
		if code := run(args, strings.NewReader(""), &out, &errb); code != 2 {
			t.Errorf("%v: exit = %d, want 2 (stderr=%q)", args, code, errb.String())
		}
	}

	var out, errb strings.Builder
	if code := run([]string{"tail", "--help"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("tail --help exit = %d, stderr = %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "--format") || !strings.Contains(out.String(), "--verdict") {
		t.Errorf("tail --help missing flag docs:\n%s", out.String())
	}
}
