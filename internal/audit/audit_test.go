package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteAppendsJSONL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d", "audit.jsonl")
	for i := 0; i < 2; i++ {
		if err := Write(Record{Plane: "claude", Tool: "Bash", Decision: "deny", RuleID: "P1.rm-rf"}, p); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d", len(lines))
	}
	var rec Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.TS == "" || rec.Decision != "deny" {
		t.Fatalf("bad record: %+v", rec)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(p)
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
		}
	}
}

func TestRedact(t *testing.T) {
	in := `curl -H "Authorization: Bearer sk-abcdef123456" https://x --data AWS_SECRET=AKIAIOSFODNN7EXAMPLE`
	out := redact(in)
	if strings.Contains(out, "sk-abcdef123456") || strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("secrets leaked: %s", out)
	}
}

func TestDefaultPath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Setenv("XDG_STATE_HOME", "/xdg")
		if got := DefaultPath(""); got != "/xdg/guardrail/audit.jsonl" {
			t.Fatalf("got %q", got)
		}
	}
	if got := DefaultPath("/explicit/x.jsonl"); got != "/explicit/x.jsonl" {
		t.Fatalf("override ignored: %q", got)
	}
}
