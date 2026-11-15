package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
	"github.com/gofrs/flock"
)

func TestTimingStorageBoundedAndNonblocking(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	t.Setenv("GUARDRAIL_TIMING", "1")
	for i := 0; i < 205; i++ {
		if err := WriteTiming(TimingSample{Host: "opencode", Kind: "hook", CallID: fmt.Sprintf("c-%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(TimingPath())
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) != 200 {
		t.Fatalf("got %d records", len(lines))
	}
	var first, last TimingSample
	if err := json.Unmarshal(lines[0], &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[len(lines)-1], &last); err != nil {
		t.Fatal(err)
	}
	if first.CallID != "c-5" || last.CallID != "c-204" {
		t.Fatalf("window %s..%s", first.CallID, last.CallID)
	}
	lock := flock.New(TimingPath() + ".lock")
	if err := lock.Lock(); err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	defer lock.Unlock()
	if err := WriteTiming(TimingSample{CallID: "contended"}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(TimingPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, after) {
		t.Fatal("contended diagnostic must drop, never wait")
	}
}

func TestTimingRejectsSymlinkAndOversizedRecord(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	t.Setenv("GUARDRAIL_TIMING", "1")
	if err := WriteTiming(TimingSample{CallID: string(bytes.Repeat([]byte("x"), 5000))}); err == nil {
		t.Fatal("oversized record accepted")
	}
	target := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(TimingPath()), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, TimingPath()); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := WriteTiming(TimingSample{}); err == nil {
		t.Fatal("symlink accepted")
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != "keep" {
		t.Fatalf("target changed: %q %v", raw, err)
	}
}

func TestTimingDiscardsMalformedAndOversizedHistory(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	t.Setenv("GUARDRAIL_TIMING", "1")
	if err := os.MkdirAll(filepath.Dir(TimingPath()), 0700); err != nil {
		t.Fatal(err)
	}
	bad := append(bytes.Repeat([]byte("x"), 5000), '\n')
	bad = append(bad, []byte("not-json\n")...)
	if err := os.WriteFile(TimingPath(), bad, 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteTiming(TimingSample{CallID: "new"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(TimingPath())
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes.Split(bytes.TrimSpace(raw), []byte("\n"))) != 1 {
		t.Fatalf("retained invalid history: %d bytes", len(raw))
	}
	var sample TimingSample
	if err := json.Unmarshal(bytes.TrimSpace(raw), &sample); err != nil || sample.CallID != "new" {
		t.Fatalf("invalid history: %v %+v", err, sample)
	}
}
