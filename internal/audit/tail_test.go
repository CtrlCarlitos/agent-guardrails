package audit

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestTailStreamsAppendedRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := Write(Record{Plane: "claude", Tool: "Read", Decision: "allow"}, path); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu   sync.Mutex
		got  []Record
		done = make(chan error, 1)
	)
	ready := make(chan struct{})
	go func() {
		done <- Tail(ctx, TailOptions{
			Path:         path,
			PollInterval: 10 * time.Millisecond,
			OnReady:      func() { close(ready) },
			Emit: func(rec Record) error {
				mu.Lock()
				got = append(got, rec)
				n := len(got)
				mu.Unlock()
				if n >= 2 {
					cancel()
				}
				return nil
			},
		})
	}()
	<-ready

	if err := Write(Record{Plane: "antigravity", NativeTool: "read_file", Decision: "deny", RuleID: "P4.secret-path", Paths: []string{"/repo/.env"}, HookMS: 0.2}, path); err != nil {
		t.Fatal(err)
	}
	if err := Write(Record{Plane: "claude", Tool: "Bash", Command: "git push origin main", Decision: "ask", RuleID: "P2.git-push-protected", HookMS: 0.4}, path); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Tail returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("timed out waiting for appended records")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(got), got)
	}
	if got[0].Plane != "antigravity" || got[0].RuleID != "P4.secret-path" {
		t.Errorf("first record = %+v, want antigravity P4.secret-path", got[0])
	}
	if got[1].Plane != "claude" || got[1].Decision != "ask" {
		t.Errorf("second record = %+v, want claude ask", got[1])
	}
}

func TestTailWaitsForMissingFileToAppear(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu   sync.Mutex
		got  []Record
		done = make(chan error, 1)
	)
	ready := make(chan struct{})
	go func() {
		done <- Tail(ctx, TailOptions{
			Path:         path,
			PollInterval: 10 * time.Millisecond,
			OnReady:      func() { close(ready) },
			Emit: func(rec Record) error {
				mu.Lock()
				got = append(got, rec)
				mu.Unlock()
				cancel()
				return nil
			},
		})
	}()
	<-ready

	if err := Write(Record{Plane: "antigravity", NativeTool: "read_file", Decision: "allow", Paths: []string{"/repo/a.go"}}, path); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Tail returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("timed out waiting for newly created audit file")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].NativeTool != "read_file" {
		t.Fatalf("got = %+v, want 1 read_file record", got)
	}
}

func TestTailFollowsAcrossSegmentRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := Write(Record{Plane: "claude", Tool: "Read", Decision: "allow", Paths: []string{"/repo/init.go"}}, path); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu   sync.Mutex
		got  []Record
		done = make(chan error, 1)
	)
	ready := make(chan struct{})
	go func() {
		done <- Tail(ctx, TailOptions{
			Path:         path,
			PollInterval: 10 * time.Millisecond,
			OnReady:      func() { close(ready) },
			Emit: func(rec Record) error {
				mu.Lock()
				got = append(got, rec)
				n := len(got)
				mu.Unlock()
				if n >= 2 {
					cancel()
				}
				return nil
			},
		})
	}()
	<-ready

	// Write a record, then immediately rotate the segment like rotateIfOverLimit,
	// and write another record to the new active segment.
	if err := Write(Record{Plane: "antigravity", NativeTool: "read_file", Decision: "deny", RuleID: "P4.secret-path", Paths: []string{"/repo/.env"}}, path); err != nil {
		t.Fatal(err)
	}
	rotated := filepath.Join(dir, "audit-20261121-000000.000000001.jsonl")
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := Write(Record{Plane: "opencode", NativeTool: "bash", Command: "git status", Decision: "allow"}, path); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Tail returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("timed out waiting for records across segment rotation")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("got %d records across rotation, want 2: %+v", len(got), got)
	}
	if got[0].RuleID != "P4.secret-path" || got[1].Plane != "opencode" {
		t.Errorf("got = %+v, want P4.secret-path then opencode", got)
	}
}

func TestTailFiltersAndInitialLinesAcrossSegments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	rotated := filepath.Join(dir, "audit-20261121-000000.000000001.jsonl")

	// Seed rotated segment + active segment.
	for _, rec := range []Record{
		{Plane: "antigravity", NativeTool: "read_file", Decision: "deny", RuleID: "P4.old-1"},
		{Plane: "claude", Tool: "Bash", Decision: "deny", RuleID: "P1.other"},
		{Plane: "antigravity", NativeTool: "write_file", Decision: "deny", RuleID: "P4.old-2"},
	} {
		if err := Write(rec, rotated); err != nil {
			t.Fatal(err)
		}
	}
	for _, rec := range []Record{
		{Plane: "antigravity", NativeTool: "read_file", Decision: "allow"},
		{Plane: "antigravity", NativeTool: "edit_file", Decision: "deny", RuleID: "P4.active-3"},
	} {
		if err := Write(rec, path); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu   sync.Mutex
		got  []Record
		done = make(chan error, 1)
	)
	go func() {
		done <- Tail(ctx, TailOptions{
			Path:         path,
			PollInterval: 10 * time.Millisecond,
			InitialLines: 2,
			Filter:       TailFilter{Plane: "antigravity", Verdict: "deny"},
			Emit: func(rec Record) error {
				mu.Lock()
				got = append(got, rec)
				n := len(got)
				mu.Unlock()
				if n >= 2 {
					cancel()
				}
				return nil
			},
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Tail returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("timed out waiting for initial filtered records")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(got), got)
	}
	if got[0].RuleID != "P4.old-2" || got[1].RuleID != "P4.active-3" {
		t.Errorf("got rules = [%s, %s], want [P4.old-2, P4.active-3]", got[0].RuleID, got[1].RuleID)
	}
}

func TestTailBuffersPartialLineUntilNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu   sync.Mutex
		got  []Record
		done = make(chan error, 1)
	)
	ready := make(chan struct{})
	go func() {
		done <- Tail(ctx, TailOptions{
			Path:         path,
			PollInterval: 10 * time.Millisecond,
			OnReady:      func() { close(ready) },
			Emit: func(rec Record) error {
				mu.Lock()
				got = append(got, rec)
				mu.Unlock()
				cancel()
				return nil
			},
		})
	}()
	<-ready

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"ts":"2026-11-21T01:02:03Z","plane":"antigravity",`); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	time.Sleep(35 * time.Millisecond)

	f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\"native_tool\":\"read_file\",\"decision\":\"allow\"}\n"); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Tail returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("timed out waiting for completed line")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].NativeTool != "read_file" {
		t.Fatalf("got = %+v, want 1 read_file record", got)
	}
}
