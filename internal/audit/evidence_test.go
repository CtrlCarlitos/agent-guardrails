package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCodexEvidenceGate(t *testing.T) {
	cutoff := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	now := cutoff.Add(time.Hour)
	first := Record{TS: cutoff.Add(time.Second).Format(time.RFC3339), Plane: "codex", SessionID: "live-session", Event: "pre", Tool: "Bash", Command: "pwd", Decision: "allow"}
	second := first
	second.TS = cutoff.Add(2 * time.Second).Format(time.RFC3339)
	mutate := func(r Record, f func(*Record)) Record { f(&r); return r }
	for _, tc := range []struct {
		name                 string
		records              []Record
		want                 bool
		eligible, duplicates int
	}{
		{"empty", nil, false, 0, 0},
		{"singleton", []Record{first}, false, 1, 0},
		{"distinct timestamp", []Record{first, second}, true, 2, 0},
		{"distinct tool", []Record{first, mutate(first, func(r *Record) { r.Tool = "Read" })}, true, 2, 0},
		{"distinct decision", []Record{first, mutate(first, func(r *Record) { r.Decision = "deny" })}, true, 2, 0},
		{"command alone is not distinct", []Record{first, mutate(first, func(r *Record) { r.Command = "ls" })}, false, 1, 1},
		{"reason alone is not distinct", []Record{first, mutate(first, func(r *Record) { r.Reason = "changed" })}, false, 1, 1},
		{"equivalent timestamp spelling", []Record{first, mutate(first, func(r *Record) { r.TS = "2026-09-18T12:00:01.000+00:00" })}, false, 1, 1},
		{"duplicate copies", []Record{first, first}, false, 1, 1},
		{"separate singletons", []Record{first, mutate(second, func(r *Record) { r.SessionID = "other" })}, false, 2, 0},
		{"pre post one call", []Record{first, mutate(first, func(r *Record) { r.Event = "post" })}, false, 1, 0},
		{"mtime equality", []Record{first, mutate(second, func(r *Record) { r.TS = cutoff.Format(time.RFC3339) })}, false, 1, 0},
		{"future timestamp", []Record{first, mutate(second, func(r *Record) { r.TS = now.Add(time.Second).Format(time.RFC3339) })}, false, 1, 0},
		{"bad timestamp", []Record{first, mutate(second, func(r *Record) { r.TS = "bad" })}, false, 1, 0},
		{"missing session", []Record{mutate(first, func(r *Record) { r.SessionID = "" }), mutate(second, func(r *Record) { r.SessionID = "" })}, false, 0, 0},
		{"missing verdict", []Record{first, mutate(second, func(r *Record) { r.Decision = "" })}, false, 1, 0},
		{"other plane", []Record{mutate(first, func(r *Record) { r.Plane = "claude" }), mutate(second, func(r *Record) { r.Plane = "claude" })}, false, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			var lines strings.Builder
			for _, r := range tc.records {
				raw, _ := json.Marshal(r)
				lines.Write(raw)
				lines.WriteByte('\n')
			}
			if err := os.WriteFile(path, []byte(lines.String()), 0600); err != nil {
				t.Fatal(err)
			}
			e, err := ReadCodexEvidence([]string{path}, cutoff, now)
			if err != nil {
				t.Fatal(err)
			}
			if e.Observed() != tc.want || e.Eligible != tc.eligible || e.Duplicates != tc.duplicates {
				t.Fatalf("evidence=%+v want observed=%v eligible=%d duplicates=%d", e, tc.want, tc.eligible, tc.duplicates)
			}
		})
	}
}

func TestCodexSyntheticProvenance(t *testing.T) {
	for _, id := range []string{"selftest", "selftest-123", "codex-fixture", "codex-fixture-read", "fixture", "fixture-mcp"} {
		if !syntheticCodexSession(id) {
			t.Errorf("did not exclude %q", id)
		}
	}
	for _, id := range []string{"selftesting", "live-selftest", "codex-fixtures", "fixtures", "live"} {
		if syntheticCodexSession(id) {
			t.Errorf("overbroad exclusion for %q", id)
		}
	}
	// Keep the documented exclusion list tied to the actual contract fixtures.
	files, err := filepath.Glob("../../test/fixtures/codex/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("fixtures: %v", err)
	}
	for _, p := range files {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			SessionID string `json:"session_id"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.SessionID != "" && !syntheticCodexSession(doc.SessionID) {
			t.Errorf("unexcluded fixture ID %q in %s", doc.SessionID, p)
		}
	}
}

func TestCodexEvidenceRotationsAndDuplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	old := filepath.Join(dir, "audit-20260918-120000.jsonl")
	record := `{"ts":"2026-09-18T12:00:01Z","plane":"codex","session_id":"live","event":"pre","tool":"Bash","command":"pwd","decision":"allow"}`
	reordered := `{"decision":"allow","command":"pwd","tool":"Bash","event":"pre","session_id":"live","plane":"codex","ts":"2026-09-18T12:00:01Z"}`
	if err := os.WriteFile(old, []byte(record+"\n"+reordered+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	segments, err := Segments(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) != 1 || segments[0] != old {
		t.Fatalf("rotated-only segments=%v", segments)
	}
	cutoff, _ := time.Parse(time.RFC3339, "2026-09-18T12:00:00Z")
	e, err := ReadCodexEvidence(segments, cutoff, cutoff.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if e.Observed() || e.Eligible != 1 || e.Duplicates != 1 {
		t.Fatalf("duplicate opened gate: %+v", e)
	}
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(record, "12:00:01Z", "12:00:02Z")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	segments, err = Segments(path)
	if err != nil {
		t.Fatal(err)
	}
	e, err = ReadCodexEvidence(segments, cutoff, cutoff.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !e.Observed() || e.Eligible != 2 || e.QualifiedSessions != 1 {
		t.Fatalf("cross-segment evidence=%+v", e)
	}
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(record, "12:00:01Z", "12:00:02Z")+"\n{broken\n"), 0600); err != nil {
		t.Fatal(err)
	}
	e, err = ReadCodexEvidence(segments, cutoff, cutoff.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if e.Observed() || e.Malformed != 1 {
		t.Fatalf("malformed scan opened gate: %+v", e)
	}
	if _, err := ReadCodexEvidence([]string{dir}, cutoff, cutoff.Add(time.Hour)); err == nil {
		t.Fatal("accepted directory")
	}
}

func TestCodexEvidenceFiltersSessionAndAssertsExpectedTools(t *testing.T) {
	cutoff := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	records := []Record{
		{TS: cutoff.Add(time.Second).Format(time.RFC3339), Plane: "codex", SessionID: "older", Event: "pre", Tool: "Bash", NativeTool: "command_execution", Decision: "allow"},
		{TS: cutoff.Add(2 * time.Second).Format(time.RFC3339), Plane: "codex", SessionID: "older", Event: "pre", Tool: "Bash", NativeTool: "command_execution", Decision: "deny"},
		{TS: cutoff.Add(3 * time.Second).Format(time.RFC3339), Plane: "codex", SessionID: "newest", Event: "pre", Tool: "apply_patch", NativeTool: "apply_patch", Decision: "allow"},
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	var lines strings.Builder
	for _, record := range records {
		raw, _ := json.Marshal(record)
		lines.Write(raw)
		lines.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(lines.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence, err := ReadCodexEvidenceFiltered([]string{path}, cutoff, cutoff.Add(time.Hour), "newest", []string{"command_execution", "apply_patch"})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Observed() || evidence.Eligible != 1 || evidence.OtherSessions != 2 || strings.Join(evidence.MissingExpectedTools, ",") != "command_execution" {
		t.Fatalf("evidence = %+v", evidence)
	}
}

func TestCodexEvidenceLargeHistoricalRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	// Old audit segments can contain a single unrelated command above 8 MiB.
	// It must not stop the scan before later Codex records.
	raw, _ := json.Marshal(Record{Plane: "opencode", Command: strings.Repeat("x", 9<<20)})
	one := `{"ts":"2026-09-18T12:00:01Z","plane":"codex","session_id":"live","event":"pre","tool":"Bash","command":"pwd","decision":"allow"}`
	raw = append(raw, []byte("\n"+one+"\n"+strings.ReplaceAll(one, "12:00:01Z", "12:00:02Z")+"\n")...)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cutoff, _ := time.Parse(time.RFC3339, "2026-09-18T12:00:00Z")
	e, err := ReadCodexEvidence([]string{path}, cutoff, cutoff.Add(time.Hour))
	if err != nil || !e.Observed() || e.Records != 3 {
		t.Fatalf("evidence=%+v err=%v", e, err)
	}
}
