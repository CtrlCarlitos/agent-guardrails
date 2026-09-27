package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadRecordsKeepsSegmentOrderAndCountsMalformedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	rotated := filepath.Join(dir, "audit-20260101-000000.000000000.jsonl")
	if err := os.WriteFile(rotated, []byte(`{"ts":"1","decision":"deny","repo_root":"/r"}`+"\nnot json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(Record{TS: "2", Decision: "ask"}, path); err != nil {
		t.Fatal(err)
	}
	segments, err := Segments(path)
	if err != nil {
		t.Fatal(err)
	}
	records, malformed, err := ReadRecords(segments)
	if err != nil {
		t.Fatal(err)
	}
	if malformed != 1 || len(records) != 2 || records[0].TS != "1" || records[1].TS != "2" || records[0].RepoRoot != "/r" {
		t.Fatalf("records = %+v malformed = %d", records, malformed)
	}
	if _, _, err := ReadRecords([]string{filepath.Join(dir, "missing.jsonl")}); err == nil {
		t.Fatal("an unreadable segment must be an error, not a shorter history")
	}
}
