package adapter

import (
	"strings"
	"testing"
)

// TestWindowsDegradedAllowReportsSanitized pins the parse-side defense: only
// contract-eligible, well-formed, bounded reports survive into the ToolCall.
// A report for a non-eligible tool (bash) or with a malformed timestamp is
// dropped, not passed through.
func TestWindowsDegradedAllowReportsSanitized(t *testing.T) {
	payload := `{"event":"pre","tool":"bash","cwd":"/repo","degraded_allows":[` +
		`{"tool":"question","call_id":"c1","ts":"2026-09-20T05:00:00Z"},` +
		`{"tool":"read","call_id":"c2","ts":"2026-09-20T05:00:01Z"},` +
		`{"tool":"bash","ts":"2026-09-20T05:00:02Z"},` +
		`{"tool":"todowrite","ts":"not-a-time"},` +
		`{"tool":"todowrite","ts":"2026-09-20T05:00:03Z"}]}`
	tc, err := ParseOpencode(strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(tc.DegradedAllows) != 3 {
		t.Fatalf("kept %d reports, want 3: %+v", len(tc.DegradedAllows), tc.DegradedAllows)
	}
	if tc.DegradedAllows[0].Tool != "question" || tc.DegradedAllows[0].CallID != "c1" {
		t.Fatalf("first report = %+v, want question/c1", tc.DegradedAllows[0])
	}
	if tc.DegradedAllows[1].Tool != "read" || tc.DegradedAllows[1].CallID != "c2" {
		t.Fatalf("second report = %+v, want read/c2 (floor fallback)", tc.DegradedAllows[1])
	}
	if tc.DegradedAllows[2].Tool != "todowrite" || tc.DegradedAllows[2].TS != "2026-09-20T05:00:03Z" {
		t.Fatalf("third report = %+v, want todowrite with valid ts", tc.DegradedAllows[2])
	}
}
