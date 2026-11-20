package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"time"
)

// CreationEvidence names the record that proves a session created a
// resource (ADR-0039).
type CreationEvidence struct {
	TS      string
	Command string
}

// SessionCreation scans the audit segments for the newest same-session,
// pre-tool record inside lookback whose decision allowed or asked a command
// that resource accepts. It fails closed: any read or parse trouble simply
// does not match.
func SessionCreation(path, sessionID string, now time.Time, lookback time.Duration, resource func(command string) bool) (CreationEvidence, bool) {
	if sessionID == "" || resource == nil {
		return CreationEvidence{}, false
	}
	segments, err := Segments(path)
	if err != nil {
		return CreationEvidence{}, false
	}
	var best CreationEvidence
	var bestTS time.Time
	found := false
	consider := func(rec Record) {
		if rec.SessionID == "" || rec.SessionID != sessionID || syntheticCodexSession(rec.SessionID) {
			return
		}
		if rec.Event != "pre" || (rec.Decision != "allow" && rec.Decision != "ask") {
			return
		}
		ts, err := time.Parse(time.RFC3339Nano, rec.TS)
		if err != nil || ts.After(now) || ts.Before(now.Add(-lookback)) {
			return
		}
		if !resource(rec.Command) {
			return
		}
		if !found || !ts.Before(bestTS) {
			best, bestTS, found = CreationEvidence{TS: rec.TS, Command: rec.Command}, ts, true
		}
	}
	for _, segment := range segments {
		info, err := os.Lstat(segment)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 128<<20 {
			continue
		}
		f, err := os.Open(segment)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(&io.LimitedReader{R: f, N: (128 << 20) + 1})
		scanner.Buffer(make([]byte, 64<<10), (128<<20)+1)
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			var rec Record
			if json.Unmarshal(line, &rec) != nil {
				continue
			}
			consider(rec)
		}
		f.Close()
	}
	return best, found
}
