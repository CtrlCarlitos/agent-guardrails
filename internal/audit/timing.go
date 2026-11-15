package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

// TimingSample contains measurements only, never commands or arguments. Nil
// phases explicitly mean unmeasured; zero is a measured zero-duration span.
type TimingSample struct {
	TS          string              `json:"ts"`
	Kind        string              `json:"kind"`
	Host        string              `json:"host"`
	Version     string              `json:"version"`
	HostVersion *string             `json:"host_version"`
	Runtime     string              `json:"runtime"`
	Transport   string              `json:"transport"`
	SessionID   string              `json:"session_id"`
	CallID      string              `json:"call_id"`
	Phases      map[string]*float64 `json:"phases"`
}

const TimingKeep = 200
const timingLineLimit = 4096

func TimingEnabled() bool { return os.Getenv("GUARDRAIL_TIMING") == "1" }
func TimingPath() string  { return filepath.Join(filepath.Dir(DefaultPath("")), "hook-timing.jsonl") }

// WriteTiming is best-effort sampling. It never waits for a contended lock.
// Reuse audit's regular-file checks and cap both record size and record count.
func WriteTiming(rec TimingSample) error {
	if !TimingEnabled() {
		return nil
	}
	if rec.TS == "" {
		rec.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if len(line) > timingLineLimit {
		return errors.New("timing record exceeds 4 KiB")
	}
	path := TimingPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	lockPath := path + ".lock"
	if info, err := os.Lstat(lockPath); err == nil && !info.Mode().IsRegular() {
		return errors.New("timing lock is not a regular file")
	}
	lock := flock.New(lockPath)
	defer lock.Close()
	ok, err := lock.TryLock()
	if err != nil || !ok {
		return err
	}
	defer lock.Unlock()
	// Windows O_APPEND grants append-only access and cannot truncate. This
	// bounded snapshot needs a read/write handle; retain audit's identity and
	// regular-file validation before and after opening it.
	before, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && !before.Mode().IsRegular() {
		return errors.New("timing destination is not a regular file")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := validateRegularDestination(path, f, before); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	var raw []byte
	if info.Size() <= TimingKeep*(timingLineLimit+1) {
		raw, err = os.ReadFile(path)
		if err != nil {
			return err
		}
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(raw) == 0 {
		lines = nil
	}
	kept := lines[:0]
	for _, old := range lines {
		if len(old) <= timingLineLimit && json.Valid(old) {
			kept = append(kept, old)
		}
	}
	lines = kept
	if len(lines) >= TimingKeep {
		lines = lines[len(lines)-(TimingKeep-1):]
	}
	lines = append(lines, line)
	data := append(bytes.Join(lines, []byte("\n")), '\n')
	if err := validateRegularDestination(path, f, nil); err != nil {
		return err
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	return validateRegularDestination(path, f, nil)
}
