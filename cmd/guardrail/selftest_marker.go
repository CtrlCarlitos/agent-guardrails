package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

// selftestMarkerPath is the legacy one-line record of the guardrail release
// that last passed selftest on this machine. Kept alongside proof.json (#110)
// for migration compatibility.
func selftestMarkerPath() (string, error) {
	base, err := stateBaseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "guardrail", "selftest-passed"), nil
}

// selftestPassedVersion reports the release recorded by the last passing
// selftest, or "" when none is recorded or the marker is unreadable — the
// posture treats both as "not passed", never as an error.
func selftestPassedVersion() string {
	path, err := selftestMarkerPath()
	if err != nil {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return safetext.SingleLine(strings.TrimSpace(string(raw)))
}

// recordSelftestPass writes the unified proof.json (#110) and legacy marker
// for a passing run; it is only ever called after every probe passed. A failed
// write leaves the state as it was, and the next session keeps asking.
func recordSelftestPass(release string) error {
	now := time.Now().UTC()
	proofErr := saveProofRecord(computeProof(release, &now))

	path, err := selftestMarkerPath()
	if err != nil {
		return errors.Join(proofErr, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return errors.Join(proofErr, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".selftest-*")
	if err != nil {
		return errors.Join(proofErr, err)
	}
	defer os.Remove(tmp.Name())
	if err := errors.Join(tmp.Chmod(0o600), writeLine(tmp, release), tmp.Close()); err != nil {
		return errors.Join(proofErr, err)
	}
	return errors.Join(proofErr, os.Rename(tmp.Name(), path))
}

func writeLine(f *os.File, line string) error {
	_, err := f.WriteString(line + "\n")
	return err
}
