package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

// selftestMarkerPath is the one-line record of the guardrail release that
// last passed selftest on this machine: $XDG_STATE_HOME/guardrail/selftest-passed.
func selftestMarkerPath() (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
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

// recordSelftestPass writes the marker for a passing run; it is only ever
// called after every probe passed. A failed write leaves the marker as it
// was, and the next session keeps asking for a selftest.
func recordSelftestPass(release string) error {
	path, err := selftestMarkerPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".selftest-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := errors.Join(tmp.Chmod(0o600), writeLine(tmp, release), tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func writeLine(f *os.File, line string) error {
	_, err := f.WriteString(line + "\n")
	return err
}

// selftestPosture is the advisory line asking for a selftest on the first
// session after a guardrail bump — and every session until one passes on
// the installed release. Empty once it has.
func selftestPosture(release string) string {
	last := selftestPassedVersion()
	switch {
	case last == release:
		return ""
	case last == "":
		return "guardrail " + release + " has not passed selftest on this machine; run guardrail selftest"
	default:
		return "guardrail " + release + " is new here (selftest last passed on " + last + "); run guardrail selftest"
	}
}
