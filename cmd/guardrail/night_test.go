package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/night"
)

func isolateNightConfig(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	if os.PathSeparator == '\\' {
		t.Setenv("APPDATA", base)
	} else {
		t.Setenv("XDG_CONFIG_HOME", base)
	}
	path, err := night.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func runNightCommand(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"night"}, args...), strings.NewReader(""), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestNightOnDefaultsToEightHours(t *testing.T) {
	path := isolateNightConfig(t)
	before := time.Now()
	code, stdout, stderr := runNightCommand(t, "on")
	after := time.Now()
	if code != 0 || stderr != "" || !strings.HasPrefix(stdout, "NIGHT MODE until ") {
		t.Fatalf("night on = code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	state, err := night.Load(path, before)
	if err != nil {
		t.Fatal(err)
	}
	if state.Until.Before(before.Add(8*time.Hour)) || state.Until.After(after.Add(8*time.Hour)) {
		t.Fatalf("until = %s, want invocation time + 8h", state.Until)
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("%s:%d", hostname, os.Getpid()); state.SetBy != want {
		t.Fatalf("set_by = %q, want %q", state.SetBy, want)
	}
}

func TestNightOnForAndUntil(t *testing.T) {
	t.Run("duration", func(t *testing.T) {
		path := isolateNightConfig(t)
		before := time.Now()
		code, _, stderr := runNightCommand(t, "on", "--for", "90m")
		state, err := night.Load(path, before)
		if code != 0 || err != nil || state.Until.Before(before.Add(90*time.Minute)) || state.Until.After(time.Now().Add(90*time.Minute)) {
			t.Fatalf("night on --for = code %d, state %+v, load error %v, stderr %q", code, state, err, stderr)
		}
	})

	t.Run("next local time", func(t *testing.T) {
		path := isolateNightConfig(t)
		now := time.Now()
		clock := now.Add(-time.Minute).Format("15:04")
		code, _, stderr := runNightCommand(t, "on", "--until", clock)
		state, err := night.Load(path, now)
		if code != 0 || err != nil {
			t.Fatalf("night on --until = code %d, load error %v, stderr %q", code, err, stderr)
		}
		localUntil := state.Until.In(time.Local)
		if localUntil.Hour() != now.Add(-time.Minute).Hour() || localUntil.Minute() != now.Add(-time.Minute).Minute() {
			t.Fatalf("until = %s, want next local %s", state.Until, clock)
		}
		if !state.Until.After(now) || state.Until.After(now.Add(24*time.Hour)) {
			t.Fatalf("until = %s, want next occurrence within 24h", state.Until)
		}
	})
}

func TestNightOnRejectsInvalidExpiryWithoutChangingMarker(t *testing.T) {
	tests := [][]string{
		{"on", "--for", "0s"},
		{"on", "--for", "nonsense"},
		{"on", "--for="},
		{"on", "--until", "25:00"},
		{"on", "--until="},
		{"on", "--for", "1h", "--until", "23:00"},
		{"on", "--for", "1h", "--for", "2h"},
		{"on", "--until", "22:00", "--until", "23:00"},
		{"on", "-for", "1h", "-for", "2h"},
		{"on", "--until", "22:00", "-until", "23:00"},
		{"on", "extra"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args[1:], "_"), func(t *testing.T) {
			path := isolateNightConfig(t)
			original := night.Marker{Until: time.Now().Add(2 * time.Hour).Round(0), SetBy: "operator:1"}
			if err := night.Write(path, original); err != nil {
				t.Fatal(err)
			}
			code, _, _ := runNightCommand(t, args...)
			state, err := night.Load(path, time.Now())
			if code != 2 || err != nil || !state.Until.Equal(original.Until) || state.SetBy != original.SetBy {
				t.Fatalf("%v = code %d, marker %+v, error %v; want unchanged", args, code, state, err)
			}
		})
	}
}

func TestNightStatusAndOffLifecycle(t *testing.T) {
	path := isolateNightConfig(t)
	if code, stdout, stderr := runNightCommand(t, "status"); code != 1 || stdout != "night mode inactive\n" || stderr != "" {
		t.Fatalf("inactive status = code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if err := night.Write(path, night.Marker{Until: time.Now().Add(time.Hour), SetBy: "operator:1"}); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := runNightCommand(t, "status"); code != 0 || !strings.HasPrefix(stdout, "NIGHT MODE until ") || stderr != "" {
		t.Fatalf("active status = code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if code, stdout, stderr := runNightCommand(t, "off"); code != 0 || stdout != "night mode off\n" || stderr != "" {
		t.Fatalf("night off = code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if code, _, stderr := runNightCommand(t, "off"); code != 0 || stderr != "" {
		t.Fatalf("second night off = code %d, stderr %q", code, stderr)
	}
}

func TestNightStatusRejectsMalformedMarker(t *testing.T) {
	path := isolateNightConfig(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("until = ["), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runNightCommand(t, "status")
	if code != 2 || stdout != "" || !strings.Contains(stderr, "parsing night marker") {
		t.Fatalf("malformed status = code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}
