package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func TestSetupRequiresInteractiveTerminal(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())

	var out, errb strings.Builder
	// run() derives terminal from *os.File stdin; a strings.Reader is not one.
	code := run([]string{"setup"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	const want = "guardrail: setup requires an interactive local terminal (run it from your shell, not from an agent or CI)"
	if !strings.Contains(errb.String(), want) {
		t.Fatalf("stderr = %q, want to contain %q", errb.String(), want)
	}

	var found []string
	if err := filepath.Walk(home, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path != home && !info.IsDir() {
			found = append(found, path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("setup touched the sandboxed home before the terminal check: %v", found)
	}
}

func TestSetupRejectsBadState(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	guardTestHome(t)

	var out, errb strings.Builder
	code := cmdSetup([]string{"--state", "maybe"}, true, &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	const want = `guardrail: setup --state must be enabled or disabled`
	if !strings.Contains(errb.String(), want) {
		t.Fatalf("stderr = %q, want to contain %q", errb.String(), want)
	}
}

func TestSetupRejectsUnsupportedPlane(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	guardTestHome(t)

	var out, errb strings.Builder
	code := cmdSetup([]string{"--planes", "claude,gemini"}, true, &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	const want = `unsupported plane "gemini"`
	if !strings.Contains(errb.String(), want) {
		t.Fatalf("stderr = %q, want to contain %q", errb.String(), want)
	}
}

func TestSetupRejectsUnknownFlag(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	guardTestHome(t)

	var out, errb strings.Builder
	code := cmdSetup([]string{"--verbose"}, true, &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	const want = `unknown flag "--verbose"`
	if !strings.Contains(errb.String(), want) {
		t.Fatalf("stderr = %q, want to contain %q", errb.String(), want)
	}
}

func TestSetupRefusesStagingPath(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	guardTestHome(t)

	tmp := t.TempDir()
	origInstalled := installedExecutable
	defer func() { installedExecutable = origInstalled }()

	installedExecutable = func() (string, error) { return filepath.Join(tmp, ".guardrail-update"), nil }
	var out, errb strings.Builder
	if code := cmdSetup(nil, true, &out, &errb); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	} else if !strings.Contains(errb.String(), "refuses to register a staging or superseded binary path") {
		t.Fatalf("stderr = %q, want staging refusal", errb.String())
	}

	oldName := testenv.ExecutableName("guardrail") + ".old"
	installedExecutable = func() (string, error) { return filepath.Join(tmp, oldName), nil }
	out.Reset()
	errb.Reset()
	if code := cmdSetup(nil, true, &out, &errb); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	} else if !strings.Contains(errb.String(), "refuses to register a staging or superseded binary path") {
		t.Fatalf("stderr = %q, want staging refusal", errb.String())
	}
}

func TestSetupPrintsRegisteredPathFirst(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	guardTestHome(t)

	tmp := t.TempDir()
	path := filepath.Join(tmp, "bin", "guardrail")

	origInstalled := installedExecutable
	origPlaneInstalled := planeInstalled
	defer func() {
		installedExecutable = origInstalled
		planeInstalled = origPlaneInstalled
	}()
	installedExecutable = func() (string, error) { return path, nil }
	planeInstalled = func(string) bool { return false }

	var out, errb strings.Builder
	code := cmdSetup(nil, true, &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", code, errb.String())
	}
	lines := strings.SplitN(out.String(), "\n", 2)
	want := "setup: registering " + path
	if lines[0] != want {
		t.Fatalf("first stdout line = %q, want %q", lines[0], want)
	}
}

func TestUsageMentionsSetup(t *testing.T) {
	var out, errb strings.Builder
	if code := run([]string{"help"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "setup [flags]") {
		t.Fatalf("usage does not mention setup [flags]:\n%s", out.String())
	}
}
