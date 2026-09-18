package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain sandboxes the whole package: XDG config/state and HOME point
// into fresh temp directories unless a test overrides them with t.Setenv,
// so no test can ever mutate the operator's real settings through
// lifecycle, recover, or approval paths (the guardrail.test-pollution
// lesson).
func TestMain(m *testing.M) {
	configHome, err := os.MkdirTemp("", "guardrail-command-tests-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for name, value := range map[string]string{
		"XDG_CONFIG_HOME": configHome,
		"APPDATA":         configHome,
	} {
		if err := os.Setenv(name, value); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if home := os.Getenv("HOME"); home != "" && !strings.HasPrefix(filepath.Clean(home), filepath.Clean(os.TempDir())+string(filepath.Separator)) {
		sandbox, err := os.MkdirTemp("", "guardrail-cmd-test-home-*")
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot sandbox HOME:", err)
			os.Exit(1)
		}
		_ = os.Setenv("HOME", sandbox)
		_ = os.Setenv("XDG_STATE_HOME", filepath.Join(sandbox, ".local", "state"))
	}
	code := m.Run()
	_ = os.RemoveAll(configHome)
	os.Exit(code)
}
