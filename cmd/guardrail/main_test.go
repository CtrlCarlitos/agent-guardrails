package main

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	configHome, err := os.MkdirTemp("", "guardrail-command-tests-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.Setenv("XDG_CONFIG_HOME", configHome); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.Setenv("APPDATA", configHome); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(configHome)
	os.Exit(code)
}
