package testenv

import (
	"os"
	"testing"
)

func TestSandboxSynchronizesPortableAndWindowsRoots(t *testing.T) {
	roots := Sandbox(t)

	for name, want := range map[string]string{
		"HOME":            roots.Home,
		"USERPROFILE":     roots.Home,
		"XDG_CONFIG_HOME": roots.Config,
		"APPDATA":         roots.Config,
		"XDG_STATE_HOME":  roots.State,
		"LOCALAPPDATA":    roots.State,
	} {
		if got := os.Getenv(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestSettersKeepEquivalentRootsTogether(t *testing.T) {
	SetHome(t, "home")
	SetConfig(t, "config")
	SetState(t, "state")

	for name, want := range map[string]string{
		"HOME":            "home",
		"USERPROFILE":     "home",
		"XDG_CONFIG_HOME": "config",
		"APPDATA":         "config",
		"XDG_STATE_HOME":  "state",
		"LOCALAPPDATA":    "state",
	} {
		if got := os.Getenv(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}
