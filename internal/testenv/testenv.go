// Package testenv keeps test-owned home, config, and state roots consistent
// across the Unix XDG and Windows environment conventions.
package testenv

// TB is the part of testing.TB needed by the environment helpers.
type TB interface {
	Helper()
	Setenv(string, string)
	TempDir() string
}

// Roots contains the three independent filesystem roots used by Sandbox.
type Roots struct {
	Home   string
	Config string
	State  string
}

// Sandbox points every supported home, config, and state variable at fresh
// test-owned directories. Tests that need a specific root can use the setters.
func Sandbox(t TB) Roots {
	t.Helper()
	roots := Roots{Home: t.TempDir(), Config: t.TempDir(), State: t.TempDir()}
	SetHome(t, roots.Home)
	SetConfig(t, roots.Config)
	SetState(t, roots.State)
	return roots
}

// SetHome synchronizes the Unix and Windows home variables.
func SetHome(t TB, root string) {
	t.Helper()
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
}

// SetConfig synchronizes the XDG and Windows roaming-config roots.
func SetConfig(t TB, root string) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", root)
	t.Setenv("APPDATA", root)
}

// SetState synchronizes the XDG and Windows local-state roots.
func SetState(t TB, root string) {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", root)
	t.Setenv("LOCALAPPDATA", root)
}
