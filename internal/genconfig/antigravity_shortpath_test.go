package genconfig

import "testing"

// antigravityPreCommand is the PreToolUse command string written into hooks.json.
func antigravityPreCommand(t *testing.T, binary string) string {
	t.Helper()
	pre := AntigravityConfig(binary)["guardrail"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	return pre["hooks"].([]any)[0].(map[string]any)["command"].(string)
}

func withShortPathResolver(t *testing.T, fn func(string) (string, bool)) {
	t.Helper()
	old := shortPathResolver
	shortPathResolver = fn
	t.Cleanup(func() { shortPathResolver = old })
}

// A binary path with a space needs quotes, and agy's `cmd /C` spawn turns a
// quote into \" that cmd.exe cannot read (#353, #358). Its 8.3 short name is
// quote-free, so it is the spelling to write when the volume has one.
func TestWindowsAntigravityHookCommandUsesTheShortNameForASpacedPath(t *testing.T) {
	withShortPathResolver(t, func(p string) (string, bool) {
		if p != `C:\Program Files\guardrail\guardrail.exe` {
			t.Errorf("resolver asked about %q", p)
		}
		return `C:\PROGRA~1\guardrail\guardrail.exe`, true
	})
	got := antigravityPreCommand(t, `C:\Program Files\guardrail\guardrail.exe`)
	want := `C:/PROGRA~1/guardrail/guardrail.exe hook antigravity pre`
	if got != want {
		t.Fatalf("antigravity pre command = %q, want %q", got, want)
	}
}

// With 8.3 creation off, GetShortPathName hands back the long name unchanged,
// and with no file to inspect it fails. Neither is a spelling agy can spawn, so
// the quoted form stays and doctor names the problem.
func TestWindowsAntigravityHookCommandKeepsQuotesWhenNoUsableShortNameExists(t *testing.T) {
	const want = `"C:/Program Files/guardrail/guardrail.exe" hook antigravity pre`
	for name, resolve := range map[string]func(string) (string, bool){
		"long name returned unchanged": func(p string) (string, bool) { return p, true },
		"resolution failed":            func(string) (string, bool) { return "", false },
		"short name still has a space": func(string) (string, bool) { return `C:\Some Dir\g.exe`, true },
	} {
		t.Run(name, func(t *testing.T) {
			withShortPathResolver(t, resolve)
			if got := antigravityPreCommand(t, `C:\Program Files\guardrail\guardrail.exe`); got != want {
				t.Fatalf("antigravity pre command = %q, want %q", got, want)
			}
		})
	}
}

// A path that already needs no quotes is never sent to the resolver: it would
// only risk rewriting a spelling that works.
func TestWindowsAntigravityHookCommandDoesNotResolveAPathThatIsAlreadyBare(t *testing.T) {
	withShortPathResolver(t, func(p string) (string, bool) {
		t.Errorf("resolver called for %q", p)
		return "", false
	})
	got := antigravityPreCommand(t, `C:\Users\carlitos\.local\bin\guardrail.exe`)
	if want := `C:/Users/carlitos/.local/bin/guardrail.exe hook antigravity pre`; got != want {
		t.Fatalf("antigravity pre command = %q, want %q", got, want)
	}
}

func TestWindowsAntigravityHookSpawnableReportsWhetherAgyCanReachTheBinary(t *testing.T) {
	withShortPathResolver(t, func(string) (string, bool) { return "", false })
	for _, tt := range []struct {
		binary string
		want   bool
	}{
		{`C:\Users\carlitos\.local\bin\guardrail.exe`, true},
		{`C:\Program Files\guardrail\guardrail.exe`, false},
		{`/usr/local/bin/guardrail`, true},
		{`/home/first last/bin/guardrail`, true}, // POSIX: agy's cmd spawn does not apply
		{`guardrail`, true},
	} {
		if got := AntigravityHookSpawnable(tt.binary); got != tt.want {
			t.Errorf("AntigravityHookSpawnable(%q) = %v, want %v", tt.binary, got, tt.want)
		}
	}
	withShortPathResolver(t, func(string) (string, bool) { return `C:\PROGRA~1\guardrail\guardrail.exe`, true })
	if !AntigravityHookSpawnable(`C:\Program Files\guardrail\guardrail.exe`) {
		t.Error("a spaced path with a usable short name must be spawnable")
	}
}
