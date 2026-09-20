package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// claudeEvidenceEnv points HOME and the audit log at temp dirs and registers a
// spawnable claude hook, so only the audit contents vary between cases.
func claudeEvidenceEnv(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	state := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", state)
	t.Setenv("APPDATA", t.TempDir())
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	settings := `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"*","hooks":[` +
		`{"type":"command","command":"guardrail hook claude"}]}]}}`
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}
	return state
}

func writeAuditRecords(t *testing.T, state string, records ...string) {
	t.Helper()
	path := filepath.Join(state, "guardrail", "audit.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(records, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func preRecord(session, tool string) string {
	return `{"ts":"` + time.Now().UTC().Format(time.RFC3339Nano) +
		`","plane":"claude","session_id":"` + session +
		`","event":"pre","tool":"` + tool + `","decision":"allow"}`
}

// doctor's claude line read "guardrail hook registered" for four days while an
// unspawnable command enforced nothing (#149, fail-open class #151).
// Registration is a claim; the audit log is the evidence. A registered hook
// that has never produced a record from a real session must say so.
func TestWindowsDoctorSaysRegisteredButNeverObservedFiring(t *testing.T) {
	const realSession = "78f4afb7-748f-4af6-b026-51882e1865f3"
	for _, tt := range []struct {
		name    string
		records []string
		caveat  bool
	}{
		{"no audit log at all", nil, true},
		{"only fixture sessions", []string{preRecord("night-claude", "Bash"), preRecord("trifecta-sess-1", "Read")}, true},
		{"one real record", []string{preRecord(realSession, "Bash")}, true},
		{"another plane is mediated", []string{
			strings.Replace(preRecord(realSession, "Bash"), `"claude"`, `"opencode"`, 1),
			strings.Replace(preRecord(realSession, "Read"), `"claude"`, `"opencode"`, 1),
		}, true},
		{"two records from a real session", []string{preRecord(realSession, "Bash"), preRecord(realSession, "Read")}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := claudeEvidenceEnv(t)
			if tt.records != nil {
				writeAuditRecords(t, state, tt.records...)
			}
			var out, errb strings.Builder
			run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
			line := claudeLine(t, out.String())
			saidNever := strings.Contains(strings.ToLower(line), "never observed firing")
			if saidNever != tt.caveat {
				t.Fatalf("claude line = %q; caveat present = %v, want %v", line, saidNever, tt.caveat)
			}
			if !strings.Contains(line, "registered") {
				t.Fatalf("claude line = %q, want it to still report registration", line)
			}
		})
	}
}

// The caveat is operator-facing only. claudeSettingsState is the lifecycle's
// ownership test — planeIntegrationRegistered compares it for exact equality —
// and it reaches the model through the SessionStart line, which falls silent in
// steady state. A plane with no records yet is newly enrolled, not drifted.
func TestWindowsClaudeEvidenceCaveatStaysOutOfTheLifecycleString(t *testing.T) {
	claudeEvidenceEnv(t) // registered, and no audit records at all
	if got := claudeSettingsState(); got != "guardrail hook registered" {
		t.Fatalf("claudeSettingsState() = %q, want the bare lifecycle string", got)
	}
	if !planeIntegrationRegistered("claude") {
		t.Fatal("planeIntegrationRegistered(claude) = false with no audit records; a fresh enrolment is not drift")
	}
}

func claudeLine(t *testing.T, output string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "claude settings:") {
			return line
		}
	}
	t.Fatalf("doctor printed no claude settings line:\n%s", output)
	return ""
}

// The two checks compose. A command that cannot spawn has necessarily never
// fired, so doctor names the cause — the unspawnable command — and not also
// its consequence. Stacking #149's fix and this gate is what makes the pair
// meet: the spawn fault is a hard one the lifecycle acts on, the missing
// record is a soft caveat a fresh enrolment trips.
func TestWindowsDoctorNamesTheSpawnFaultRatherThanItsConsequence(t *testing.T) {
	home := t.TempDir()
	state := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", state)
	t.Setenv("APPDATA", t.TempDir())
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The exact pre-#149 string, JSON-escaped: registered, and unspawnable in a
	// POSIX shell because every backslash is an escape character there.
	settings := `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"*","hooks":[` +
		`{"type":"command","command":"C:\\Users\\u\\.local\\bin\\guardrail.exe hook claude"}]}]}}`
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb strings.Builder
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	line := claudeLine(t, out.String())
	if !strings.Contains(line, claudeCannotSpawnMarker) {
		t.Fatalf("claude line = %q, want it to name the spawn fault", line)
	}
	if strings.Contains(strings.ToLower(line), "never observed firing") {
		t.Fatalf("claude line = %q; it names the cause and then its consequence — one is enough", line)
	}
}
