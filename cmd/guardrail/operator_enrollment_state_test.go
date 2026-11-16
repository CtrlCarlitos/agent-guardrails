package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #593: on a fresh install the bootstrap said "no operator enrolled", and a
// later `guardrail operator enroll` refused with "initial enrollment requires
// no enrolled credentials". The operator could not tell whether anyone was
// enrolled. These pin the root cause and the fix.

func stubEnrollCeremony(t *testing.T) *[]string {
	t.Helper()
	previous := runOperatorCeremonyFunc
	var calls []string
	runOperatorCeremonyFunc = func(_ *operatorauth.Store, operation, fingerprint string) error {
		calls = append(calls, operation)
		return nil
	}
	t.Cleanup(func() { runOperatorCeremonyFunc = previous })
	return &calls
}

func seedCredentials(t *testing.T, n int) operatorauth.Store {
	t.Helper()
	store := *defaultOperatorAuthStore()
	if err := os.MkdirAll(filepath.Dir(filepath.Dir(store.Path())), 0o700); err != nil {
		t.Fatal(err)
	}
	creds := []operatorauth.Credential{{ID: "AQI", PublicKey: "cHVibGlj", Algorithm: -7}, {ID: "AwQ", PublicKey: "cHVibGlj", Algorithm: -7}}
	if err := store.Replace(creds[:n]); err != nil {
		t.Fatal(err)
	}
	return store
}

// An unreadable store: the private directory and file exist, but the file does
// not decode. Any read error behaves the same (an ACL guardrail rejects, a
// different principal's file, a truncated copy restored from a backup).
func seedUnreadableStore(t *testing.T) {
	t.Helper()
	store := seedCredentials(t, 1)
	if err := os.WriteFile(store.Path(), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Enrolled(); err == nil {
		t.Fatal("fixture: the store should be unreadable")
	}
}

// Root cause, part 1: nothing on the install path creates credentials. A
// bootstrap setup from a clean state leaves no credential store, and the
// enrollment command then proceeds to the ceremony.
func TestFreshBootstrapLeavesNoOperatorCredentials(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "claude")
	stubSetupGates(t, false, 0, 0)
	calls := stubEnrollCeremony(t)

	code, out, errb := runSetup(t)
	if code != 0 || !strings.Contains(out, "bootstrap: no operator enrolled") {
		t.Fatalf("setup: exit=%d out=%q err=%q; want a bootstrap enable", code, out, errb)
	}
	store := defaultOperatorAuthStore()
	if enrolled, err := store.Enrolled(); enrolled || err != nil {
		t.Fatalf("after bootstrap: enrolled=%v err=%v; want no credentials and no error", enrolled, err)
	}
	if _, err := os.Lstat(filepath.Dir(store.Path())); !os.IsNotExist(err) {
		t.Fatalf("bootstrap created the credential directory (err=%v)", err)
	}
	var stdout, stderr bytes.Buffer
	if code := cmdOperatorInput([]string{"enroll"}, true, strings.NewReader(""), &stdout, &stderr); code != 0 || len(*calls) != 1 {
		t.Fatalf("enroll after bootstrap: exit=%d calls=%v stderr=%q; want the ceremony", code, *calls, stderr.String())
	}
}

// Root cause, part 2: `enroll` printed the same refusal for "credentials are
// enrolled" and "the store could not be read". The second is not enrollment.
func TestEnrollOnAnEnrolledStoreSaysSoAndNamesTheNextCommand(t *testing.T) {
	driftSandbox(t)
	calls := stubEnrollCeremony(t)
	store := seedCredentials(t, 2)
	var stdout, stderr bytes.Buffer
	if code := cmdOperatorInput([]string{"enroll"}, true, strings.NewReader(""), &stdout, &stderr); code != 2 || len(*calls) != 0 {
		t.Fatalf("exit=%d calls=%v; want a refusal before any ceremony", code, *calls)
	}
	got := stderr.String()
	for _, want := range []string{"already enrolled", "2 authenticators", store.Path(), "guardrail operator add-authenticator"} {
		if !strings.Contains(got, want) {
			t.Errorf("refusal lacks %q:\n%s", want, got)
		}
	}
}

func TestEnrollOnAnUnreadableStoreReportsUnknownNotEnrolled(t *testing.T) {
	driftSandbox(t)
	calls := stubEnrollCeremony(t)
	seedUnreadableStore(t)
	var stdout, stderr bytes.Buffer
	if code := cmdOperatorInput([]string{"enroll"}, true, strings.NewReader(""), &stdout, &stderr); code == 0 || len(*calls) != 0 {
		t.Fatalf("exit=%d calls=%v; want a refusal before any ceremony", code, *calls)
	}
	got := stderr.String()
	if !strings.Contains(got, "cannot read the operator credential store") || !strings.Contains(got, "unknown") {
		t.Errorf("refusal must say the store is unreadable and the state unknown:\n%s", got)
	}
	for _, wrong := range []string{"already enrolled", "requires no enrolled credentials"} {
		if strings.Contains(got, wrong) {
			t.Errorf("an unreadable store was reported as enrolled (%q):\n%s", wrong, got)
		}
	}
}

// The fix's other half: doctor shows the enrollment state in every approval
// mode, and an unreadable store is UNKNOWN, never "no authenticator enrolled".
func TestDoctorReportsTheEnrollmentStateInEveryMode(t *testing.T) {
	for _, mode := range []string{policy.ApprovalPrompt, policy.ApprovalPasskey} {
		for _, c := range []struct {
			name  string
			seed  func(*testing.T)
			want  string
			never []string
		}{
			{"none", func(*testing.T) {}, "operator enrollment: none", []string{"UNKNOWN"}},
			{"enrolled", func(t *testing.T) { seedCredentials(t, 1) }, "operator enrollment: 1 authenticator", []string{"no authenticator enrolled", "UNKNOWN"}},
			{"unreadable", seedUnreadableStore, "operator enrollment: UNKNOWN", []string{"no authenticator enrolled", "operator enrollment: none"}},
		} {
			t.Run(mode+"/"+c.name, func(t *testing.T) {
				verdictSandbox(t)
				useApprovalMode(t, mode)
				c.seed(t)
				var out, errb bytes.Buffer
				cmdDoctor(nil, &out, &errb)
				if !strings.Contains(out.String(), c.want) {
					t.Errorf("doctor lacks %q:\n%s", c.want, out.String())
				}
				for _, never := range c.never {
					if strings.Contains(out.String(), never) {
						t.Errorf("doctor says %q:\n%s", never, out.String())
					}
				}
			})
		}
	}
}
