package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
)

func TestOperatorCommandsRequireLocalTerminal(t *testing.T) {
	for _, command := range []string{"enroll", "add-authenticator", "remove-authenticator", "recover-reset"} {
		var stdout, stderr bytes.Buffer
		if code := cmdOperatorInput([]string{command}, false, strings.NewReader("yes\n"), &stdout, &stderr); code != 2 {
			t.Fatalf("%s without terminal exit = %d, want 2", command, code)
		}
	}
}

func TestRecoverResetRequiresConfirmationAndDisablesApprovals(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	store := operatorauth.NewStore(filepath.Join(state, "guardrail"))
	if err := os.MkdirAll(filepath.Dir(store.Path()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.Replace([]operatorauth.Credential{{ID: "AQI", PublicKey: "cHVibGlj", Algorithm: -7}}); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := cmdOperatorInput([]string{"recover-reset"}, true, strings.NewReader("no\n"), &stdout, &stderr); code != 2 {
		t.Fatalf("unconfirmed reset exit = %d, want 2", code)
	}
	if _, err := os.Lstat(store.Path()); err != nil {
		t.Fatalf("unconfirmed reset removed credentials: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := cmdOperatorInput([]string{"recover-reset"}, true, strings.NewReader("RESET\n"), &stdout, &stderr); code != 0 {
		t.Fatalf("confirmed reset exit = %d, stderr=%q", code, stderr.String())
	}
	if _, err := os.Lstat(store.Path()); !os.IsNotExist(err) {
		t.Fatalf("recovery did not clear credentials: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(state, "guardrail", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	if len(records) != 2 || records[0]["decision"] != "requested" || records[1]["decision"] != "completed" {
		t.Fatalf("recovery audit records = %#v, want request before completion", records)
	}
}

func TestRecoveryDoesNotClearCredentialsWhenRequestAuditFails(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	store := operatorauth.NewStore(filepath.Join(state, "guardrail"))
	if err := os.MkdirAll(filepath.Dir(store.Path()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.Replace([]operatorauth.Credential{{ID: "AQI", PublicKey: "cHVibGlj", Algorithm: -7}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(state, "guardrail", "audit.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := cmdOperatorInput([]string{"recover-reset"}, true, strings.NewReader("RESET\n"), &stdout, &stderr); code != 1 {
		t.Fatalf("reset with unwritable audit exit = %d, want 1", code)
	}
	if _, err := os.Lstat(store.Path()); err != nil {
		t.Fatalf("request-audit failure cleared credentials: %v", err)
	}
}

func TestCredentialManagementCommandsGateBeforeBrowserCeremony(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	previous := runOperatorCeremonyFunc
	var calls []string
	runOperatorCeremonyFunc = func(_ *operatorauth.Store, operation, fingerprint string) error {
		calls = append(calls, operation+":"+fingerprint)
		return nil
	}
	t.Cleanup(func() { runOperatorCeremonyFunc = previous })
	store := operatorauth.NewStore(filepath.Join(state, "guardrail"))
	var stdout, stderr bytes.Buffer
	if code := cmdOperatorInput([]string{"add-authenticator"}, true, strings.NewReader(""), &stdout, &stderr); code != 2 || len(calls) != 0 {
		t.Fatalf("unenrolled add = exit %d calls %#v", code, calls)
	}
	if err := os.MkdirAll(filepath.Dir(store.Path()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.Replace([]operatorauth.Credential{{ID: "AQI", PublicKey: "cHVibGlj", Algorithm: -7}}); err != nil {
		t.Fatal(err)
	}
	if code := cmdOperatorInput([]string{"remove-authenticator", "fingerprint"}, true, strings.NewReader(""), &stdout, &stderr); code != 2 || len(calls) != 0 {
		t.Fatalf("final-credential removal = exit %d calls %#v", code, calls)
	}
	if err := store.Replace([]operatorauth.Credential{{ID: "AQI", PublicKey: "cHVibGlj", Algorithm: -7}, {ID: "AwQ", PublicKey: "cHVibGlj", Algorithm: -7}}); err != nil {
		t.Fatal(err)
	}
	if code := cmdOperatorInput([]string{"add-authenticator"}, true, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("enrolled add exit = %d", code)
	}
	if code := cmdOperatorInput([]string{"remove-authenticator", "fingerprint"}, true, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("nonfinal removal exit = %d", code)
	}
	if want := []string{"add:", "remove:fingerprint"}; strings.Join(calls, ",") != strings.Join(want, ",") {
		t.Fatalf("ceremony calls = %#v, want %#v", calls, want)
	}
}
