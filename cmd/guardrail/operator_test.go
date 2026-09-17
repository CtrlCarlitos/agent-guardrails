package main

import (
	"bytes"
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
}
