package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// TestMain sandboxes the whole package: portable and Windows home, config,
// and state variables point into fresh temp directories unless a test
// overrides them through testenv, so no test can ever mutate the operator's
// real settings through lifecycle, recover, or approval paths (the
// guardrail.test-pollution lesson).
func TestMain(m *testing.M) {
	// Approval helpers intentionally share the parent's test-owned state root so
	// separate processes can exercise one-shot approval consumption and locking.
	if os.Getenv("GUARDRAIL_TEST_OPENCODE_APPROVAL_HELPER") == "1" {
		os.Exit(m.Run())
	}

	env := &processTestEnv{}
	testenv.Sandbox(env)
	if env.err != nil {
		fmt.Fprintln(os.Stderr, "cannot sandbox command test environment:", env.err)
		env.cleanup()
		os.Exit(1)
	}
	code := m.Run()
	env.cleanup()
	os.Exit(code)
}

// processTestEnv adapts the package-wide TestMain lifecycle to testenv's
// testing.TB-shaped helpers. TestMain exits the process, so environment
// restoration is unnecessary; the temporary roots still need explicit
// cleanup because there is no testing.T.Cleanup at this level.
type processTestEnv struct {
	dirs []string
	err  error
}

func (*processTestEnv) Helper() {}

func (e *processTestEnv) Setenv(name, value string) {
	if e.err == nil {
		e.err = os.Setenv(name, value)
	}
}

func (e *processTestEnv) TempDir() string {
	if e.err != nil {
		return ""
	}
	dir, err := os.MkdirTemp("", "guardrail-command-tests-*")
	if err != nil {
		e.err = err
		return ""
	}
	e.dirs = append(e.dirs, dir)
	return dir
}

func (e *processTestEnv) cleanup() {
	for _, dir := range e.dirs {
		_ = os.RemoveAll(dir)
	}
}
