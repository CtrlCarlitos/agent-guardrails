package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func gitRepo(t *testing.T) string {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	if out, err := exec.Command("git", "init", "-q", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	return repo
}

// setOperatorEnv points the operator config and allowance journal roots at
// throwaway directories on every platform: XDG on Unix, APPDATA and
// LOCALAPPDATA on Windows.
func setOperatorEnv(t *testing.T) {
	t.Helper()
	testenv.Sandbox(t)
}

func TestEgressIsAnOperatorActionOutsideATerminal(t *testing.T) {
	var out, errb bytes.Buffer
	code := cmdEgress([]string{"grant", "--scope", "repo", "--host", "api.example.test"}, false, t.TempDir(), &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "operator action") || !strings.Contains(errb.String(), "terminal") || !strings.Contains(errb.String(), "guarded session") {
		t.Fatalf("code=%d stderr=%q", code, errb.String())
	}
}

func TestEgressGrantFromTerminalAuthorizesRepositoryHosts(t *testing.T) {
	setOperatorEnv(t)
	repo := gitRepo(t)
	var out, errb bytes.Buffer
	code := cmdEgress([]string{"grant", "--scope", "repo", "--host", "a.example.test,b.example.test"}, true, filepath.Join(repo), &out, &errb)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errb.String())
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	root, _ := policy.FindRepoRoot(repo)
	for _, host := range []string{"a.example.test", "b.example.test"} {
		if !op.AllowsWebHost(root, host) {
			t.Fatalf("%s not authorized for %s", host, root)
		}
	}
	ov, err := policy.LoadOverlay(filepath.Join(root, "guardrail.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ov.WebHosts, ",") != "a.example.test,b.example.test" {
		t.Fatalf("overlay web hosts = %v", ov.WebHosts)
	}
	if !strings.Contains(out.String(), "granted") || !strings.Contains(out.String(), "a.example.test") || !strings.Contains(out.String(), "b.example.test") {
		t.Fatalf("stdout = %q", out.String())
	}

	out.Reset()
	code = cmdEgress([]string{"revoke", "--scope", "repo", "--host", "a.example.test"}, true, repo, &out, &errb)
	if code != 0 {
		t.Fatalf("revoke code=%d stderr=%q", code, errb.String())
	}
	op, _ = policy.LoadOperatorConfig()
	if op.AllowsWebHost(root, "a.example.test") || !op.AllowsWebHost(root, "b.example.test") {
		t.Fatal("revoke did not remove exactly the named host")
	}
}

func TestEgressGlobalGrantFromTerminalDoesNotTouchOverlay(t *testing.T) {
	setOperatorEnv(t)
	dir := t.TempDir()
	var out, errb bytes.Buffer
	if code := cmdEgress([]string{"grant", "--scope", "global", "--host", "g.example.test"}, true, dir, &out, &errb); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errb.String())
	}
	op, _ := policy.LoadOperatorConfig()
	if !op.AllowsGlobalWebHost("g.example.test") {
		t.Fatal("global grant not applied")
	}
	if _, err := policy.LoadOverlay(filepath.Join(dir, "guardrail.toml")); err == nil {
		t.Fatal("global grant must not write an overlay")
	}
}

func TestEgressRejectsBadInput(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cases := [][]string{
		{"grant"},
		{"grant", "--scope", "repo"},
		{"grant", "--scope", "nope", "--host", "a.example.test"},
		{"grant", "--scope", "repo", "--host", "not a host"},
		{"grant", "--scope", "repo", "--host", "a.example.test", "extra"},
		{"frobnicate", "--scope", "repo", "--host", "a.example.test"},
	}
	for _, args := range cases {
		var out, errb bytes.Buffer
		if code := cmdEgress(args, true, t.TempDir(), &out, &errb); code != 2 || errb.Len() == 0 {
			t.Fatalf("%v: code=%d stderr=%q", args, code, errb.String())
		}
	}
	// repo scope outside any repository is refused rather than guessed.
	var out, errb bytes.Buffer
	if code := cmdEgress([]string{"grant", "--scope", "repo", "--host", "a.example.test"}, true, t.TempDir(), &out, &errb); code != 2 || !strings.Contains(errb.String(), "repository") {
		t.Fatalf("outside repo: code=%d stderr=%q", code, errb.String())
	}
}

func TestEgressHelpAndDispatch(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"egress", "help"}, strings.NewReader(""), &out, &errb); code != 0 || !strings.Contains(out.String(), "guardrail egress grant --scope repo|global --host") {
		t.Fatalf("help code=%d out=%q", code, out.String())
	}
	if !strings.Contains(usage, "egress grant") {
		t.Fatal("top-level usage does not list egress")
	}
}
