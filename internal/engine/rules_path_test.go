package engine

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func pathPol() *policy.Policy {
	return &policy.Policy{
		Slots: policy.Slots{
			SecretGlobs: []string{
				"**/.env", ".env.*", "**/.env.*",
				"**/.ssh/**", "**/.aws/**", "**/.kube/config", "**/.docker/config.json", "**/.netrc",
				"id_rsa*", "id_ed25519*", "*.pem", "*.key",
				"**/.claude.json", "service-account*.json",
			},
			SecretAllow: []string{"**/.env.example", ".env.example"},
		},
		Waived: map[string]bool{},
	}
}

func TestCheckPathsFileTool(t *testing.T) {
	deny := []string{
		"/home/u/.ssh/id_rsa",
		"/home/u/project/.env",
		"/home/u/project/.env.production",
		"/home/u/.aws/credentials",
		"secrets/server.pem",
		"/home/u/.claude.json",
	}
	for _, p := range deny {
		tc := ToolCall{Tool: "Read", Paths: []string{p}}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("Read %q -> %+v, want deny", p, v)
		}
	}
	ok := []string{"/home/u/project/.env.example", "src/main.go", "README.md"}
	for _, p := range ok {
		tc := ToolCall{Tool: "Read", Paths: []string{p}}
		if v := checkPaths(tc, pathPol()); v != nil {
			t.Errorf("Read %q -> %+v, want nil", p, v)
		}
	}
}

func TestGlobMatchingIgnoresDotSegments(t *testing.T) {
	pol := pathPol()
	deny := []string{
		"/home/u/.kube/./config",
		"/home/u/.kube//config",
		"/home/u/.docker/./config.json",
		"/repo/.git/x/../config",
	}
	for _, p := range deny {
		tc := ToolCall{Tool: "Write", Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want a deny (dot-segments must not defeat the glob)", p, v)
		}
	}
}

func TestCheckPathsBashReader(t *testing.T) {
	tc := ToolCall{Tool: "Bash", Command: `cat ~/.aws/credentials`}
	if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
		t.Errorf("cat credentials -> %+v, want deny", v)
	}
	tc = ToolCall{Tool: "Bash", Command: `grep -r TODO src/`}
	if v := checkPaths(tc, pathPol()); v != nil {
		t.Errorf("grep src -> %+v, want nil", v)
	}
}

func TestCheckPathsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	repo := t.TempDir()
	outside := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(repo, "innocent.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	tc := ToolCall{Tool: "Edit", Paths: []string{link}, RepoRoot: repo, CWD: repo}
	v := checkPaths(tc, pathPol())
	if v == nil || v.RuleID != "P4.symlink-escape" {
		t.Fatalf("-> %+v, want deny/P4.symlink-escape", v)
	}
}

func TestGitProtectedPathWrite(t *testing.T) {
	tc := ToolCall{Tool: "Edit", Paths: []string{"/repo/.git/hooks/pre-commit"}, RepoRoot: "/repo", CWD: "/repo"}
	v := checkPaths(tc, pathPol())
	if v == nil || v.Decision != policy.Deny || v.RuleID != "P2.git-protected-path" {
		t.Fatalf("-> %+v, want deny/P2.git-protected-path", v)
	}
	tc = ToolCall{Tool: "Edit", Paths: []string{"/repo/.git/config"}, RepoRoot: "/repo", CWD: "/repo"}
	if v := checkPaths(tc, pathPol()); v == nil || v.RuleID != "P2.git-protected-path" {
		t.Fatalf(".git/config -> %+v, want deny", v)
	}
	tc = ToolCall{Tool: "Edit", Paths: []string{"/repo/src/main.go"}, RepoRoot: "/repo", CWD: "/repo"}
	if v := checkPaths(tc, pathPol()); v != nil {
		t.Fatalf("unrelated path -> %+v, want nil", v)
	}
}

func TestSelfConfigDenied(t *testing.T) {
	deny := []string{"/repo/.claude/settings.json", "/repo/CLAUDE.md", "/repo/AGENTS.md", "/repo/.mcp.json", "/repo/.envrc", "/home/u/.bashrc", "/home/u/.zshrc"}
	for _, p := range deny {
		tc := ToolCall{Tool: "Edit", Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("Edit %q -> %+v, want deny/P5.self-config", p, v)
		}
	}
	tc := ToolCall{Tool: "Edit", Paths: []string{"/repo/src/main.go"}, RepoRoot: "/repo", CWD: "/repo"}
	if v := checkPaths(tc, pathPol()); v != nil {
		t.Errorf("unrelated path -> %+v, want nil", v)
	}
}

func TestCIInfraLockfileAsk(t *testing.T) {
	ask := []string{
		"/repo/.github/workflows/ci.yml", "/repo/Dockerfile", "/repo/docker-compose.yml",
		"/repo/main.tf", "/repo/Makefile", "/repo/package-lock.json", "/repo/go.sum",
	}
	for _, p := range ask {
		tc := ToolCall{Tool: "Write", Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Ask || v.RuleID != "P5.ci-infra-lockfile" {
			t.Errorf("Write %q -> %+v, want ask/P5.ci-infra-lockfile", p, v)
		}
	}
	tc := ToolCall{Tool: "Read", Paths: []string{"/repo/go.sum"}, RepoRoot: "/repo", CWD: "/repo"}
	if v := checkPaths(tc, pathPol()); v != nil {
		t.Errorf("reading a lockfile -> %+v, want nil", v)
	}
}

func TestOutOfRepoWriteAsk(t *testing.T) {
	tc := ToolCall{Tool: "Write", Paths: []string{"/etc/hosts"}, RepoRoot: "/repo", CWD: "/repo"}
	v := checkPaths(tc, pathPol())
	if v == nil || v.Decision != policy.Ask || v.RuleID != "P5.out-of-repo" {
		t.Fatalf("-> %+v, want ask/P5.out-of-repo", v)
	}
	tc = ToolCall{Tool: "Write", Paths: []string{"/repo/src/new.go"}, RepoRoot: "/repo", CWD: "/repo"}
	if v := checkPaths(tc, pathPol()); v != nil {
		t.Fatalf("in-repo write -> %+v, want nil", v)
	}
	// deviation from plan (controller ruling 2): ../outside.txt with CWD /repo/sub
	// resolves to /repo/outside.txt — inside the repo — so ../../ is used for a
	// true escape (/outside.txt).
	tc = ToolCall{Tool: "Write", Paths: []string{"../../outside.txt"}, RepoRoot: "/repo", CWD: "/repo/sub"}
	if v := checkPaths(tc, pathPol()); v == nil || v.RuleID != "P5.out-of-repo" {
		t.Fatalf("relative escape -> %+v, want ask/P5.out-of-repo", v)
	}
}

func TestCheckPathsSecretWaivedStillChecksSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	repo := t.TempDir()
	outside := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(repo, ".env") // matches P4.secret-path globs AND is a symlink out
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	pol := pathPol()
	pol.Waived["P4.secret-path"] = true
	tc := ToolCall{Tool: "Edit", Paths: []string{link}, RepoRoot: repo, CWD: repo}
	v := checkPaths(tc, pol)
	if v == nil || v.RuleID != "P4.symlink-escape" {
		t.Fatalf("-> %+v, want deny/P4.symlink-escape even with P4.secret-path waived", v)
	}
}
