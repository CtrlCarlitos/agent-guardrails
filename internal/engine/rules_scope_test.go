package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// wantAllow is strict: nil or Allow. "Not deny" would let an accidental ask
// pass silently, which is how a false positive hides in a green suite.
func wantAllow(t *testing.T, label string, v *policy.Verdict) {
	t.Helper()
	if v != nil && v.Decision != policy.Allow {
		t.Errorf("%s -> %+v, want allow", label, v)
	}
}

func TestRootOnlyGlobsMatchOnlyAtRepoRoot(t *testing.T) {
	deep := []struct{ path, cwd string }{
		{"CLAUDE.md", "/repo/docs/templates"}, {"/repo/docs/templates/CLAUDE.md", "/repo"},
		{"Makefile", "/repo/vendor/x"}, {"/repo/vendor/x/Makefile", "/repo"},
		{"conftest.py", "/repo/tests/unit"}, {"/repo/tests/unit/conftest.py", "/repo"},
	}
	for _, d := range deep {
		tc := ToolCall{Tool: "Write", Paths: []string{d.path}, CWD: d.cwd, RepoRoot: "/repo"}
		wantAllow(t, "selfConfig "+d.path+" cwd "+d.cwd, checkSelfConfig(tc))
		wantAllow(t, "ciInfra "+d.path+" cwd "+d.cwd, checkCIInfraLockfile(tc))
	}
	for _, r := range []struct{ path, cwd, root string }{
		{"CLAUDE.md", "/repo", "/repo"}, {"/repo/CLAUDE.md", "/repo", "/repo"}, {"./CLAUDE.md", "/repo", "/repo"},
		{"/CLAUDE.md", "/", "/"}, // repoRoot "/" — must not be rejected by containment
	} {
		tc := ToolCall{Tool: "Write", Paths: []string{r.path}, CWD: r.cwd, RepoRoot: r.root}
		if v := checkSelfConfig(tc); v == nil || v.Decision != policy.Deny {
			t.Errorf("selfConfig %q (root %s) -> %+v, want deny", r.path, r.root, v)
		}
	}
	for _, p := range []string{"/home/u/.bashrc", "/repo/sub/.envrc", "/repo/.envrc"} {
		tc := ToolCall{Tool: "Write", Paths: []string{p}, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkSelfConfig(tc); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny (anywhere glob unaffected by repo scoping)", p, v)
		}
	}
	// Containment is case-insensitive; an escape is never repo-relative.
	up := ToolCall{Tool: "Write", Paths: []string{"/REPO/CLAUDE.md"}, CWD: "/REPO", RepoRoot: "/repo"}
	if v := checkSelfConfig(up); v == nil || v.Decision != policy.Deny {
		t.Errorf("/REPO/CLAUDE.md with root /repo -> %+v, want deny", v)
	}
	esc := ToolCall{Tool: "Write", Paths: []string{"/etc/CLAUDE.md"}, CWD: "/repo", RepoRoot: "/repo"}
	wantAllow(t, "/etc/CLAUDE.md is outside the repo (self-config)", checkSelfConfig(esc))
	// Root-level CI files still ask; nested ones do not.
	rootMk := ToolCall{Tool: "Write", Paths: []string{"/repo/Makefile"}, CWD: "/repo", RepoRoot: "/repo"}
	if v := checkCIInfraLockfile(rootMk); v == nil || v.Decision != policy.Ask {
		t.Errorf("/repo/Makefile -> %+v, want ask", v)
	}
	nestedWf := ToolCall{Tool: "Write", Paths: []string{"/repo/sub/.github/workflows/ci.yml"}, CWD: "/repo", RepoRoot: "/repo"}
	if v := checkCIInfraLockfile(nestedWf); v == nil || v.Decision != policy.Ask {
		t.Errorf("nested workflows dir -> %+v, want ask (anywhere glob)", v)
	}
}

func TestRepoRelativeHandlesRootAndEscapes(t *testing.T) {
	for _, c := range []struct {
		p, cwd, root, want string
		ok                 bool
	}{
		{"/CLAUDE.md", "/", "/", "claude.md", true},
		{"/repo/docs/CLAUDE.md", "/repo", "/repo", "docs/claude.md", true},
		{"CLAUDE.md", "/repo/docs", "/repo", "docs/claude.md", true},
		{"/REPO/CLAUDE.md", "/REPO", "/repo", "claude.md", true},
		{"/etc/passwd", "/repo", "/repo", "", false},
		{"/repo", "/repo", "/repo", "", false},
		{"x", "", "/repo", "", false},
		{"/repo/x", "/repo", "", "x", true}, // no RepoRoot: adapters fall back to CWD
		{"/repo/x", "", "", "", false},
	} {
		got, ok := repoRelative(c.p, c.cwd, c.root)
		if ok != c.ok || got != c.want {
			t.Errorf("repoRelative(%q,%q,%q) = (%q,%v), want (%q,%v)", c.p, c.cwd, c.root, got, ok, c.want, c.ok)
		}
	}
}

func TestRootOnlyGlobsFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "CLAUDE.md"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "CLAUDE.md"), filepath.Join(root, "notes.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	tc := ToolCall{Tool: "Write", Paths: []string{filepath.Join(root, "notes.md")}, CWD: root, RepoRoot: root}
	if v := checkSelfConfig(tc); v == nil || v.Decision != policy.Deny {
		t.Errorf("symlink to CLAUDE.md -> %+v, want deny", v)
	}
}

// H-7: matching is case-insensitive for every list, not only secrets. On APFS
// and NTFS each of these opens the same file as its canonical-case sibling.
func TestGlobMatchingIsCaseInsensitiveAcrossLists(t *testing.T) {
	pol := pathPol()
	for _, c := range []struct {
		tool, path, rule string
		want             policy.Decision
	}{
		{"Read", "/home/u/.SSH/ID_RSA", "P4.secret-path", policy.Deny},
		{"Read", "/home/u/.Ssh/id_rsa", "P4.secret-path", policy.Deny},
		{"Read", "/repo/.ENV", "P4.secret-path", policy.Deny},
		{"Read", "/home/u/.AWS/credentials", "P4.secret-path", policy.Deny},
		{"Write", "/home/u/.BASHRC", "P5.self-config", policy.Deny},
		{"Write", "/repo/claude.MD", "P5.self-config", policy.Deny},
		{"Write", "/repo/.Claude/settings.json", "P5.self-config", policy.Deny},
		{"Write", "/repo/.GIT/config", "P2.git-protected-path", policy.Deny},
		{"Write", "/repo/.git/HOOKS/pre-commit", "P2.git-protected-path", policy.Deny},
		{"Write", "/repo/MAKEFILE", "P5.ci-infra-lockfile", policy.Ask},
		{"Write", "/repo/.GitHub/Workflows/ci.yml", "P5.ci-infra-lockfile", policy.Ask},
	} {
		tc := ToolCall{Tool: c.tool, Paths: []string{c.path}, CWD: "/repo", RepoRoot: "/repo"}
		v := checkPaths(tc, pol)
		if v == nil || v.Decision != c.want || v.RuleID != c.rule {
			t.Errorf("%s %q -> %+v, want %s/%s", c.tool, c.path, v, c.want, c.rule)
		}
	}
}

func TestNoBasenameFallbackForSecretGlobs(t *testing.T) {
	// With "**/" prefixes the base globs still match at depth without the
	// fallback; a bare glob would now match only a path that IS that name.
	pol := pathPol()
	for _, p := range []string{"secrets/server.pem", "/repo/keys/id_rsa", "id_rsa", "/repo/svc/service-account.json"} {
		tc := ToolCall{Tool: "Read", Paths: []string{p}, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("Read %q -> %+v, want deny", p, v)
		}
	}
}
