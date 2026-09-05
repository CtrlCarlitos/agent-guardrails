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
	tc = ToolCall{Tool: "Bash", Command: `/bin/cat ~/.aws/credentials`}
	if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
		t.Errorf("absolute cat credentials -> %+v, want deny", v)
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

func TestGuardrailOwnMachineryIsProtected(t *testing.T) {
	protected := []string{
		"/repo/guardrail.toml",
		"/repo/.guardrail/guardrail.js",
		"/repo/opencode.json",
		"/repo/.agents/hooks.json",
		"/home/u/.gemini/config/hooks.json",
		"/home/u/.local/bin/guardrail",
		"/repo/bin/guardrail",
	}
	for _, p := range protected {
		read := ToolCall{Tool: "Read", Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkPaths(read, pathPol()); v != nil {
			t.Errorf("Read %q -> %+v, want nil (reads are not the risk)", p, v)
		}

		write := ToolCall{Tool: "Write", Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(write, pathPol())
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("Write %q -> %+v, want deny/P5.self-config (the agent must not configure its own guard)", p, v)
		}
	}
}

func TestOperatorConfigIsProtected(t *testing.T) {
	protected := []string{
		"/home/u/.config/guardrail/anything.toml",
		"/home/u/guardrail/waivers.toml",
	}
	for _, p := range protected {
		read := ToolCall{Tool: "Read", Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkPaths(read, pathPol()); v != nil {
			t.Errorf("Read %q -> %+v, want nil (reads are not the risk)", p, v)
		}

		for _, tool := range []string{"Write", "Edit"} {
			tc := ToolCall{Tool: tool, Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
			v := checkPaths(tc, pathPol())
			if v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
				t.Errorf("%s %q -> %+v, want deny/P5.self-config", tool, p, v)
			}
		}
	}

	for _, command := range []string{
		"cp /tmp/evil /home/u/.config/guardrail/anything.toml",
		"sed -i s/deny/allow/ /home/u/guardrail/waivers.toml",
	} {
		tc := ToolCall{Tool: "Bash", Command: command, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("Bash %q -> %+v, want deny/P5.self-config", command, v)
		}
	}
}

func TestSelfConfigAndGitProtectedAllowReads(t *testing.T) {
	allow := []string{
		"/repo/CLAUDE.md", "/repo/AGENTS.md",
		"/home/u/.claude/skills/x/SKILL.md",
		"/home/u/.claude/plugins/cache/x/y.js",
		"/repo/.git/config", "/repo/.git/hooks/pre-commit",
	}
	for _, p := range allow {
		tc := ToolCall{Tool: "Read", Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkPaths(tc, pathPol()); v != nil {
			t.Errorf("Read %q -> %+v, want nil (reads are not the risk)", p, v)
		}
	}
}

func TestSelfConfigAndGitProtectedStillDenyWrites(t *testing.T) {
	deny := []struct {
		path       string
		ruleID     string
		wantReason string
	}{
		{"/repo/.claude/settings.json", "P5.self-config", "write to the agent's own guardrail/shell config: /repo/.claude/settings.json"},
		{"/repo/CLAUDE.md", "P5.self-config", "write to the agent's own guardrail/shell config: /repo/CLAUDE.md"},
		{"/home/u/.claude/settings.json", "P5.self-config", "write to the agent's own guardrail/shell config: /home/u/.claude/settings.json"},
		{"/repo/.git/config", "P2.git-protected-path", "write to a protected git-internal path: /repo/.git/config"},
		{"/repo/.git/hooks/pre-commit", "P2.git-protected-path", "write to a protected git-internal path: /repo/.git/hooks/pre-commit"},
	}
	for _, tool := range []string{"Edit", "Write", "MultiEdit"} {
		for _, test := range deny {
			tc := ToolCall{Tool: tool, Paths: []string{test.path}, RepoRoot: "/repo", CWD: "/repo"}
			v := checkPaths(tc, pathPol())
			if v == nil || v.Decision != policy.Deny || v.RuleID != test.ruleID || v.Reason != test.wantReason {
				t.Errorf("%s %q -> %+v, want deny/%s with reason %q", tool, test.path, v, test.ruleID, test.wantReason)
			}
		}
	}
}

func TestSelfConfigAndGitProtectedStillDenyBashRedirects(t *testing.T) {
	deny := []struct {
		path       string
		ruleID     string
		wantReason string
	}{
		{"/repo/CLAUDE.md", "P5.self-config", "write to the agent's own guardrail/shell config: /repo/CLAUDE.md"},
		{"/repo/.git/config", "P2.git-protected-path", "write to a protected git-internal path: /repo/.git/config"},
	}
	for _, test := range deny {
		tc := ToolCall{Tool: "Bash", Command: "printf x > " + test.path, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny || v.RuleID != test.ruleID || v.Reason != test.wantReason {
			t.Errorf("Bash redirect to %q -> %+v, want deny/%s with reason %q", test.path, v, test.ruleID, test.wantReason)
		}
	}
}

func TestWritesByArgumentAreSeen(t *testing.T) {
	deny := []string{
		`cp evil /home/u/.claude/settings.json`,
		`mv evil /home/u/.claude/settings.json`,
		`rm /home/u/.claude/settings.json`,
		`install -m755 evil /home/u/.claude/settings.json`,
		`sed -i s/a/b/ /repo/.git/hooks/pre-commit`,
		`ln -sf evil /repo/.git/hooks/pre-commit`,
		`dd if=evil of=/repo/.git/hooks/pre-commit`,
		`cp evil /repo/guardrail.toml`,
		`rsync evil /repo/guardrail.toml`,
		`truncate /repo/guardrail.toml`,
		`chmod 600 /repo/guardrail.toml`,
		`chown user /repo/guardrail.toml`,
		`mkdir /repo/.claude`,
		`tee /repo/guardrail.toml`,
		`touch /repo/guardrail.toml`,
		`shred /repo/guardrail.toml`,
		`/usr/bin/cp evil /repo/guardrail.toml`,
	}
	for _, c := range deny {
		tc := ToolCall{Tool: "Bash", Command: c, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestCR15ExactReproductionsAreDenied(t *testing.T) {
	deny := []string{
		`cp /tmp/evil /repo/.git/hooks/pre-commit`,
		`sed -i s/a/b/ /repo/.git/hooks/pre-commit`,
		`install -m755 /tmp/evil /repo/.git/hooks/pre-commit`,
		`dd if=/tmp/evil of=/repo/.git/hooks/pre-commit`,
		`ln -sf /tmp/evil /repo/.git/hooks/pre-commit`,
		`echo x | tee /repo/.claude/settings.json`,
		`cp /tmp/evil ~/.bashrc`,
		`cp evil ~/.claude/settings.json`,
		`rm ~/.claude/settings.json`,
		`install -m755 evil ~/.local/bin/guardrail`,
		`cp /tmp/evil ~/.claude/settings.json`,
		`install -m755 /tmp/evil ~/.local/bin/guardrail`,
	}
	for _, c := range deny {
		tc := ToolCall{Tool: "Bash", Command: c, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestClusteredTargetDirectoryOptionsAreSeen(t *testing.T) {
	deny := []string{
		`cp -vt /home/u/.claude /tmp/settings.json`,
		`mv -vt/home/u/.claude /tmp/settings.json`,
		`install -vDt /home/u/.local/bin /tmp/guardrail`,
		`ln -sft/repo/.git/hooks /tmp/pre-commit`,
	}
	for _, c := range deny {
		tc := ToolCall{Tool: "Bash", Command: c, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestValuedOptionsDoNotReplaceMutatingCommandDestination(t *testing.T) {
	deny := []string{
		`cp /tmp/evil /repo/guardrail.toml --suffix .bak`,
		`cp /tmp/evil /repo/guardrail.toml --suffix=.bak`,
		`mv /tmp/evil /repo/guardrail.toml -S .bak`,
		`install /tmp/evil /repo/guardrail.toml --mode 755`,
		`ln -s /tmp/evil /repo/.git/hooks/pre-commit -S.bak`,
		`rsync /tmp/evil /repo/guardrail.toml --backup-dir /tmp/backups`,
		`rsync /tmp/evil /tmp --backup-dir /repo/.claude`,
		`cp /tmp/evil /repo/guardrail.toml --unknown-option value`,
		`cp /tmp/evil -- --suffix /repo/guardrail.toml`,
	}
	for _, c := range deny {
		tc := ToolCall{Tool: "Bash", Command: c, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestValuedOptionArgumentsAreNotDestinations(t *testing.T) {
	allow := []string{
		`cp /repo/CLAUDE.md /tmp --suffix .bashrc`,
		`mv /repo/CLAUDE.md /tmp -S .bashrc`,
		`install /repo/CLAUDE.md /tmp --mode CLAUDE.md`,
		`ln -s /repo/CLAUDE.md /tmp/link --suffix .bashrc`,
		`rsync /repo/CLAUDE.md /tmp --exclude-from /repo/.claude`,
		`rsync -t /repo/CLAUDE.md /tmp`,
		`rsync -S /repo/CLAUDE.md /tmp`,
		`cp /tmp/evil -- /repo/CLAUDE.md /tmp`,
	}
	for _, c := range allow {
		tc := ToolCall{Tool: "Bash", Command: c, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkSelfConfig(tc); v != nil {
			t.Errorf("%q -> %+v, want nil (option values and sources are not destinations)", c, v)
		}
	}
}

func TestMutatingCommandTargetDirectoriesAreSeen(t *testing.T) {
	deny := []string{
		`cp --target-directory=/home/u/.claude /tmp/settings.json`,
		`mv --target-directory /home/u/.claude /tmp/settings.json`,
		`install --target-directory=/home/u/.local/bin /tmp/guardrail`,
		`install --target-directory /home/u/.local/bin /tmp/guardrail`,
		`ln -t /repo/.git/hooks /tmp/pre-commit`,
		`cp -t/home/u/.claude /tmp/settings.json`,
		`cp -t /home/u/.claude /tmp/settings.json`,
	}
	for _, c := range deny {
		tc := ToolCall{Tool: "Bash", Command: c, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestMutatingCommandSourcesAreNotWriteTargets(t *testing.T) {
	allow := []string{
		`cp /tmp/a /repo/CLAUDE.md /tmp`,
		`mv /tmp/a /repo/CLAUDE.md /tmp`,
		`install /tmp/a /repo/CLAUDE.md /tmp`,
		`ln /tmp/a /repo/CLAUDE.md /tmp`,
		`rsync /tmp/a /repo/CLAUDE.md /tmp`,
		`rsync -t /repo/CLAUDE.md /tmp`,
	}
	for _, c := range allow {
		tc := ToolCall{Tool: "Bash", Command: c, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkSelfConfig(tc); v != nil {
			t.Errorf("%q -> %+v, want nil (only the final positional operand is the destination)", c, v)
		}
	}
}

func TestReadingViaMutatingCommandSourceIsNotAWrite(t *testing.T) {
	// `cp <protected> /tmp/x` reads the protected file; it is not a write to it.
	// It must not be reported as a self-config write (the secret-path rule
	// covers the read side separately).
	tc := ToolCall{Tool: "Bash", Command: `cp /repo/CLAUDE.md /tmp/x`, RepoRoot: "/repo", CWD: "/repo"}
	if v := checkSelfConfig(tc); v != nil {
		t.Errorf("-> %+v, want nil (source position is a read, not a write)", v)
	}
}

func TestSedWithoutInPlaceFlagIsNotAWrite(t *testing.T) {
	tc := ToolCall{Tool: "Bash", Command: `sed s/a/b/ /repo/CLAUDE.md`, RepoRoot: "/repo", CWD: "/repo"}
	if v := checkSelfConfig(tc); v != nil {
		t.Errorf("-> %+v, want nil (sed without -i does not write its input)", v)
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
