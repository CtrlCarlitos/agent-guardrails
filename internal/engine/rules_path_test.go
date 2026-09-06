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

func TestBashPathCandidatesRetainStatementCwd(t *testing.T) {
	repo := t.TempDir()
	for _, dir := range []string{".aws", ".git", ".claude", filepath.Join(".github", "workflows")} {
		if err := os.MkdirAll(filepath.Join(repo, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		command string
		ruleID  string
	}{
		{`cd .aws; cat credentials`, "P4.secret-path"},
		{`cd .aws; cat < credentials`, "P4.secret-path"},
		{`cd .aws; printf x > credentials`, "P4.secret-path"},
		{`cd .aws; cp source credentials`, "P4.secret-path"},
		{`cd .git; touch config`, "P2.git-protected-path"},
		{`cd .git; printf x > config`, "P2.git-protected-path"},
		{`cd .claude; touch settings.json`, "P5.self-config"},
		{`cd .claude; cp source settings.json`, "P5.self-config"},
		{`cd .github/workflows; touch ci.yml`, "P5.ci-infra-lockfile"},
	}
	for _, test := range cases {
		tc := ToolCall{Tool: "Bash", Command: test.command, CWD: repo, RepoRoot: repo}
		v := checkPaths(tc, pathPol())
		if v == nil || v.RuleID != test.ruleID {
			t.Errorf("%q -> %+v, want %s", test.command, v, test.ruleID)
		}
	}
}

func TestBashPathCandidatesRetainUnknownCwd(t *testing.T) {
	candidates := privatePathCandidates(ToolCall{Tool: "Bash", Command: `cd "$TARGET"; cat credentials`, CWD: "/repo"})
	for _, candidate := range candidates {
		if candidate.path == "credentials" {
			if !candidate.cwdUnknown {
				t.Fatalf("credentials candidate = %+v, want unknown cwd", candidate)
			}
			return
		}
	}
	t.Fatalf("credentials candidate missing: %+v", candidates)
}

func TestSecretAllowIsAppliedIndependentlyToResolvedForm(t *testing.T) {
	repo := t.TempDir()
	secret := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(repo, ".env.example")
	if err := os.Symlink(secret, alias); err != nil {
		t.Skipf("create symlink: %v", err)
	}
	tc := ToolCall{Tool: "Read", Paths: []string{alias}, CWD: repo, RepoRoot: repo}
	if v := checkPaths(tc, pathPol()); v == nil || v.RuleID != "P4.secret-path" {
		t.Fatalf("resolved secret -> %+v, want P4.secret-path", v)
	}
	if !IsPrivateDataAccess(tc, pathPol()) {
		t.Fatal("resolved secret must arm P7 private-data detection")
	}
}

func TestBashSymlinkCandidateRetainsStatementCwd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	repo := t.TempDir()
	subdir := filepath.Join(repo, "subdir")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(subdir, "link")); err != nil {
		t.Fatal(err)
	}
	tc := ToolCall{Tool: "Bash", Command: `cd subdir; cat link`, CWD: repo, RepoRoot: repo}
	v := checkPaths(tc, pathPol())
	if v == nil || v.Decision != policy.Deny || v.RuleID != "P4.symlink-escape" {
		t.Fatalf("-> %+v, want deny/P4.symlink-escape", v)
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

func TestOutsideRepoSymlinkTargets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	repo := t.TempDir()
	outside := t.TempDir()
	secretDir := filepath.Join(outside, ".ssh")
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(secretDir, "id_rsa")
	allowedSecret := filepath.Join(secretDir, ".env.example")
	benign := filepath.Join(outside, "notes.txt")
	for _, target := range []string{secret, allowedSecret, benign} {
		if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	secretAlias := filepath.Join(t.TempDir(), "innocent")
	allowedAlias := filepath.Join(t.TempDir(), "example")
	benignAlias := filepath.Join(t.TempDir(), "notes")
	for alias, target := range map[string]string{
		secretAlias:  secret,
		allowedAlias: allowedSecret,
		benignAlias:  benign,
	} {
		if err := os.Symlink(target, alias); err != nil {
			t.Fatal(err)
		}
	}

	tc := ToolCall{Tool: "Read", Paths: []string{secretAlias}, RepoRoot: repo, CWD: repo}
	if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
		t.Fatalf("Read outside-repo secret alias -> %+v, want deny/P4.secret-path", v)
	}
	for _, alias := range []string{allowedAlias, benignAlias} {
		tc.Paths = []string{alias}
		if v := checkPaths(tc, pathPol()); v != nil {
			t.Errorf("Read benign/allowed outside-repo alias %q -> %+v, want nil", alias, v)
		}
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

func TestOperatorConfigAliasWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	repo := t.TempDir()
	operatorDir := filepath.Join(t.TempDir(), "guardrail")
	if err := os.MkdirAll(operatorDir, 0o700); err != nil {
		t.Fatal(err)
	}
	operatorConfig := filepath.Join(operatorDir, "waivers.toml")
	if err := os.WriteFile(operatorConfig, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "innocent.toml")
	if err := os.Symlink(operatorConfig, alias); err != nil {
		t.Fatal(err)
	}

	write := ToolCall{Tool: "Write", Paths: []string{alias}, RepoRoot: repo, CWD: repo}
	if v := checkPaths(write, pathPol()); v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
		t.Fatalf("Write Operator-config alias -> %+v, want deny/P5.self-config", v)
	}
	for _, command := range []string{
		"cp /tmp/evil " + alias,
		"dd if=/tmp/evil of=" + alias,
		"tee " + alias,
	} {
		tc := ToolCall{Tool: "Bash", Command: command, RepoRoot: repo, CWD: repo}
		if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("Bash %q -> %+v, want deny/P5.self-config", command, v)
		}
	}

	for _, read := range []ToolCall{
		{Tool: "Read", Paths: []string{alias}, RepoRoot: repo, CWD: repo},
		{Tool: "Bash", Command: "cat " + operatorConfig, RepoRoot: repo, CWD: repo},
	} {
		if v := checkPaths(read, pathPol()); v != nil {
			t.Errorf("read Operator config -> %+v, want nil", v)
		}
	}
}

func TestOperatorConfigMissingLeafAliasWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}

	operatorDir := filepath.Join(t.TempDir(), "guardrail")
	if err := os.Mkdir(operatorDir, 0o700); err != nil {
		t.Fatal(err)
	}
	operatorSubdir := filepath.Join(operatorDir, "subdir")
	if err := os.Mkdir(operatorSubdir, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "innocent")
	if err := os.Symlink(operatorDir, alias); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(alias, "waivers.toml")
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("Operator config leaf must not exist before the attempted write: %v", err)
	}
	traversalDir := t.TempDir()
	traversalAlias := filepath.Join(traversalDir, "innocent")
	if err := os.Symlink(operatorSubdir, traversalAlias); err != nil {
		t.Fatal(err)
	}
	separator := string(filepath.Separator)
	traversalTarget := traversalAlias + separator + ".." + separator + "waivers.toml"
	relativeTraversalTarget := "innocent" + separator + ".." + separator + "waivers.toml"
	if _, err := os.Stat(traversalTarget); !os.IsNotExist(err) {
		t.Fatalf("Operator config traversal leaf must not exist before the attempted write: %v", err)
	}

	tests := []struct {
		name string
		call ToolCall
		cwd  string
	}{
		{"native Write", ToolCall{Tool: "Write", Paths: []string{target}}, ""},
		{"native Edit", ToolCall{Tool: "Edit", Paths: []string{target}}, ""},
		{"native MultiEdit", ToolCall{Tool: "MultiEdit", Paths: []string{target}}, ""},
		{"Bash redirect", ToolCall{Tool: "Bash", Command: "printf x > " + target}, ""},
		{"Bash destination", ToolCall{Tool: "Bash", Command: "cp /tmp/evil " + target}, ""},
		{"Bash all args", ToolCall{Tool: "Bash", Command: "tee " + target}, ""},
		{"Bash dd output", ToolCall{Tool: "Bash", Command: "dd if=/tmp/evil of=" + target}, ""},
		{"Bash in-place sed", ToolCall{Tool: "Bash", Command: "sed -i s/x/y/ " + target}, ""},
		{"native symlink parent traversal", ToolCall{Tool: "Write", Paths: []string{traversalTarget}}, ""},
		{"Bash symlink parent traversal", ToolCall{Tool: "Bash", Command: "printf x > " + traversalTarget}, ""},
		{"relative symlink parent traversal", ToolCall{Tool: "Write", Paths: []string{relativeTraversalTarget}}, traversalDir},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			call := test.call
			call.CWD = test.cwd
			if call.CWD == "" {
				call.CWD = t.TempDir()
			}
			v := checkPaths(call, pathPol())
			if v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
				t.Fatalf("-> %+v, want deny/P5.self-config", v)
			}
		})
	}

	benignDir := t.TempDir()
	benignAlias := filepath.Join(t.TempDir(), "innocent")
	if err := os.Symlink(benignDir, benignAlias); err != nil {
		t.Fatal(err)
	}
	benign := ToolCall{Tool: "Write", Paths: []string{filepath.Join(benignAlias, "new.txt")}, CWD: t.TempDir()}
	if v := checkPaths(benign, pathPol()); v != nil {
		t.Fatalf("benign absent child through symlinked parent -> %+v, want nil", v)
	}
}

func TestOperatorConfigOpaqueExecutors(t *testing.T) {
	deny := []string{
		`python3 -c "open('/home/u/.config/guardrail/waivers.toml', 'w')"`,
		`/usr/bin/Python3.12 -c "open('/home/u/guardrail/waivers.toml', 'w')"`,
		`node -e "require('fs').writeFileSync('/home/u/.config/guardrail/waivers.toml', 'x')"`,
		`perl -e "open(F, '>/home/u/guardrail/waivers.toml')"`,
		`ruby3.3 -e "File.write('/home/u/.config/guardrail/waivers.toml', 'x')"`,
		`php8.3 -r "file_put_contents('/home/u/guardrail/waivers.toml', 'x');"`,
		`lua5.4 -e "io.open('/home/u/.config/guardrail/waivers.toml', 'w')"`,
		`awk "BEGIN { print \"x\" > \"/home/u/guardrail/waivers.toml\" }"`,
		`powershell.exe -Command "Set-Content /home/u/.config/guardrail/waivers.toml x"`,
		`pwsh -Command "Set-Content /home/u/guardrail/waivers.toml x"`,
	}
	for _, command := range deny {
		tc := ToolCall{Tool: "Bash", Command: command, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("Bash %q -> %+v, want deny/P5.self-config", command, v)
		}
	}

	allow := []string{
		`python3 -c "print('ok')"`,
		`node -e "console.log('ok')"`,
		`perl -e "print 'ok'"`,
		`pwsh -Command "Write-Output ok"`,
		`python3 -c "p='/' + '.config/' + 'guardrail/'; open(p + 'waivers.toml', 'w')"`,
		`cat /home/u/.config/guardrail/waivers.toml`,
	}
	for _, command := range allow {
		tc := ToolCall{Tool: "Bash", Command: command, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkPaths(tc, pathPol()); v != nil {
			t.Errorf("Bash %q -> %+v, want nil", command, v)
		}
	}
}

func TestOperatorConfigOpaqueEquivalentPaths(t *testing.T) {
	deny := []struct {
		name    string
		command string
	}{
		{"single quoted repeated separators", `python3 -c "open('/home/u/.config//guardrail//waivers.toml', 'w')"`},
		{"double quoted dot segments", `python3 -c 'open("/home/u/.config/./guardrail/./waivers.toml", "w")'`},
		{"backtick quoted cancellable parents", "node -e 'require(\"fs\").writeFileSync(`/home/u/.config/x/../guardrail/y/../waivers.toml`, \"x\")'"},
		{"relative repeated separators", `perl -e "open(F, '>.config//guardrail//waivers.toml')"`},
		{"tilde prefix", `ruby -e "File.write('~/.config//guardrail//waivers.toml', 'x')"`},
		{"home prefix", `php -r 'file_put_contents("$HOME/.config/./guardrail/./waivers.toml", "x");'`},
		{"windows repeated separators", `pwsh -Command 'Set-Content C:\\Users\u\.config\\guardrail\\waivers.toml x'`},
		{"print only visible reference", `python3 -c "print('/home/u/.config/guardrail/waivers.toml')"`},
	}
	for _, test := range deny {
		t.Run(test.name, func(t *testing.T) {
			tc := ToolCall{Tool: "Bash", Command: test.command, RepoRoot: "/repo", CWD: "/repo"}
			if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
				t.Fatalf("Bash %q -> %+v, want deny/P5.self-config", test.command, v)
			}
		})
	}
}

func TestOperatorConfigOpaquePathScannerControls(t *testing.T) {
	allow := []struct {
		name    string
		command string
	}{
		{"benign path", `python3 -c "print('/home/u/.config/other/waivers.toml')"`},
		{"URL text", `node -e "console.log('https://docs.example/.config/guardrail/waivers.toml')"`},
		{"split config directory", `python3 -c "p='/home/u/.config/' + 'guardrail/waivers.toml'; open(p, 'w')"`},
		{"split guardrail directory", `python3 -c "p='/home/u/.config/' + 'guardrail/' + 'waivers.toml'; open(p, 'w')"`},
		{"split dot segment", `python3 -c "p='/home/u/.config/x/' + '../' + 'guardrail/waivers.toml'; open(p, 'w')"`},
		{"direct cat read", `cat /home/u/.config//guardrail/./waivers.toml`},
	}
	for _, test := range allow {
		t.Run(test.name, func(t *testing.T) {
			tc := ToolCall{Tool: "Bash", Command: test.command, RepoRoot: "/repo", CWD: "/repo"}
			if v := checkPaths(tc, pathPol()); v != nil {
				t.Fatalf("Bash %q -> %+v, want nil", test.command, v)
			}
		})
	}
}

func TestOperatorConfigOpaqueQuotedPaths(t *testing.T) {
	deny := []struct {
		name    string
		command string
	}{
		{"single quoted path", `python3 -c "open('/home/u/.config/a b/../guardrail/waivers.toml', 'w')"`},
		{"double quoted path", `python3 -c 'open("/home/u/.config/a b/../guardrail/waivers.toml", "w")'`},
		{"backtick quoted path", "node -e 'require(\"fs\").writeFileSync(`/home/u/.config/a b/../guardrail/waivers.toml`, \"x\")'"},
		{"escaped quote in path", `python3 -c 'open("/home/u/.config/a\" b/../guardrail/waivers.toml", "w")'`},
	}
	for _, test := range deny {
		t.Run(test.name, func(t *testing.T) {
			tc := ToolCall{Tool: "Bash", Command: test.command, RepoRoot: "/repo", CWD: "/repo"}
			if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
				t.Fatalf("Bash %q -> %+v, want deny/P5.self-config", test.command, v)
			}
		})
	}
}

func TestOperatorConfigOpaqueFileURLs(t *testing.T) {
	deny := []struct {
		name    string
		command string
	}{
		{"percent encoded path", `python3 -c "open('file:///home/u/.config/a%20b/../guardrail/waivers.toml', 'w')"`},
		{"localhost path", `node -e "console.log('file://localhost/home/u/.config/%67uardrail/waivers.toml')"`},
		{"Windows drive path", `pwsh -Command "Write-Output file:///C:/Users/u/.config/guardrail/waivers.toml"`},
		{"malformed percent escape", `python3 -c "print('file:///home/u/.config/guardrail/waivers.toml%ZZ')"`},
	}
	for _, test := range deny {
		t.Run(test.name, func(t *testing.T) {
			tc := ToolCall{Tool: "Bash", Command: test.command, RepoRoot: "/repo", CWD: "/repo"}
			if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
				t.Fatalf("Bash %q -> %+v, want deny/P5.self-config", test.command, v)
			}
		})
	}
}

func TestOperatorConfigOpaqueCaseInsensitivePaths(t *testing.T) {
	tc := ToolCall{
		Tool:     "Bash",
		Command:  `pwsh -Command 'Set-Content C:\Users\u\.CONFIG\GuardRail\WAIVERS.TOML x'`,
		RepoRoot: "/repo",
		CWD:      "/repo",
	}
	if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
		t.Fatalf("mixed-case Windows Operator path -> %+v, want deny/P5.self-config", v)
	}
}

func TestOperatorConfigOpaqueRoundTwoControls(t *testing.T) {
	allow := []struct {
		name    string
		command string
	}{
		{"HTTPS path text", `node -e "console.log('https://docs.example/.CONFIG/GuardRail/WAIVERS.TOML')"`},
		{"separate mixed-case fragments", `python3 -c "p='/home/u/.CONFIG/' + 'GuardRail/' + 'WAIVERS.TOML'; open(p, 'w')"`},
	}
	for _, test := range allow {
		t.Run(test.name, func(t *testing.T) {
			tc := ToolCall{Tool: "Bash", Command: test.command, RepoRoot: "/repo", CWD: "/repo"}
			if v := checkPaths(tc, pathPol()); v != nil {
				t.Fatalf("Bash %q -> %+v, want nil", test.command, v)
			}
		})
	}
}

func TestOperatorConfigOpaqueWindowsDrivePaths(t *testing.T) {
	deny := []struct {
		name    string
		command string
	}{
		{"upper drive relative", `pwsh -Command 'Set-Content C:Users/u/.config/guardrail/waivers.toml x'`},
		{"lower drive relative", `pwsh -Command 'Set-Content c:Users/u/.CONFIG/GuardRail/WAIVERS.TOML x'`},
		{"drive absolute slash", `pwsh -Command 'Set-Content C:/Users/u/.config/guardrail/waivers.toml x'`},
		{"drive absolute backslash", `pwsh -Command 'Set-Content c:\Users\u\.config\guardrail\waivers.toml x'`},
		{"drive double slash", `pwsh -Command 'Set-Content c://Users/u/.config/guardrail/waivers.toml x'`},
	}
	for _, test := range deny {
		t.Run(test.name, func(t *testing.T) {
			tc := ToolCall{Tool: "Bash", Command: test.command, RepoRoot: "/repo", CWD: "/repo"}
			if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
				t.Fatalf("Bash %q -> %+v, want deny/P5.self-config", test.command, v)
			}
		})
	}

	tc := ToolCall{
		Tool:     "Bash",
		Command:  `node -e "console.log('https://docs.example/.config/guardrail/waivers.toml')"`,
		RepoRoot: "/repo",
		CWD:      "/repo",
	}
	if v := checkPaths(tc, pathPol()); v != nil {
		t.Fatalf("non-file HTTPS text -> %+v, want nil", v)
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
		for _, command := range []string{"printf x > " + test.path, "> " + test.path} {
			tc := ToolCall{Tool: "Bash", Command: command, RepoRoot: "/repo", CWD: "/repo"}
			v := checkPaths(tc, pathPol())
			if v == nil || v.Decision != policy.Deny || v.RuleID != test.ruleID || v.Reason != test.wantReason {
				t.Errorf("Bash %q -> %+v, want deny/%s with reason %q", command, v, test.ruleID, test.wantReason)
			}
		}
	}
}

func TestCommandLookupRedirectsReachProtectedPathChecks(t *testing.T) {
	for _, command := range []string{
		`command -v git > /repo/CLAUDE.md`,
		`command -V git > /repo/CLAUDE.md`,
		`command > /repo/CLAUDE.md`,
	} {
		tc := ToolCall{Tool: "Bash", Command: command, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("%q -> %+v, want deny/P5.self-config", command, v)
		}
	}
}

func TestInputRedirectsDoNotReachWritePathRules(t *testing.T) {
	for _, command := range []string{
		`< /repo/.git/config`,
		`< /repo/CLAUDE.md`,
		`< /repo/Makefile`,
		"cat <<'/repo/.git/config'\nbody\n/repo/.git/config",
		`cat <<< /repo/CLAUDE.md`,
	} {
		tc := ToolCall{Tool: "Bash", Command: command, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkPaths(tc, pathPol()); v != nil {
			t.Errorf("%q -> %+v, want nil", command, v)
		}
	}
}

func TestRedirectPathsReachSecretChecks(t *testing.T) {
	for _, command := range []string{`> /repo/.env`, `< /repo/.env`, `<> /repo/.env`} {
		tc := ToolCall{Tool: "Bash", Command: command, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
			t.Errorf("%q -> %+v, want deny/P4.secret-path", command, v)
		}
	}
}

func TestRedirectPathsReachSymlinkEscapeChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	repo := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(repo, "redirect-target")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	for _, operator := range []string{">", "<", "<>"} {
		tc := ToolCall{Tool: "Bash", Command: operator + " " + link, RepoRoot: repo, CWD: repo}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P4.symlink-escape" {
			t.Errorf("%q -> %+v, want deny/P4.symlink-escape", tc.Command, v)
		}
	}
}

func TestCompoundRedirectsReachPathChecks(t *testing.T) {
	cases := []struct {
		command string
		ruleID  string
	}{
		{`{ :; } > /repo/CLAUDE.md`, "P5.self-config"},
		{`( :) > /repo/.env`, "P4.secret-path"},
		{`if true; then :; fi < /repo/.env`, "P4.secret-path"},
		{`{ :; } <> /repo/.env`, "P4.secret-path"},
	}
	for _, c := range cases {
		tc := ToolCall{Tool: "Bash", Command: c.command, RepoRoot: "/repo", CWD: "/repo"}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny || v.RuleID != c.ruleID {
			t.Errorf("%q -> %+v, want deny/%s", c.command, v, c.ruleID)
		}
	}
}

func TestCompoundInputRedirectsDoNotReachWritePathRules(t *testing.T) {
	for _, command := range []string{
		`{ :; } < /repo/CLAUDE.md`,
		`( :) < /repo/.git/config`,
		`if true; then :; fi < /repo/Makefile`,
	} {
		tc := ToolCall{Tool: "Bash", Command: command, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkPaths(tc, pathPol()); v != nil {
			t.Errorf("%q -> %+v, want nil", command, v)
		}
	}
}

func TestCompoundRedirectsReachSymlinkEscapeChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	repo := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(repo, "compound-redirect-target")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{`{ :; } > ` + link, `( :) < ` + link} {
		tc := ToolCall{Tool: "Bash", Command: command, RepoRoot: repo, CWD: repo}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P4.symlink-escape" {
			t.Errorf("%q -> %+v, want deny/P4.symlink-escape", command, v)
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

func TestMutatingCommandUniqueLongOptionAbbreviations(t *testing.T) {
	deny := []string{
		`cp --target-d=/home/u/.claude /tmp/settings.json`,
		`mv --target-d=/home/u/.claude /tmp/settings.json`,
		`install --target-d=/home/u/.local/bin /tmp/guardrail`,
		`ln --target-d=/repo/.git/hooks /tmp/pre-commit`,
	}
	for _, command := range deny {
		tc := ToolCall{Tool: "Bash", Command: command, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", command, v)
		}
	}

	allow := []string{
		`cp --suf /repo/.claude /tmp/source /tmp/target`,
		`mv --suf /repo/.claude /tmp/source /tmp/target`,
		`ln --suf /repo/.claude /tmp/source /tmp/target`,
		`install --mod /repo/.claude /tmp/source /tmp/target`,
		`rsync --exclude-f /repo/.claude /tmp/source /tmp/target`,
	}
	for _, command := range allow {
		tc := ToolCall{Tool: "Bash", Command: command, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkSelfConfig(tc); v != nil {
			t.Errorf("%q -> %+v, want nil", command, v)
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
