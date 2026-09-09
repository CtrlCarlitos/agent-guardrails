package engine

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func pathPol() *policy.Policy {
	return &policy.Policy{
		Slots: policy.Slots{
			// Mirrors base.toml: full-path globs, "**/" for any depth, no basename fallback.
			SecretDirs: []string{
				"**/.ssh/**", "**/.aws/**", "**/.config/gcloud/**", "**/.docker/config.json",
				"**/.gnupg/**", "/root/.ssh/**",
			},
			SecretGlobs: []string{
				"**/.env", "**/.env.*",
				"**/.kube/config", "**/.netrc",
				"**/id_rsa*", "**/id_ed25519*", "**/id_ecdsa*", "**/id_dsa*",
				"**/*_rsa", "**/*_ed25519", "**/*_ecdsa", "**/*.private.key",
				"**/*-private-key.*", "**/private*.key", "**/.claude.json",
			},
			SecretAskGlobs: []string{
				"**/*.pem", "**/*.p12", "**/*.pfx", "**/*.keystore", "**/service-account*.json",
			},
			SecretAllow: []string{"**/.env.example", "**/*.pub"},
		},
		Waived: map[string]bool{},
	}
}

func TestSecretDirsAreUnwaivableByFilenameAllow(t *testing.T) {
	pol := pathPol()
	pol.Slots.SecretAllow = append(pol.Slots.SecretAllow, "**/.ssh/**")
	for _, p := range []string{
		"/home/u/.ssh/.env.example", "/home/u/.ssh/.env.sample",
		"/home/u/.aws/.env.example", "/home/u/.ssh/id_rsa.pub",
		"/home/u/.gnupg/.env.example",
	} {
		tc := ToolCall{Tool: "Read", Paths: []string{p}, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", p, v)
		}
	}
	tc := ToolCall{Tool: "Read", Paths: []string{"/repo/.env.example"}, CWD: "/repo", RepoRoot: "/repo"}
	wantAllow(t, "/repo/.env.example", checkPaths(tc, pol))

	pol.Waived["P4.secret-path"] = true
	tc.Paths = []string{"/home/u/.ssh/id_rsa"}
	if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
		t.Errorf("secret dir with P4.secret-path waiver -> %+v, want unconditional deny", v)
	}
}

func TestSecretDirsStayUnwaivableThroughSecretNamedSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	secretDir := filepath.Join(t.TempDir(), ".ssh")
	if err := os.Mkdir(secretDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(secretDir, "id_rsa")
	if err := os.WriteFile(secret, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), ".env")
	if err := os.Symlink(secret, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	pol := pathPol()
	pol.Waived["P4.secret-path"] = true
	tc := ToolCall{Tool: "Read", Paths: []string{alias}, CWD: "/repo", RepoRoot: "/repo"}
	if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
		t.Errorf("waived secret-named alias resolving into secret dir -> %+v, want unconditional deny", v)
	}
}

func TestSecretTiers(t *testing.T) {
	pol := pathPol()
	read := func(p string) *policy.Verdict {
		return checkPaths(ToolCall{Tool: "Read", Paths: []string{p}, CWD: "/repo", RepoRoot: "/repo"}, pol)
	}
	for _, p := range []string{"/repo/i18n/translations.key", "/repo/testdata/id_rsa.pub", "/repo/keys/server.pub"} {
		wantAllow(t, p, read(p))
	}
	for _, p := range []string{"/repo/docs/cert.pem", "/repo/testdata/service-account-fake.json", "/repo/testdata/tls/localhost.pem"} {
		if v := read(p); v == nil || v.Decision != policy.Ask || v.RuleID != "P4.secret-path-ambiguous" {
			t.Errorf("%q -> %+v, want ask/P4.secret-path-ambiguous", p, v)
		}
	}
	for _, p := range []string{
		"/repo/certs/private.key", "/repo/deploy_rsa", "/home/u/.ssh/id_rsa", "/home/u/.ssh/server.pem",
		"/repo/keys/id_rsa_work", "/repo/keys/id_ed25519.old",
		"/home/u/certs/client.pem", "/opt/svc/service-account.json", "~/client.pem",
	} {
		if v := read(p); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", p, v)
		}
	}

	pol.Slots.SecretAllow = append(pol.Slots.SecretAllow, "**/fixtures/*.pem")
	wantAllow(t, "allowed ambiguous fixture", read("/repo/fixtures/client.pem"))
}

func TestStrongestVerdictWinsAcrossCandidates(t *testing.T) {
	pol := pathPol()
	for _, command := range []string{
		`cat /repo/docs/cert.pem /home/u/.ssh/id_rsa`,
		`cat /home/u/.ssh/id_rsa /repo/docs/cert.pem`,
		`cat /repo/README.md /repo/docs/cert.pem /home/u/.ssh/id_rsa`,
	} {
		tc := ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny (strongest across candidates)", command, v)
		}
	}
	tc := ToolCall{Tool: "Bash", Command: `cat /repo/README.md /repo/docs/cert.pem`, CWD: "/repo", RepoRoot: "/repo"}
	if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Ask {
		t.Errorf("ask-only -> %+v, want ask", v)
	}
}

func TestStrongestVerdictAcrossPathRules(t *testing.T) {
	pol := pathPol()
	root := t.TempDir()
	secret := filepath.Join(root, "outside", "id_rsa")
	if err := os.MkdirAll(filepath.Dir(secret), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(filepath.Join(repo, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(repo, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	pem := filepath.Join(repo, "docs", "cert.pem")
	for _, command := range []string{"cat " + pem + " " + link, "cat " + link + " " + pem} {
		tc := ToolCall{Tool: "Bash", Command: command, CWD: repo, RepoRoot: repo}
		if v := checkPaths(tc, pol); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny (symlink escape outranks ambiguous ask)", command, v)
		}
	}

	tc := ToolCall{Tool: "Bash", Command: "cat " + pem + " > " + filepath.Join(repo, "CLAUDE.md"), CWD: repo, RepoRoot: repo}
	if v := Evaluate(tc, pol); v.Decision != policy.Deny {
		t.Errorf("ambiguous read + self-config write -> %+v, want deny", v)
	}

	waivedAsk := *pol
	waivedAsk.Waived = map[string]bool{"P4.secret-path-ambiguous": true}
	tc = ToolCall{Tool: "Bash", Command: "cat " + pem + " " + link, CWD: repo, RepoRoot: repo}
	if v := Evaluate(tc, &waivedAsk); v.Decision != policy.Deny {
		t.Errorf("waived ask + unwaived deny -> %+v, want deny", v)
	}
	tc = ToolCall{Tool: "Bash", Command: "cat " + pem, CWD: repo, RepoRoot: repo}
	if v := Evaluate(tc, &waivedAsk); v.Decision != policy.Allow {
		t.Errorf("waived ask alone -> %+v, want allow", v)
	}

	waivedDeny := *pol
	waivedDeny.Waived = map[string]bool{"P4.secret-path": true}
	for _, command := range []string{
		"cat " + filepath.Join(repo, ".env") + " " + pem,
		"cat " + pem + " " + filepath.Join(repo, ".env"),
	} {
		tc = ToolCall{Tool: "Bash", Command: command, CWD: repo, RepoRoot: repo}
		if v := Evaluate(tc, &waivedDeny); v.Decision != policy.Ask || v.RuleID != "P4.secret-path-ambiguous" {
			t.Errorf("waived deny + unwaived ask %q -> %+v, want ask", command, v)
		}
	}
}

func TestAgentMemoryIsNotAgentConfig(t *testing.T) {
	mem := ToolCall{Tool: "Write", Paths: []string{"/home/u/.claude/projects/x/memory/note.md"}, CWD: "/repo", RepoRoot: "/repo"}
	wantAllow(t, "agent memory", checkSelfConfig(mem))
	for _, p := range []string{
		"/home/u/.claude/settings.json", "/home/u/.claude/settings.local.json", "/home/u/.claude/hooks/pre.sh",
		"/home/u/.claude/plugins/p.js", "/home/u/.claude/agents/a.md", "/home/u/.claude/commands/c.md",
		"/home/u/.claude/skills/s/SKILL.md", "/home/u/.claude/CLAUDE.md", "/repo/.claude/settings.local.json",
	} {
		tc := ToolCall{Tool: "Write", Paths: []string{p}, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkSelfConfig(tc); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", p, v)
		}
	}
}

func TestCheckPathsFileTool(t *testing.T) {
	deny := []string{
		"/home/u/.ssh/id_rsa",
		"/home/u/project/.env",
		"/home/u/project/.env.production",
		"/home/u/.aws/credentials",
		"/home/u/.claude.json",
	}
	for _, p := range deny {
		tc := ToolCall{Tool: "Read", Paths: []string{p}}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("Read %q -> %+v, want deny", p, v)
		}
	}
	ok := []string{"/home/u/project/.env.example", "src/main.go", "README.md", "i18n/translations.key"}
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
	for _, tc := range []ToolCall{
		{Tool: "Bash", Command: `cat ~/.aws/credentials`},
		{Tool: "Bash", Command: `cat.exe id_rsa`, CWD: "/home/u/.ssh", RepoRoot: "/repo"},
	} {
		if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", tc.Command, v)
		}
	}
	tc := ToolCall{Tool: "Bash", Command: `/bin/cat ~/.aws/credentials`}
	if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
		t.Errorf("absolute cat credentials -> %+v, want deny", v)
	}
	tc = ToolCall{Tool: "Bash", Command: `grep -r TODO src/`}
	if v := checkPaths(tc, pathPol()); v != nil {
		t.Errorf("grep src -> %+v, want nil", v)
	}
}

func TestParsedOperandRolesRecoverPathValuesIntact(t *testing.T) {
	for _, test := range []struct {
		name string
		argv []string
		want parsedOperand
	}{
		{"root", []string{"cat", "/"}, parsedOperand{value: "/", role: operandPath}},
		{"parent relative", []string{"grep", "-f../secrets/id_rsa", "x"}, parsedOperand{value: "../secrets/id_rsa", role: operandPath}},
		{"dot relative", []string{"grep", "-f./id_rsa", "x"}, parsedOperand{value: "./id_rsa", role: operandPath}},
		{"tilde relative", []string{"grep", "-f~/.ssh/id_rsa", "x"}, parsedOperand{value: "~/.ssh/id_rsa", role: operandPath}},
		{"hidden relative", []string{"somenewtool", ".ssh/id_rsa"}, parsedOperand{value: ".ssh/id_rsa", role: operandPath}},
		{"Windows separators", []string{"grep", `-fC:\Users\u\.ssh\id_rsa`, "x"}, parsedOperand{value: `C:\Users\u\.ssh\id_rsa`, role: operandPath}},
		{"long attached", []string{"grep", "--file=../secrets/id_rsa", "x"}, parsedOperand{value: "../secrets/id_rsa", role: operandPath}},
		{"flag shaped after terminator", []string{"cat", "--", "--id_rsa"}, parsedOperand{value: "--id_rsa", role: operandPath}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, got := range parseOperandRoles(test.argv).operands {
				if got == test.want {
					return
				}
			}
			t.Fatalf("parseOperandRoles(%q) = %+v, want to contain %+v", test.argv, parseOperandRoles(test.argv).operands, test.want)
		})
	}
}

func TestGenericUnknownOptionsMakeOnlyTheirValuesUncertain(t *testing.T) {
	for _, test := range []struct {
		argv []string
		want []parsedOperand
	}{
		{
			[]string{"base64", "--future", "id_rsa", "/repo/input"},
			[]parsedOperand{{value: "id_rsa", role: operandUncertain}, {value: "/repo/input", role: operandPath}},
		},
		{
			[]string{"base64", "--future=id_rsa", "/repo/input"},
			[]parsedOperand{{value: "id_rsa", role: operandUncertain}, {value: "/repo/input", role: operandPath}},
		},
		{
			[]string{"somenewtool", "--", "--id_rsa"},
			[]parsedOperand{{value: "--id_rsa", role: operandNonPath}},
		},
	} {
		if got := parseOperandRoles(test.argv).operands; !reflect.DeepEqual(got, test.want) {
			t.Errorf("parseOperandRoles(%q) = %+v, want %+v", test.argv, got, test.want)
		}
	}

	tc := ToolCall{Tool: "Bash", Command: `somenewtool --future id_rsa`, CWD: "/home/u/.ssh", RepoRoot: "/repo"}
	if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
		t.Errorf("unknown option's uncertain bare value -> %+v, want deny", v)
	}
}

func TestGrepAndSedParsedOperandRoles(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want []parsedOperand
	}{
		{
			"grep positional pattern",
			[]string{"grep", "*.pem", "/repo/build.log"},
			[]parsedOperand{{value: "*.pem", role: operandNonPath}, {value: "/repo/build.log", role: operandPath}},
		},
		{
			"grep late abbreviated regexp",
			[]string{"grep", "/repo/build.log", "--reg=*.pem"},
			[]parsedOperand{{value: "/repo/build.log", role: operandPath}, {value: "*.pem", role: operandNonPath}},
		},
		{
			"grep context does not shift pattern",
			[]string{"grep", "--after-c", "2", "id_rsa", "/repo/log"},
			[]parsedOperand{{value: "2", role: operandNonPath}, {value: "id_rsa", role: operandNonPath}, {value: "/repo/log", role: operandPath}},
		},
		{
			"grep pattern and file after terminator",
			[]string{"grep", "--", "--id_rsa", "/home/u/.ssh/id_rsa"},
			[]parsedOperand{{value: "--id_rsa", role: operandNonPath}, {value: "/home/u/.ssh/id_rsa", role: operandPath}},
		},
		{
			"grep pattern file makes first positional an input",
			[]string{"grep", "-f", "/repo/patterns", "/home/u/.ssh/id_rsa"},
			[]parsedOperand{{value: "/repo/patterns", role: operandPath}, {value: "/home/u/.ssh/id_rsa", role: operandPath}},
		},
		{
			"unknown short owns only its uncertain value",
			[]string{"grep", "-Q", "id_rsa", "*.pem", "/repo/log"},
			[]parsedOperand{{value: "id_rsa", role: operandUncertain}, {value: "*.pem", role: operandNonPath}, {value: "/repo/log", role: operandPath}},
		},
		{
			"unknown long owns only its uncertain value",
			[]string{"grep", "--future", "id_rsa", "*.pem", "/repo/log"},
			[]parsedOperand{{value: "id_rsa", role: operandUncertain}, {value: "*.pem", role: operandNonPath}, {value: "/repo/log", role: operandPath}},
		},
		{
			"sed late abbreviated expression",
			[]string{"sed", "/repo/a.txt", "--exp=s/.env/.cfg/"},
			[]parsedOperand{{value: "/repo/a.txt", role: operandPath}, {value: "s/.env/.cfg/", role: operandNonPath}},
		},
		{
			"sed line length does not shift script",
			[]string{"sed", "-l", "80", "s/.env/.cfg/", "/repo/a.txt"},
			[]parsedOperand{{value: "80", role: operandNonPath}, {value: "s/.env/.cfg/", role: operandNonPath}, {value: "/repo/a.txt", role: operandPath}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := parseOperandRoles(test.argv).operands; !reflect.DeepEqual(got, test.want) {
				t.Fatalf("parseOperandRoles(%q) = %+v, want %+v", test.argv, got, test.want)
			}
		})
	}
}

func TestSecretReadsViaCommandOperands(t *testing.T) {
	for _, command := range []string{
		`cp /home/u/.ssh/id_rsa /tmp/x`,
		`mv /home/u/.ssh/id_rsa /tmp/x`,
		`base64 /home/u/.aws/credentials`,
		`tar cf - /home/u/.ssh/id_rsa`,
		`openssl rsa -in /home/u/.ssh/id_rsa`,
		`md5sum /home/u/.ssh/id_rsa`,
		`dd if=/home/u/.ssh/id_rsa`,
		`grep -f/home/u/.ssh/id_rsa x`,
		`grep -f../.ssh/id_rsa x`,
		`somenewtool /home/u/.ssh/id_rsa`,
	} {
		tc := ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", command, v)
		}
	}
}

func TestBareFilenameReaderHintsAndUnlistedResidue(t *testing.T) {
	for _, command := range []string{`cat id_rsa`, `head -n1 id_rsa`, `base64 id_rsa`, `cp id_rsa /tmp/x`} {
		tc := ToolCall{Tool: "Bash", Command: command, CWD: "/home/u/.ssh", RepoRoot: "/repo"}
		if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", command, v)
		}
	}

	tc := ToolCall{Tool: "Bash", Command: `somenewtool id_rsa`, CWD: "/home/u/.ssh", RepoRoot: "/repo"}
	wantAllow(t, "unlisted bare-name residue", checkPaths(tc, pathPol()))
}

func TestGrepAndSedProgramsAreNotPathCandidates(t *testing.T) {
	for _, command := range []string{
		`grep '*.pem' /repo/build.log`,
		`grep -r id_rsa /repo/src`,
		`grep -e '*.pem' /repo/build.log`,
		`grep /repo/build.log -e '*.pem'`,
		`grep --regexp='*.pem' /repo/build.log`,
		`grep --reg='*.pem' /repo/build.log`,
		`grep -A 2 id_rsa /repo/src`,
		`sed 's/.env/.cfg/' /repo/a.txt`,
		`sed /repo/a.txt -e 's/.env/.cfg/'`,
		`sed /repo/a.txt --exp='s/.env/.cfg/'`,
		`sed -l 80 's/.env/.cfg/' /repo/a.txt`,
	} {
		tc := ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}
		wantAllow(t, command, checkPaths(tc, pathPol()))
	}

	for _, command := range []string{
		`grep -f /home/u/.ssh/id_rsa /repo/log`,
		`grep --file=/home/u/.ssh/id_rsa /repo/log`,
		`grep -f /repo/patterns /home/u/.ssh/id_rsa`,
		`sed -f/home/u/.ssh/id_rsa /repo/a.txt`,
		`sed --file /home/u/.ssh/id_rsa /repo/a.txt`,
		`grep -- id_rsa /home/u/.ssh/id_rsa`,
	} {
		tc := ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", command, v)
		}
	}
}

func TestSedInPlaceUsesParsedFileRoles(t *testing.T) {
	for _, test := range []struct {
		command string
		ruleID  string
	}{
		{`sed -i /repo/.git/config -e s/x/y/`, "P2.git-protected-path"},
		{`sed --in-p /repo/CLAUDE.md --exp=s/x/y/`, "P5.self-config"},
	} {
		tc := ToolCall{Tool: "Bash", Command: test.command, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny || v.RuleID != test.ruleID {
			t.Errorf("%q -> %+v, want deny/%s", test.command, v, test.ruleID)
		}
	}
}

func TestSedInPlaceDoesNotWriteItsScriptFile(t *testing.T) {
	simple := Simple{Argv: []string{"sed", "-i", "-f", "/repo/.git/config", "/repo/a.txt"}}
	want := []string{"/repo/a.txt"}
	if got := writeTargets(simple); !reflect.DeepEqual(got, want) {
		t.Fatalf("writeTargets(%q) = %q, want %q", simple.Argv, got, want)
	}
}

func TestJQParsedOperandRoles(t *testing.T) {
	for _, test := range []struct {
		name string
		argv []string
		want []parsedOperand
	}{
		{
			"named literals and input",
			[]string{"jq", "--arg", "key", ".env", ".[$key]", "/repo/x.json"},
			[]parsedOperand{{value: "key", role: operandNonPath}, {value: ".env", role: operandNonPath}, {value: ".[$key]", role: operandNonPath}, {value: "/repo/x.json", role: operandPath}},
		},
		{
			"named file",
			[]string{"jq", "--rawfile", "key", "/home/u/.ssh/id_rsa", ".", "/repo/x.json"},
			[]parsedOperand{{value: "key", role: operandNonPath}, {value: "/home/u/.ssh/id_rsa", role: operandPath}, {value: ".", role: operandNonPath}, {value: "/repo/x.json", role: operandPath}},
		},
		{
			"filter file",
			[]string{"jq", "-f/home/u/.ssh/id_rsa", "/repo/x.json"},
			[]parsedOperand{{value: "/home/u/.ssh/id_rsa", role: operandPath}, {value: "/repo/x.json", role: operandPath}},
		},
		{
			"unknown value does not become filter",
			[]string{"jq", "--future", "id_rsa", ".", "/repo/x.json"},
			[]parsedOperand{{value: "id_rsa", role: operandUncertain}, {value: ".", role: operandNonPath}, {value: "/repo/x.json", role: operandPath}},
		},
		{
			"terminator preserves flag shaped input",
			[]string{"jq", "--", ".", "--id_rsa"},
			[]parsedOperand{{value: ".", role: operandNonPath}, {value: "--id_rsa", role: operandPath}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := parseOperandRoles(test.argv).operands; !reflect.DeepEqual(got, test.want) {
				t.Fatalf("parseOperandRoles(%q) = %+v, want %+v", test.argv, got, test.want)
			}
		})
	}
}

func TestJQReadOperandSemantics(t *testing.T) {
	allow := []string{
		`jq '.env' /repo/pkg.json`,
		`jq '.ssh.keys[]' /repo/cfg.json`,
		`jq --arg k '.env' '.[$k]' /repo/x.json`,
		`jq --argjson k '{"id_rsa":1}' '.' /repo/x.json`,
		`jq -n '.' /home/u/.ssh/id_rsa`,
		`jq --null-input '.' /home/u/.ssh/id_rsa`,
		`jq --args '.' /home/u/.ssh/id_rsa`,
		`jq --jsonargs '.' /home/u/.ssh/id_rsa`,
	}
	for _, command := range allow {
		tc := ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}
		wantAllow(t, command, checkPaths(tc, pathPol()))
	}

	deny := []string{
		`jq . ~/.claude.json`,
		`jq -f /home/u/.ssh/id_rsa /repo/x.json`,
		`jq -L/home/u/.ssh /repo/x.json`,
		`jq --rawfile k /home/u/.ssh/id_rsa '.' /repo/x.json`,
		`jq --slurpfile k /home/u/.ssh/id_rsa '.' /repo/x.json`,
		`jq --run-tests /home/u/.ssh/id_rsa`,
		`jq -- '.' --id_rsa`,
	}
	for _, command := range deny {
		cwd := "/repo"
		if strings.Contains(command, "--id_rsa") {
			cwd = "/home/u/.ssh"
		}
		tc := ToolCall{Tool: "Bash", Command: command, CWD: cwd, RepoRoot: "/repo"}
		if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", command, v)
		}
	}
}

func TestEvaluateJQLiteralTailOptionsApplyOnlyToFollowingArguments(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    policy.Decision
	}{
		{"late args preserves earlier input", `jq . /home/u/.ssh/id_rsa --args foo`, policy.Deny},
		{"late jsonargs preserves earlier input", `jq . /home/u/.ssh/id_rsa --jsonargs '1'`, policy.Deny},
		{"leading args makes following argument literal", `jq --args . /home/u/.ssh/id_rsa`, policy.Allow},
		{"leading jsonargs makes following argument literal", `jq --jsonargs . /home/u/.ssh/id_rsa`, policy.Allow},
	} {
		t.Run(test.name, func(t *testing.T) {
			tc := ToolCall{Tool: "Bash", Command: test.command, CWD: "/repo", RepoRoot: "/repo"}
			if v := Evaluate(tc, pathPol()); v.Decision != test.want {
				t.Fatalf("Evaluate(%q) = %+v, want %s", test.command, v, test.want)
			}
		})
	}
}

func TestEvaluateJQFilterFileComposesWithInputModes(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    policy.Decision
	}{
		{"args makes filter-file positional literal", `printf . | jq -f /dev/stdin --args /home/u/.ssh/id_rsa`, policy.Allow},
		{"jsonargs makes filter-file positional literal", `printf . | jq -f /dev/stdin --jsonargs /home/u/.ssh/id_rsa`, policy.Allow},
		{"null input suppresses filter-file input", `printf . | jq -f /dev/stdin -n /home/u/.ssh/id_rsa`, policy.Allow},
		{"ordinary filter file scans input", `jq -f /repo/filter.jq /home/u/.ssh/id_rsa`, policy.Deny},
		{"run tests scans test file", `jq --run-tests /home/u/.ssh/id_rsa`, policy.Deny},
	} {
		t.Run(test.name, func(t *testing.T) {
			tc := ToolCall{Tool: "Bash", Command: test.command, CWD: "/repo", RepoRoot: "/repo"}
			if v := Evaluate(tc, pathPol()); v.Decision != test.want {
				t.Fatalf("Evaluate(%q) = %+v, want %s", test.command, v, test.want)
			}
		})
	}
}

func TestEvaluateJQRunTestsTreatsTailAsTestArguments(t *testing.T) {
	tc := ToolCall{
		Tool:     "Bash",
		Command:  `jq --run-tests --indent /tmp/jq-tests/.ssh/id_rsa`,
		CWD:      "/repo",
		RepoRoot: "/repo",
	}
	if v := Evaluate(tc, pathPol()); v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
		t.Fatalf("Evaluate(%q) = %+v, want deny/P4.secret-path", tc.Command, v)
	}
}

func TestEvaluateJQRunTestsRetainsRunnerOptions(t *testing.T) {
	for _, option := range []string{"--skip", "--take"} {
		t.Run(option, func(t *testing.T) {
			command := `jq --run-tests ` + option + ` /home/u/.ssh/id_rsa /repo/tests`
			tc := ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}
			if v := Evaluate(tc, pathPol()); v.Decision != policy.Allow || v.RuleID != "" {
				t.Fatalf("Evaluate(%q) = %+v, want allow", command, v)
			}
		})
	}
}

func TestEvaluateJQOptionInterposedFilterFileAsks(t *testing.T) {
	const (
		ruleID = "P4.path-parse-uncertain"
		reason = "jq operand roles are ambiguous because a filter-file value is interposed by an option"
	)
	for _, command := range []string{
		`printf . | jq -f --args /dev/stdin /home/u/.ssh/id_rsa`,
		`printf . | jq -f --jsonargs /dev/stdin /home/u/.ssh/id_rsa`,
		`printf . | jq -f -n /dev/stdin /home/u/.ssh/id_rsa`,
	} {
		t.Run(command, func(t *testing.T) {
			tc := ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}
			if v := Evaluate(tc, pathPol()); v.Decision != policy.Ask || v.RuleID != ruleID || v.Reason != reason {
				t.Fatalf("Evaluate(%q) = %+v, want ask/%s with reason %q", command, v, ruleID, reason)
			}
		})
	}
}

func TestEvaluateJQKnownFilterFileFormsRemainPrecise(t *testing.T) {
	for _, test := range []struct {
		name     string
		command  string
		decision policy.Decision
		ruleID   string
	}{
		{"args after filter file", `printf . | jq -f /dev/stdin --args /home/u/.ssh/id_rsa`, policy.Allow, ""},
		{"jsonargs after filter file", `printf . | jq -f /dev/stdin --jsonargs /home/u/.ssh/id_rsa`, policy.Allow, ""},
		{"null input after filter file", `printf . | jq -f /dev/stdin -n /home/u/.ssh/id_rsa`, policy.Allow, ""},
		{"ordinary filter file input", `jq -f /repo/filter.jq /home/u/.ssh/id_rsa`, policy.Deny, "P4.secret-path"},
		{"direct run tests", `jq --run-tests /home/u/.ssh/id_rsa`, policy.Deny, "P4.secret-path"},
	} {
		t.Run(test.name, func(t *testing.T) {
			tc := ToolCall{Tool: "Bash", Command: test.command, CWD: "/repo", RepoRoot: "/repo"}
			if v := Evaluate(tc, pathPol()); v.Decision != test.decision || v.RuleID != test.ruleID {
				t.Fatalf("Evaluate(%q) = %+v, want %s/%s", test.command, v, test.decision, test.ruleID)
			}
		})
	}
}

func TestEvaluateJQParseUncertaintyUsesStrongestUnwaivedVerdict(t *testing.T) {
	const ruleID = "P4.path-parse-uncertain"
	tc := ToolCall{
		Tool:     "Bash",
		Command:  `printf . | jq --rawfile key /home/u/.ssh/id_rsa -f --args /dev/stdin /repo/value`,
		CWD:      "/repo",
		RepoRoot: "/repo",
	}
	if v := Evaluate(tc, pathPol()); v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
		t.Fatalf("definite secret path plus parse uncertainty = %+v, want deny/P4.secret-path", v)
	}

	p := pathPol()
	p.Waived[ruleID] = true
	tc.Command = `printf . | jq -f --args /dev/stdin /home/u/.ssh/id_rsa`
	if v := Evaluate(tc, p); v.Decision != policy.Allow || v.RuleID != "" {
		t.Fatalf("waived jq parse uncertainty = %+v, want allow", v)
	}
}

func TestEvaluateJQYQUnknownOptionsAsk(t *testing.T) {
	const ruleID = "P4.path-parse-uncertain"
	for _, test := range []struct {
		name    string
		command string
		reason  string
	}{
		{"jq", `jq --future id_rsa '.' /repo/x.json`, "jq operand roles are ambiguous because an option is unknown"},
		{"yq", `yq --future id_rsa --expression '.' /repo/x.yml`, "yq operand roles are ambiguous because an option is unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			tc := ToolCall{Tool: "Bash", Command: test.command, CWD: "/home/u/.ssh", RepoRoot: "/repo"}
			if v := Evaluate(tc, pathPol()); v.Decision != policy.Ask || v.RuleID != ruleID || v.Reason != test.reason {
				t.Fatalf("Evaluate(%q) = %+v, want ask/%s with reason %q", test.command, v, ruleID, test.reason)
			}
		})
	}
}

func TestEvaluateOrdinaryJQYQInvocationsDoNotAsk(t *testing.T) {
	for _, command := range []string{
		`jq '.' /repo/x.json`,
		`yq '.' /repo/x.yml`,
		`yq --expression '.' /repo/x.yml`,
	} {
		t.Run(command, func(t *testing.T) {
			tc := ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}
			if v := Evaluate(tc, pathPol()); v.Decision != policy.Allow || v.RuleID != "" {
				t.Fatalf("Evaluate(%q) = %+v, want allow", command, v)
			}
		})
	}
}

func TestYQParsedOperandRoles(t *testing.T) {
	for _, test := range []struct {
		name string
		argv []string
		want []parsedOperand
	}{
		{
			"front matter is not a path",
			[]string{"yq", "-f", "process", "id_rsa"},
			[]parsedOperand{{value: "process", role: operandNonPath}, {value: "id_rsa", role: operandUncertain}},
		},
		{
			"forced expression",
			[]string{"yq", "--expression", ".env", "/repo/x.yml"},
			[]parsedOperand{{value: ".env", role: operandNonPath}, {value: "/repo/x.yml", role: operandPath}},
		},
		{
			"expression file",
			[]string{"yq", "--from-file=/home/u/.ssh/id_rsa", "/repo/x.yml"},
			[]parsedOperand{{value: "/home/u/.ssh/id_rsa", role: operandPath}, {value: "/repo/x.yml", role: operandPath}},
		},
		{
			"split expression and file",
			[]string{"yq", "-s/home/u/.ssh/id_rsa", "--split-exp-file", "/home/u/.aws/credentials", ".", "/repo/x.yml"},
			[]parsedOperand{{value: "/home/u/.ssh/id_rsa", role: operandNonPath}, {value: "/home/u/.aws/credentials", role: operandPath}, {value: ".", role: operandUncertain}, {value: "/repo/x.yml", role: operandPath}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := parseOperandRoles(test.argv).operands; !reflect.DeepEqual(got, test.want) {
				t.Fatalf("parseOperandRoles(%q) = %+v, want %+v", test.argv, got, test.want)
			}
		})
	}
}

func TestYQReadOperandSemantics(t *testing.T) {
	for _, command := range []string{
		`yq -f /home/u/.ssh/id_rsa --expression '.' /repo/x.yml`,
		`yq --front-matter=extract --expression '.env' /repo/x.yml`,
		`yq -s '/home/u/.ssh/id_rsa' --expression '.' /repo/x.yml`,
	} {
		tc := ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}
		wantAllow(t, command, checkPaths(tc, pathPol()))
	}

	for _, test := range []struct {
		command string
		cwd     string
	}{
		{`yq -f process id_rsa`, "/home/u/.ssh"},
		{`yq --front-matter extract id_rsa`, "/home/u/.ssh"},
		{`yq --from-file /home/u/.ssh/id_rsa /repo/x.yml`, "/repo"},
		{`yq --split-exp-file=/home/u/.ssh/id_rsa '.' /repo/x.yml`, "/repo"},
	} {
		tc := ToolCall{Tool: "Bash", Command: test.command, CWD: test.cwd, RepoRoot: "/repo"}
		if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", test.command, v)
		}
	}
}

func TestAWKParsedOperandRoles(t *testing.T) {
	for _, test := range []struct {
		name string
		argv []string
		want []parsedOperand
	}{
		{
			"field separator assignment and program",
			[]string{"awk", "-F:", "-v", "key=/home/u/.ssh/id_rsa", "/id_rsa/", "/repo/log"},
			[]parsedOperand{{value: ":", role: operandNonPath}, {value: "key=/home/u/.ssh/id_rsa", role: operandNonPath}, {value: "/id_rsa/", role: operandNonPath}, {value: "/repo/log", role: operandPath}},
		},
		{
			"program and loader files",
			[]string{"awk", "-f/home/u/.ssh/id_rsa", "-i", "/home/u/.aws/credentials", "/repo/log"},
			[]parsedOperand{{value: "/home/u/.ssh/id_rsa", role: operandPath}, {value: "/home/u/.aws/credentials", role: operandPath}, {value: "/repo/log", role: operandPath}},
		},
		{
			"late source makes prior positional a file",
			[]string{"awk", "/repo/log", "--source", "/id_rsa/"},
			[]parsedOperand{{value: "/repo/log", role: operandPath}, {value: "/id_rsa/", role: operandNonPath}},
		},
		{
			"assignment does not become program",
			[]string{"awk", "key=/home/u/.ssh/id_rsa", "/id_rsa/", "/repo/log"},
			[]parsedOperand{{value: "key=/home/u/.ssh/id_rsa", role: operandNonPath}, {value: "/id_rsa/", role: operandNonPath}, {value: "/repo/log", role: operandPath}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := parseOperandRoles(test.argv).operands; !reflect.DeepEqual(got, test.want) {
				t.Fatalf("parseOperandRoles(%q) = %+v, want %+v", test.argv, got, test.want)
			}
		})
	}
}

func TestAWKReadOperandSemantics(t *testing.T) {
	for _, command := range []string{
		`awk -F: '/id_rsa/' /repo/passwd.txt`,
		`awk -v key=/home/u/.ssh/id_rsa '/id_rsa/' /repo/log`,
		`awk key=/home/u/.ssh/id_rsa '/id_rsa/' /repo/log`,
		`awk --source 'BEGIN { print "/home/u/.ssh/id_rsa" }' /repo/log`,
		`awk -- '/id_rsa/' /repo/log`,
	} {
		tc := ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}
		wantAllow(t, command, checkPaths(tc, pathPol()))
	}

	for _, command := range []string{
		`awk -f /home/u/.ssh/id_rsa /repo/log`,
		`awk -E/home/u/.ssh/id_rsa /repo/log`,
		`awk -i /home/u/.ssh/id_rsa '/ok/' /repo/log`,
		`awk -l/home/u/.ssh/id_rsa '/ok/' /repo/log`,
		`awk '/ok/' /home/u/.ssh/id_rsa`,
		`awk /home/u/.ssh/id_rsa --source '{print}'`,
	} {
		tc := ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", command, v)
		}
	}
}

func TestTarParsedOperandRolesKeepPerOperandCertainty(t *testing.T) {
	argv := []string{
		"tar", "--future", "id_rsa", "--exclude", "/home/u/.ssh/id_rsa",
		"--exclude-from=/home/u/.aws/credentials", "-zjJav", "-X../patterns", "/repo/src",
	}
	want := []parsedOperand{
		{value: "id_rsa", role: operandUncertain},
		{value: "/home/u/.ssh/id_rsa", role: operandNonPath},
		{value: "/home/u/.aws/credentials", role: operandPath},
		{value: "../patterns", role: operandPath},
		{value: "/repo/src", role: operandPath},
	}
	if got := parseOperandRoles(argv).operands; !reflect.DeepEqual(got, want) {
		t.Fatalf("parseOperandRoles(%q) = %+v, want %+v", argv, got, want)
	}
}

func TestTarReadOperandSemantics(t *testing.T) {
	for _, command := range []string{
		`tar --exclude /home/u/.ssh/id_rsa -z -j -J -a -v -cf /tmp/a.tar /repo/src`,
		`tar --exclude=/home/u/.ssh/id_rsa --gzip --bzip2 --xz --auto-compress --verbose -cf /tmp/a.tar /repo/src`,
		`tar --future value --exclude /home/u/.ssh/id_rsa /repo/src`,
		`tar --future --exclude /home/u/.ssh/id_rsa /repo/src`,
	} {
		tc := ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}
		wantAllow(t, command, checkPaths(tc, pathPol()))
	}

	for _, test := range []struct {
		command string
		cwd     string
	}{
		{`tar --exclude-from /home/u/.ssh/id_rsa -cf /tmp/a.tar /repo/src`, "/repo"},
		{`tar --exclude-from=/home/u/.ssh/id_rsa -cf /tmp/a.tar /repo/src`, "/repo"},
		{`tar -X/home/u/.ssh/id_rsa -cf /tmp/a.tar /repo/src`, "/repo"},
		{`tar --future id_rsa --exclude /repo/secret -cf /tmp/a.tar /repo/src`, "/home/u/.ssh"},
	} {
		tc := ToolCall{Tool: "Bash", Command: test.command, CWD: test.cwd, RepoRoot: "/repo"}
		if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", test.command, v)
		}
	}
}

func TestDDInputOperandIsAnExactPath(t *testing.T) {
	want := []parsedOperand{
		{value: "/home/u/.ssh/id_rsa", role: operandPath},
		{value: "/tmp/output", role: operandNonPath},
		{value: "direct", role: operandNonPath},
	}
	argv := []string{"dd", "if=/home/u/.ssh/id_rsa", "of=/tmp/output", "iflag=direct"}
	if got := parseOperandRoles(argv).operands; !reflect.DeepEqual(got, want) {
		t.Fatalf("parseOperandRoles(%q) = %+v, want %+v", argv, got, want)
	}
}

func TestDDInputFollowsSymlinks(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "outside", "id_rsa")
	if err := os.MkdirAll(filepath.Dir(secret), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(repo, "innocent.bin")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	tc := ToolCall{Tool: "Bash", Command: "dd if=" + link + " of=/tmp/x", CWD: repo, RepoRoot: repo}
	if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
		t.Errorf("dd if=<symlink to secret> -> %+v, want deny", v)
	}
}

func TestOpaqueSourceBoundary(t *testing.T) {
	for _, command := range []string{
		`python3 -c "print(open('/home/u/.ssh/id_rsa').read())"`,
		`python3 -c "print('/home/u/.ssh/id_rsa')"`,
		`node -e "require('fs').readFileSync('/home/u/.ssh/id_rsa')"`,
	} {
		tc := ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}
		if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", command, v)
		}
	}

	tc := ToolCall{Tool: "Bash", Command: `python3 -c "print('/repo/docs/cert.pem')"`, CWD: "/repo", RepoRoot: "/repo"}
	if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Ask {
		t.Errorf("ambiguous path in source -> %+v, want ask", v)
	}
	tc.Command = `python3 -c "print('hello world')"`
	wantAllow(t, "ordinary source", checkPaths(tc, pathPol()))
	tc.Command = `awk 'BEGIN { print "/home/u/.ssh/id_rsa" }' /repo/log`
	wantAllow(t, "awk program is not opaque source", checkPaths(tc, pathPol()))
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

	tc := ToolCall{Tool: "Read", RepoRoot: repo, CWD: repo}
	for _, alias := range []string{secretAlias, allowedAlias} {
		tc.Paths = []string{alias}
		if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
			t.Errorf("Read outside-repo secret alias %q -> %+v, want deny/P4.secret-path", alias, v)
		}
	}
	tc.Paths = []string{benignAlias}
	if v := checkPaths(tc, pathPol()); v != nil {
		t.Errorf("Read benign outside-repo alias %q -> %+v, want nil", benignAlias, v)
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

func TestSessionStoreDeletionDenied(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		command string
	}{
		{"linux", "/home/u/.local/state/guardrail/sessions/key.json", `rm /home/u/.local/state/guardrail/sessions/key.json`},
		{"xdg", "/var/user-state/guardrail/sessions/key.json", `rm /var/user-state/guardrail/sessions/key.json`},
		{"macos", "/Users/u/Library/Application Support/guardrail/sessions/key.json", `rm "/Users/u/Library/Application Support/guardrail/sessions/key.json"`},
		{"windows", `C:\Users\u\AppData\Local\guardrail\sessions\key.json`, `rm "C:\Users\u\AppData\Local\guardrail\sessions\key.json"`},
		{"transaction lock", "/home/u/.local/state/guardrail/sessions/.lock", `rm /home/u/.local/state/guardrail/sessions/.lock`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, tc := range []ToolCall{
				{Tool: "Write", Paths: []string{test.path}, RepoRoot: "/repo", CWD: "/repo"},
				{Tool: "Bash", Command: test.command, RepoRoot: "/repo", CWD: "/repo"},
			} {
				v := checkPaths(tc, pathPol())
				if v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
					t.Errorf("%s session state %q -> %+v, want deny/P5.self-config", tc.Tool, test.path, v)
				}
			}
		})
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

func nf17SetHome(t *testing.T, home string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
		return
	}
	t.Setenv("HOME", home)
}

func nf17NonTempHome(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, ".nf17-home", strings.ReplaceAll(t.Name(), "/", "-"))
}

// Mutation caught: omitting Base temp roots from native file-tool authorization makes scratch writes ask.
func TestNF17FileToolsAuthorizeStrictSystemTempDescendants(t *testing.T) {
	tmpdir := t.TempDir()
	t.Setenv("TMPDIR", tmpdir)
	target := filepath.Join(tmpdir, "session", "scratchpad", "note.md")
	for _, plane := range []string{"claude", "opencode", "antigravity", ""} {
		for _, tool := range []string{"Write", "Edit", "MultiEdit"} {
			t.Run(plane+"/"+tool, func(t *testing.T) {
				call := ToolCall{Plane: plane, Tool: tool, Paths: []string{target}, CWD: "/repo", RepoRoot: "/repo"}
				if v := Evaluate(call, pathPol()); v.Decision != policy.Allow || v.RuleID != "" {
					t.Fatalf("Evaluate(%s %s %q) = %+v, want allow", plane, tool, target, v)
				}
			})
		}
	}
}

// Mutation caught: treating temp roots as ordinary prefix roots authorizes equality, traversal, and symlink escapes.
func TestNF17FileToolTempAuthorizationKeepsStrictPhysicalBoundary(t *testing.T) {
	tmpdir := t.TempDir()
	t.Setenv("TMPDIR", tmpdir)
	escape := filepath.Join(tmpdir, "escape")
	if err := os.Symlink("/etc", escape); err != nil {
		t.Skipf("create symlink escape: %v", err)
	}
	tests := []struct {
		name string
		path string
	}{
		{"temp root equality", tmpdir},
		{"adjacent prefix", "/tmpish/note.md"},
		{"cleaned parent escape", tmpdir + string(filepath.Separator) + ".." + string(filepath.Separator) + ".." + string(filepath.Separator) + ".." + string(filepath.Separator) + "etc" + string(filepath.Separator) + "nf17-note.md"},
		{"existing symlink escape", filepath.Join(escape, "nf17-note.md")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			call := ToolCall{Tool: "Write", Paths: []string{test.path}, CWD: "/repo", RepoRoot: "/repo"}
			v := Evaluate(call, pathPol())
			if v.Decision != policy.Ask || v.RuleID != "P5.out-of-repo" {
				t.Fatalf("Evaluate(Write %q) = %+v, want ask/P5.out-of-repo", test.path, v)
			}
		})
	}
}

// Mutation caught: omitting the exact actual-home memory root makes routine plane memory writes ask.
func TestNF17ActualHomeClaudeMemoryAllowsApprovedOperations(t *testing.T) {
	home := nf17NonTempHome(t)
	nf17SetHome(t, home)
	target := filepath.Join(home, ".claude", "projects", "project-key", "memory", "notes", "note.md")
	tests := []ToolCall{
		{Plane: "claude", Tool: "Write", Paths: []string{target}, CWD: "/repo", RepoRoot: "/repo"},
		{Plane: "claude", Tool: "Edit", Paths: []string{target}, CWD: "/repo", RepoRoot: "/repo"},
		{Plane: "claude", Tool: "MultiEdit", Paths: []string{target}, CWD: "/repo", RepoRoot: "/repo"},
		{Plane: "claude", Tool: "Bash", Command: "printf x > " + target, CWD: "/repo", RepoRoot: "/repo"},
		{Plane: "claude", Tool: "Bash", Command: "rm -rf " + target, CWD: "/repo", RepoRoot: "/repo"},
	}
	for _, call := range tests {
		if v := Evaluate(call, pathPol()); v.Decision != policy.Allow || v.RuleID != "" {
			t.Errorf("Evaluate(%s %q) = %+v, want allow", call.Tool, target, v)
		}
	}
}

// Mutation caught: authorizing the memory directory itself permits replacing or deleting the bounded root.
func TestNF17ClaudeMemoryRootRemainsProtected(t *testing.T) {
	home := nf17NonTempHome(t)
	nf17SetHome(t, home)
	root := filepath.Join(home, ".claude", "projects", "project-key", "memory")
	tests := []struct {
		name     string
		call     ToolCall
		decision policy.Decision
		ruleID   string
	}{
		{"Write", ToolCall{Plane: "claude", Tool: "Write", Paths: []string{root}, CWD: "/repo", RepoRoot: "/repo"}, policy.Ask, "P5.out-of-repo"},
		{"Edit", ToolCall{Plane: "claude", Tool: "Edit", Paths: []string{root}, CWD: "/repo", RepoRoot: "/repo"}, policy.Ask, "P5.out-of-repo"},
		{"MultiEdit", ToolCall{Plane: "claude", Tool: "MultiEdit", Paths: []string{root}, CWD: "/repo", RepoRoot: "/repo"}, policy.Ask, "P5.out-of-repo"},
		{"redirect", ToolCall{Plane: "claude", Tool: "Bash", Command: "printf x > " + root, CWD: "/repo", RepoRoot: "/repo"}, policy.Ask, "P1.redirect"},
		{"recursive rm", ToolCall{Plane: "claude", Tool: "Bash", Command: "rm -rf " + root, CWD: "/repo", RepoRoot: "/repo"}, policy.Deny, "P1.rm-rf"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			v := Evaluate(test.call, pathPol())
			if v.Decision != test.decision || v.RuleID != test.ruleID {
				t.Fatalf("Evaluate(%s memory root) = %+v, want %s/%s", test.call.Tool, v, test.decision, test.ruleID)
			}
		})
	}
}

// Mutation caught: broad home or projects-prefix matching admits paths outside the exact memory shape.
func TestNF17ClaudeMemoryRejectsFalseShapesAndTraversal(t *testing.T) {
	home := nf17NonTempHome(t)
	nf17SetHome(t, home)
	otherHome := filepath.Join(filepath.Dir(home), "other-home")
	tests := []struct {
		name string
		path string
	}{
		{"no project segment", filepath.Join(home, ".claude", "projects", "memory", "note.md")},
		{"extra segment before memory", filepath.Join(home, ".claude", "projects", "project-key", "extra", "memory", "note.md")},
		{"memory adjacent name", filepath.Join(home, ".claude", "projects", "project-key", "memoryish", "note.md")},
		{"different home", filepath.Join(otherHome, ".claude", "projects", "project-key", "memory", "note.md")},
		{"literal tilde", filepath.Join("~", ".claude", "projects", "project-key", "memory", "note.md")},
		{"traversal outside memory", filepath.Join(home, ".claude", "projects", "project-key", "memory") + string(filepath.Separator) + ".." + string(filepath.Separator) + "outside.md"},
		{"traversal exits and reenters memory", filepath.Join(home, ".claude", "projects", "project-key", "memory") + string(filepath.Separator) + ".." + string(filepath.Separator) + "memory" + string(filepath.Separator) + "note.md"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			call := ToolCall{Plane: "claude", Tool: "Write", Paths: []string{test.path}, CWD: "/repo", RepoRoot: "/repo"}
			v := Evaluate(call, pathPol())
			if v.Decision != policy.Ask || v.RuleID != "P5.out-of-repo" {
				t.Fatalf("Evaluate(Write %q) = %+v, want ask/P5.out-of-repo", test.path, v)
			}
		})
	}
}

// Mutation caught: sharing memory authorization with general Bash mutators broadens it beyond the approved seams.
func TestNF17ClaudeMemoryDoesNotAuthorizeOtherBashMutators(t *testing.T) {
	home := nf17NonTempHome(t)
	nf17SetHome(t, home)
	target := filepath.Join(home, ".claude", "projects", "project-key", "memory", "note.md")
	tests := []struct {
		command string
		ruleID  string
	}{
		{"cp /repo/source " + target, "P1.out-of-repo-write"},
		{"mv /repo/source " + target, "P1.out-of-repo-write"},
		{"ln -s /repo/source " + target, "P1.out-of-repo-write"},
		{"tee " + target, "P1.out-of-repo-write"},
		{"install /repo/source " + target, "P1.out-of-repo-write"},
		{"rsync --delete /repo/source/ " + target, "P1.out-of-repo-write"},
		{"find " + filepath.Dir(target) + " -delete", "P1.find-delete"},
	}
	for _, test := range tests {
		call := ToolCall{Plane: "claude", Tool: "Bash", Command: test.command, CWD: "/repo", RepoRoot: "/repo"}
		if v := Evaluate(call, pathPol()); v.Decision != policy.Ask || v.RuleID != test.ruleID {
			t.Errorf("Evaluate(%q) = %+v, want ask/%s", test.command, v, test.ruleID)
		}
	}
}

// Mutation caught: returning early on memory authorization suppresses stronger path protections or later candidates.
func TestNF17ClaudeMemoryRetainsStrongerVerdictsAndAggregation(t *testing.T) {
	home := nf17NonTempHome(t)
	nf17SetHome(t, home)
	memory := filepath.Join(home, ".claude", "projects", "project-key", "memory")
	tests := []struct {
		name     string
		paths    []string
		decision policy.Decision
		ruleID   string
	}{
		{"secret", []string{filepath.Join(memory, "id_rsa")}, policy.Deny, "P4.secret-path"},
		{"git protected", []string{filepath.Join(memory, ".git", "config")}, policy.Deny, "P2.git-protected-path"},
		{"self config", []string{filepath.Join(memory, "guardrail.toml")}, policy.Deny, "P5.self-config"},
		{"CI workflow", []string{filepath.Join(memory, ".github", "workflows", "ci.yml")}, policy.Ask, "P5.ci-infra-lockfile"},
		{"safe then secret", []string{filepath.Join(memory, "note.md"), filepath.Join(memory, "id_rsa")}, policy.Deny, "P4.secret-path"},
		{"secret then safe", []string{filepath.Join(memory, "id_rsa"), filepath.Join(memory, "note.md")}, policy.Deny, "P4.secret-path"},
		{"safe then arbitrary outside", []string{filepath.Join(memory, "note.md"), "/etc/nf17-note.md"}, policy.Ask, "P5.out-of-repo"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			call := ToolCall{Plane: "claude", Tool: "Write", Paths: test.paths, CWD: "/repo", RepoRoot: "/repo"}
			v := Evaluate(call, pathPol())
			if v.Decision != test.decision || v.RuleID != test.ruleID {
				t.Fatalf("Evaluate(Write %q) = %+v, want %s/%s", test.paths, v, test.decision, test.ruleID)
			}
		})
	}
}

// Mutation caught: trusting a lexical memory shape lets project or memory symlinks escape the actual home.
func TestNF17ClaudeMemoryRequiresPhysicalContainmentUnderActualHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	home, err := os.MkdirTemp(".", ".nf17-home-")
	if err != nil {
		t.Fatal(err)
	}
	home, err = filepath.Abs(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	nf17SetHome(t, home)
	projects := filepath.Join(home, ".claude", "projects")
	if err := os.MkdirAll(projects, 0o700); err != nil {
		t.Fatal(err)
	}

	outsideProject := t.TempDir()
	projectAlias := filepath.Join(projects, "project-alias")
	if err := os.Symlink(outsideProject, projectAlias); err != nil {
		t.Fatal(err)
	}
	realProject := filepath.Join(projects, "real-project")
	if err := os.Mkdir(realProject, 0o700); err != nil {
		t.Fatal(err)
	}
	memoryAlias := filepath.Join(realProject, "memory")
	if err := os.Symlink(t.TempDir(), memoryAlias); err != nil {
		t.Fatal(err)
	}

	for _, target := range []string{
		filepath.Join(projectAlias, "memory", "note.md"),
		filepath.Join(memoryAlias, "note.md"),
	} {
		call := ToolCall{Plane: "claude", Tool: "Write", Paths: []string{target}, CWD: "/repo", RepoRoot: "/repo"}
		v := Evaluate(call, pathPol())
		if v.Decision != policy.Ask || v.RuleID != "P5.out-of-repo" {
			t.Errorf("Evaluate(Write symlink escape %q) = %+v, want ask/P5.out-of-repo", target, v)
		}
	}
}

// Mutation caught: rejecting a symlinked actual home breaks valid homes whose physical memory remains beneath it.
func TestNF17ClaudeMemoryAllowsSymlinkedActualHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	physicalHome := t.TempDir()
	alias, err := os.MkdirTemp(".", ".nf17-home-link-")
	if err != nil {
		t.Fatal(err)
	}
	alias, err = filepath.Abs(alias)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(physicalHome, alias); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(alias) })
	nf17SetHome(t, alias)
	target := filepath.Join(alias, ".claude", "projects", "project-key", "memory", "note.md")
	call := ToolCall{Plane: "claude", Tool: "Write", Paths: []string{target}, CWD: "/repo", RepoRoot: "/repo"}
	if v := Evaluate(call, pathPol()); v.Decision != policy.Allow || v.RuleID != "" {
		t.Fatalf("Evaluate(Write under symlinked actual home) = %+v, want allow", v)
	}
}

// Mutation caught: accepting an unusable home value can turn a relative path or filesystem root into writable memory.
func TestNF17ClaudeMemoryRejectsUnsetRelativeAndRootHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix HOME edge cases")
	}
	tests := []struct {
		name string
		home string
		path string
	}{
		{"unset", "", filepath.Join(nf17NonTempHome(t), ".claude", "projects", "p", "memory", "note.md")},
		{"relative", "relative-home", filepath.Join(nf17NonTempHome(t), ".claude", "projects", "p", "memory", "note.md")},
		{"filesystem root", "/", filepath.Join("/", ".claude", "projects", "p", "memory", "note.md")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nf17SetHome(t, test.home)
			call := ToolCall{Plane: "claude", Tool: "Write", Paths: []string{test.path}, CWD: "/repo", RepoRoot: "/repo"}
			v := Evaluate(call, pathPol())
			if v.Decision != policy.Ask || v.RuleID != "P5.out-of-repo" {
				t.Fatalf("Evaluate(Write with HOME=%q) = %+v, want ask/P5.out-of-repo", test.home, v)
			}
		})
	}
}

// Mutation caught: applying Unix spelling rules on Windows rejects native separators/case, while folding on Unix broadens the shape.
func TestNF17ClaudeMemoryUsesPlatformSeparatorAndCaseSemantics(t *testing.T) {
	home := nf17NonTempHome(t)
	nf17SetHome(t, home)
	target := filepath.Join(home, ".claude", "projects", "project-key", "memory", "note.md")
	separatorVariant := strings.ReplaceAll(target, string(filepath.Separator), func() string {
		if filepath.Separator == '/' {
			return `\`
		}
		return "/"
	}())
	caseVariant := strings.Replace(target, ".claude", ".CLAUDE", 1)
	want := policy.Ask
	wantRule := "P5.out-of-repo"
	if runtime.GOOS == "windows" {
		want = policy.Allow
		wantRule = ""
	}
	for _, candidate := range []string{separatorVariant, caseVariant} {
		call := ToolCall{Plane: "claude", Tool: "Write", Paths: []string{candidate}, CWD: filepath.Dir(home), RepoRoot: "/repo"}
		v := Evaluate(call, pathPol())
		if v.Decision != want || v.RuleID != wantRule {
			t.Errorf("Evaluate(Write platform variant %q) = %+v, want %s/%s", candidate, v, want, wantRule)
		}
	}
}

// Mutation caught: adding Claude memory roots without checking the normalized plane grants other planes the same authority.
func TestNF17ReviewClaudeMemoryRequiresExactNormalizedClaudePlane(t *testing.T) {
	home := nf17NonTempHome(t)
	nf17SetHome(t, home)
	target := filepath.Join(home, ".claude", "projects", "project-key", "memory", "note.md")
	tests := []struct {
		name             string
		plane            string
		fileDecision     policy.Decision
		fileRule         string
		redirectDecision policy.Decision
		redirectRule     string
		rmDecision       policy.Decision
		rmRule           string
	}{
		{"claude", "claude", policy.Allow, "", policy.Allow, "", policy.Allow, ""},
		{"opencode", "opencode", policy.Ask, "P5.out-of-repo", policy.Ask, "P1.redirect", policy.Deny, "P1.rm-rf"},
		{"antigravity", "antigravity", policy.Ask, "P5.out-of-repo", policy.Ask, "P1.redirect", policy.Deny, "P1.rm-rf"},
		{"empty", "", policy.Ask, "P5.out-of-repo", policy.Ask, "P1.redirect", policy.Deny, "P1.rm-rf"},
		{"non-normalized case", "Claude", policy.Ask, "P5.out-of-repo", policy.Ask, "P1.redirect", policy.Deny, "P1.rm-rf"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := []struct {
				name     string
				call     ToolCall
				decision policy.Decision
				ruleID   string
			}{
				{"file tool", ToolCall{Plane: test.plane, Tool: "Write", Paths: []string{target}, CWD: "/repo", RepoRoot: "/repo"}, test.fileDecision, test.fileRule},
				{"redirect", ToolCall{Plane: test.plane, Tool: "Bash", Command: "printf x > " + target, CWD: "/repo", RepoRoot: "/repo"}, test.redirectDecision, test.redirectRule},
				{"recursive rm", ToolCall{Plane: test.plane, Tool: "Bash", Command: "rm -rf " + target, CWD: "/repo", RepoRoot: "/repo"}, test.rmDecision, test.rmRule},
			}
			for _, operation := range calls {
				t.Run(operation.name, func(t *testing.T) {
					v := Evaluate(operation.call, pathPol())
					if v.Decision != operation.decision || v.RuleID != operation.ruleID {
						t.Fatalf("Evaluate(%s %s) = %+v, want %s/%s", test.plane, operation.name, v, operation.decision, operation.ruleID)
					}
				})
			}
		})
	}
}

// Mutation caught: accepting any physical memory root beneath HOME permits symlink aliases in the protected suffix.
func TestNF17ReviewClaudeMemoryRejectsSymlinksWithinHomeSuffix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	components := []string{".claude", "projects", "project-key", "memory"}
	for linkIndex, linkedComponent := range components {
		t.Run(linkedComponent, func(t *testing.T) {
			home, err := os.MkdirTemp(".", ".nf17-review-home-")
			if err != nil {
				t.Fatal(err)
			}
			home, err = filepath.Abs(home)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(home) })
			nf17SetHome(t, home)

			unrelated := filepath.Join(home, "unrelated-"+strings.TrimPrefix(linkedComponent, "."))
			if err := os.Mkdir(unrelated, 0o700); err != nil {
				t.Fatal(err)
			}
			current := home
			for index, component := range components {
				current = filepath.Join(current, component)
				if index == linkIndex {
					if err := os.Symlink(unrelated, current); err != nil {
						t.Fatal(err)
					}
					continue
				}
				if err := os.Mkdir(current, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			target := filepath.Join(current, "note.md")
			call := ToolCall{Plane: "claude", Tool: "Write", Paths: []string{target}, CWD: "/repo", RepoRoot: "/repo"}
			v := Evaluate(call, pathPol())
			if v.Decision != policy.Ask || v.RuleID != "P5.out-of-repo" {
				t.Fatalf("Evaluate(Write through symlinked %s) = %+v, want ask/P5.out-of-repo", linkedComponent, v)
			}
		})
	}
}

// Mutation caught: checking non-strict roots first allows a protected strict root through an overlapping repo or safe root.
func TestNF17ReviewStrictRootEqualityPrecedesOverlappingNonStrictRoots(t *testing.T) {
	tmpdir := t.TempDir()
	t.Setenv("TMPDIR", tmpdir)
	home := nf17NonTempHome(t)
	nf17SetHome(t, home)
	memoryRoot := filepath.Join(home, ".claude", "projects", "project-key", "memory")

	safeTemp := pathPol()
	safeTemp.Slots.SafeRoots = []string{filepath.Dir(tmpdir)}
	safeHome := pathPol()
	safeHome.Slots.SafeRoots = []string{home}
	tests := []struct {
		name     string
		call     ToolCall
		pol      *policy.Policy
		decision policy.Decision
		ruleID   string
	}{
		{"temp root equals repo", ToolCall{Plane: "opencode", Tool: "Write", Paths: []string{tmpdir}, CWD: tmpdir, RepoRoot: tmpdir}, pathPol(), policy.Ask, "P5.out-of-repo"},
		{"temp root inside safe root", ToolCall{Plane: "opencode", Tool: "Bash", Command: "printf x > " + tmpdir, CWD: "/repo", RepoRoot: "/repo"}, safeTemp, policy.Ask, "P1.redirect"},
		{"memory root inside repo", ToolCall{Plane: "claude", Tool: "Write", Paths: []string{memoryRoot}, CWD: home, RepoRoot: home}, pathPol(), policy.Ask, "P5.out-of-repo"},
		{"memory root inside safe root redirect", ToolCall{Plane: "claude", Tool: "Bash", Command: "printf x > " + memoryRoot, CWD: "/repo", RepoRoot: "/repo"}, safeHome, policy.Ask, "P1.redirect"},
		{"memory root inside safe root rm", ToolCall{Plane: "claude", Tool: "Bash", Command: "rm -rf " + memoryRoot, CWD: "/repo", RepoRoot: "/repo"}, safeHome, policy.Deny, "P1.rm-rf"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			v := Evaluate(test.call, test.pol)
			if v.Decision != test.decision || v.RuleID != test.ruleID {
				t.Fatalf("Evaluate(%s) = %+v, want %s/%s", test.name, v, test.decision, test.ruleID)
			}
		})
	}
}

// Mutation caught: dropping strict physical equality lets a lexical repository alias authorize deletion of the protected temp root.
func TestNF17ReviewStrictPhysicalEqualityPrecedesRepositoryAlias(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	strictRoot := t.TempDir()
	t.Setenv("TMPDIR", strictRoot)
	alias, err := os.MkdirTemp(".", ".nf17-temp-alias-")
	if err != nil {
		t.Fatal(err)
	}
	alias, err = filepath.Abs(alias)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(strictRoot, alias); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(alias) })

	call := ToolCall{Tool: "Bash", Command: "rm -rf " + alias, CWD: alias, RepoRoot: alias}
	v := Evaluate(call, pathPol())
	if v.Decision != policy.Deny || v.RuleID != "P1.rm-rf" {
		t.Fatalf("Evaluate(rm protected temp root through repository alias) = %+v, want deny/P1.rm-rf", v)
	}
}

// Mutation caught: rejecting an overlapping strict root wholesale also rejects its approved strict descendants.
func TestNF17ReviewOverlappingStrictRootDescendantsRemainAuthorized(t *testing.T) {
	tmpdir := t.TempDir()
	t.Setenv("TMPDIR", tmpdir)
	home := nf17NonTempHome(t)
	nf17SetHome(t, home)
	memoryRoot := filepath.Join(home, ".claude", "projects", "project-key", "memory")
	tests := []struct {
		name string
		call ToolCall
		pol  *policy.Policy
	}{
		{"temp descendant in repo", ToolCall{Plane: "opencode", Tool: "Write", Paths: []string{filepath.Join(tmpdir, "note.md")}, CWD: tmpdir, RepoRoot: tmpdir}, pathPol()},
		{"memory descendant in repo", ToolCall{Plane: "claude", Tool: "Write", Paths: []string{filepath.Join(memoryRoot, "note.md")}, CWD: home, RepoRoot: home}, pathPol()},
		{"memory descendant in safe root", ToolCall{Plane: "claude", Tool: "Bash", Command: "printf x > " + filepath.Join(memoryRoot, "note.md"), CWD: "/repo", RepoRoot: "/repo"}, func() *policy.Policy {
			pol := pathPol()
			pol.Slots.SafeRoots = []string{home}
			return pol
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if v := Evaluate(test.call, test.pol); v.Decision != policy.Allow || v.RuleID != "" {
				t.Fatalf("Evaluate(%s) = %+v, want allow", test.name, v)
			}
		})
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
