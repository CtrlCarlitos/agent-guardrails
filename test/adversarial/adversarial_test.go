package adversarial

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	// The hook runs as a subprocess, so bind Go's test cache to its internal dependencies.
	_ "github.com/CtrlCarlitos/agent-guardrails/internal/adapter"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	_ "github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	_ "github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	_ "github.com/CtrlCarlitos/agent-guardrails/internal/recipe"
	_ "github.com/CtrlCarlitos/agent-guardrails/internal/session"
	"mvdan.cc/sh/v3/syntax"
)

type entry struct {
	Name                    string           `json:"name"`
	Tool                    string           `json:"tool"`
	Command                 string           `json:"command,omitempty"`
	Paths                   []string         `json:"paths,omitempty"`
	CWD                     string           `json:"cwd"`
	RepoRoot                string           `json:"repo_root"`
	RepoAlias               string           `json:"repo_alias,omitempty"`
	FixtureFiles            []string         `json:"fixture_files,omitempty"`
	FixtureSymlinks         []fixtureSymlink `json:"fixture_symlinks,omitempty"`
	Waive                   []string         `json:"waive,omitempty"`
	Want                    string           `json:"want"`
	RewriteLogicalRepoPaths bool             `json:"rewrite_logical_repo_paths,omitempty"`
	RewriteActualHomePaths  bool             `json:"rewrite_actual_home_paths,omitempty"`
}

type fixtureSymlink struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

var (
	adversarialBuildOnce sync.Once
	adversarialBuildDir  string
	adversarialBinary    string
	adversarialBuildErr  error
	adversarialBuildLog  string
)

func TestMain(m *testing.M) {
	code := m.Run()
	if adversarialBuildDir != "" {
		_ = os.RemoveAll(adversarialBuildDir)
	}
	os.Exit(code)
}

func buildAdversarialBinary(t *testing.T) string {
	t.Helper()
	trackCommandSources(t)
	adversarialBuildOnce.Do(func() {
		adversarialBuildDir, adversarialBuildErr = os.MkdirTemp("", "guardrail-adversarial-")
		if adversarialBuildErr != nil {
			return
		}
		adversarialBinary = filepath.Join(adversarialBuildDir, "guardrail")
		var attempts []string
		for _, goBinary := range []string{"go", "/usr/local/go/bin/go"} {
			out, err := exec.Command(goBinary, "build", "-o", adversarialBinary, "../../cmd/guardrail").CombinedOutput()
			if err == nil {
				adversarialBuildErr = nil
				return
			}
			attempts = append(attempts, fmt.Sprintf("%s: %v: %s", goBinary, err, out))
			adversarialBuildErr = err
		}
		adversarialBuildLog = strings.Join(attempts, " / ")
	})
	if adversarialBuildErr != nil {
		t.Fatalf("build adversarial binary: %v (%s)", adversarialBuildErr, adversarialBuildLog)
	}
	return adversarialBinary
}

func trackCommandSources(t *testing.T) {
	t.Helper()
	sources, err := filepath.Glob("../../cmd/guardrail/*.go")
	if err != nil || len(sources) == 0 {
		t.Fatalf("locate guardrail command sources: %v", err)
	}
	for _, source := range sources {
		if _, err := os.ReadFile(source); err != nil {
			t.Fatalf("track guardrail command source %s: %v", source, err)
		}
	}
}

// The corpus harness requires CWD inside RepoRoot. The cwd ~/.ssh bare-filename
// cases therefore remain covered by focused Engine tests.
func TestAdversarialCorpus(t *testing.T) {
	bin := buildAdversarialBinary(t)
	raw, err := os.ReadFile("corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var entries []entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("corpus is empty")
	}

	names := make(map[string]bool, len(entries))
	for i, e := range entries {
		if err := validateEntry(e, names); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		e := e
		t.Run(e.Name, func(t *testing.T) {
			cwd, physicalRoot := materializeRepo(t, e)
			callEntry, err := rewriteLogicalRepoPaths(e, physicalRoot)
			if err != nil {
				t.Fatal(err)
			}
			var actualHome string
			if callEntry.RewriteActualHomePaths {
				workingDirectory, err := os.Getwd()
				if err != nil {
					t.Fatal(err)
				}
				actualHome = filepath.Join(workingDirectory, ".adversarial-home", fmt.Sprintf("entry-%03d", i))
				callEntry = rewriteActualHomePaths(callEntry, actualHome)
			}
			sessionID := fmt.Sprintf("adv-%03d", i)
			in := map[string]any{
				"session_id":      sessionID,
				"cwd":             cwd,
				"hook_event_name": "PreToolUse",
				"tool_name":       e.Tool,
			}
			ti := map[string]any{}
			if callEntry.Command != "" {
				ti["command"] = callEntry.Command
			} else {
				ti["file_path"] = callEntry.Paths[0]
			}
			in["tool_input"] = ti
			payload, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}

			stateHome := t.TempDir()
			configHome := t.TempDir()
			config := filepath.Join(t.TempDir(), "guardrail.toml")
			var overlay []byte
			if len(e.Waive) > 0 {
				quoted := make([]string, len(e.Waive))
				for i, ruleID := range e.Waive {
					quoted[i] = fmt.Sprintf("%q", ruleID)
				}
				overlay = []byte("waive = [" + strings.Join(quoted, ",") + "]\n")

				grantRoot, err := filepath.EvalSymlinks(physicalRoot)
				if err != nil {
					t.Fatalf("resolve repository root for waiver grant: %v", err)
				}
				operatorDir := filepath.Join(configHome, "guardrail")
				if err := os.MkdirAll(operatorDir, 0o700); err != nil {
					t.Fatalf("create Operator config directory: %v", err)
				}
				operatorConfig := fmt.Sprintf("[%q]\nwaive = [%s]\n", grantRoot, strings.Join(quoted, ","))
				if err := os.WriteFile(filepath.Join(operatorDir, "waivers.toml"), []byte(operatorConfig), 0o600); err != nil {
					t.Fatalf("write Operator config: %v", err)
				}
			}
			if err := os.WriteFile(config, overlay, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(bin, "hook", "claude")
			cmd.Stdin = bytes.NewReader(payload)
			cmd.Env = append(os.Environ(),
				"XDG_STATE_HOME="+stateHome,
				"XDG_CONFIG_HOME="+configHome,
				"GUARDRAIL_CONFIG="+config,
			)
			if actualHome != "" {
				cmd.Env = append(cmd.Env, actualHomeEnvironment(runtime.GOOS, actualHome))
			}
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			runErr := cmd.Run()
			code := 0
			if runErr != nil {
				var exitErr *exec.ExitError
				if !errors.As(runErr, &exitErr) {
					t.Fatalf("run hook: %v", runErr)
				}
				code = exitErr.ExitCode()
			}

			got, err := classifyClaudeResult(code, stdout.String(), stderr.String(),
				filepath.Join(stateHome, "guardrail", "audit.jsonl"),
				auditExpectation{SessionID: sessionID, Tool: e.Tool, Event: "pre"})
			if err != nil {
				t.Fatalf("invalid Claude hook result: %v (exit=%d stdout=%s stderr=%s)", err, code, stdout.String(), stderr.String())
			}
			if got != e.Want {
				t.Fatalf("got %s, want %s (exit=%d stdout=%s stderr=%s)", got, e.Want, code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestClassifyClaudeResult(t *testing.T) {
	const (
		denyAudit   = `{"ts":"2026-09-04T00:00:00Z","session_id":"adv-test","plane":"claude","tool":"Bash","event":"pre","decision":"deny"}` + "\n"
		askAudit    = `{"ts":"2026-09-04T00:00:00Z","session_id":"adv-test","plane":"claude","tool":"Bash","event":"pre","decision":"ask"}` + "\n"
		allowAudit  = `{"ts":"2026-09-04T00:00:00Z","session_id":"adv-test","plane":"claude","tool":"Bash","event":"pre","decision":"allow"}` + "\n"
		originAudit = `{"ts":"2026-09-04T00:00:00Z","session_id":"adv-test","plane":"claude","tool":"Bash","event":"pre","decision":"allow","rule_id":"ask-approved-by-retry","origin_rule_id":"P2.git-checkout-restore"}` + "\n"
	)
	tests := []struct {
		name   string
		code   int
		stdout string
		stderr string
		audit  string
		want   string
		fail   bool
	}{
		{name: "allow", code: 0, audit: allowAudit, want: "allow"},
		{name: "allow with origin attribution", code: 0, audit: originAudit, want: "allow"},
		{name: "ask", code: 0, stdout: `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"confirm"}}` + "\n", audit: askAudit, want: "ask"},
		{name: "deny", code: 2, stderr: "guardrail: blocked by policy\n", audit: denyAudit, want: "deny"},
		{name: "deny reason contains runtime marker", code: 2, stderr: "guardrail: target contains runtime: metadata\n", audit: denyAudit, want: "deny"},
		{name: "deny reason contains embedded newline", code: 2, stderr: "guardrail: first reason line\nsecond reason line\n", audit: denyAudit, want: "deny"},
		{name: "setup failure has no audit", code: 2, stderr: "guardrail: cannot load base policy: unavailable\n", fail: true},
		{name: "exit two without guardrail stderr", code: 2, stderr: "command failed\n", audit: denyAudit, fail: true},
		{name: "exit two with panic", code: 2, stderr: "panic: runtime failure\n", audit: denyAudit, fail: true},
		{name: "exit two with stdout", code: 2, stdout: `{"hookSpecificOutput":{"permissionDecision":"ask"}}`, stderr: "guardrail: blocked by policy\n", audit: denyAudit, fail: true},
		{name: "post-tool ask is invalid", code: 0, stdout: `{"hookSpecificOutput":{"hookEventName":"PostToolUse","permissionDecision":"ask","permissionDecisionReason":"confirm"}}` + "\n", audit: strings.Replace(askAudit, `"event":"pre"`, `"event":"post"`, 1), fail: true},
		{name: "unknown exit", code: 3, stderr: "guardrail: unexpected failure\n", audit: denyAudit, fail: true},
		{name: "invalid success stdout", code: 0, stdout: "not-json\n", audit: allowAudit, fail: true},
		{name: "missing audit", code: 0, fail: true},
		{name: "malformed audit", code: 0, audit: "not-json\n", fail: true},
		{name: "multiple audit records", code: 0, audit: allowAudit + allowAudit, fail: true},
		{name: "audit decision mismatch", code: 2, stderr: "guardrail: blocked by policy\n", audit: allowAudit, fail: true},
		{name: "audit session mismatch", code: 0, audit: strings.Replace(allowAudit, "adv-test", "other", 1), fail: true},
		{name: "audit tool mismatch", code: 0, audit: strings.Replace(allowAudit, `"tool":"Bash"`, `"tool":"Read"`, 1), fail: true},
		{name: "audit event mismatch", code: 0, audit: strings.Replace(allowAudit, `"event":"pre"`, `"event":"post"`, 1), fail: true},
		{name: "audit plane mismatch", code: 0, audit: strings.Replace(allowAudit, `"plane":"claude"`, `"plane":"opencode"`, 1), fail: true},
		{name: "audit missing timestamp", code: 0, audit: strings.Replace(allowAudit, `"ts":"2026-09-04T00:00:00Z",`, "", 1), fail: true},
		{name: "audit has unknown field", code: 0, audit: strings.Replace(allowAudit, `"decision":"allow"`, `"decision":"allow","unexpected":true`, 1), fail: true},
		{name: "audit has raw arguments", code: 0, audit: strings.Replace(allowAudit, `"decision":"allow"`, `"decision":"allow","arguments":{"command":"secret"}`, 1), fail: true},
	}
	expectation := auditExpectation{SessionID: "adv-test", Tool: "Bash", Event: "pre"}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
			if test.audit != "" {
				if err := os.WriteFile(auditPath, []byte(test.audit), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := classifyClaudeResult(test.code, test.stdout, test.stderr, auditPath, expectation)
			if test.fail {
				if err == nil {
					t.Fatalf("classifyClaudeResult(%d, %q, %q) = %q, want error", test.code, test.stdout, test.stderr, got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("classifyClaudeResult(%d, %q, %q) = %q, %v; want %q, nil", test.code, test.stdout, test.stderr, got, err, test.want)
			}
		})
	}
}

func TestAuditContractAcceptsOriginRuleAndRejectsArguments(t *testing.T) {
	writeAndRead := func(t *testing.T, raw string) error {
		t.Helper()
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		if err := os.WriteFile(path, []byte(raw+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := readSingleAuditRecord(path)
		return err
	}
	const attributed = `{"ts":"2026-09-04T00:00:00Z","plane":"opencode","tool":"Bash","decision":"allow","rule_id":"ask-approved-by-retry","origin_rule_id":"P2.git-checkout-restore"}`
	if err := writeAndRead(t, attributed); err != nil {
		t.Fatalf("declared origin_rule_id was rejected: %v", err)
	}
	const leakedArguments = `{"ts":"2026-09-04T00:00:00Z","plane":"opencode","tool":"Bash","decision":"allow","arguments":{"command":"secret"}}`
	if err := writeAndRead(t, leakedArguments); err == nil {
		t.Fatal("raw arguments were accepted by the strict audit contract")
	}
}

func TestClassifyClaudeResultRejectsExitTwoCrashProcess(t *testing.T) {
	code, stdout, stderr := runFakeClaudeProcess(t, "panic")
	if got, err := classifyClaudeResult(code, stdout, stderr, filepath.Join(t.TempDir(), "missing-audit.jsonl"), auditExpectation{SessionID: "adv-test", Tool: "Bash", Event: "pre"}); err == nil {
		t.Fatalf("fake crash classified as %q; stderr=%q", got, stderr)
	}
}

func TestClassifyClaudeResultRejectsSetupFailureWithoutAudit(t *testing.T) {
	code, stdout, stderr := runFakeClaudeProcess(t, "setup")
	if got, err := classifyClaudeResult(code, stdout, stderr, filepath.Join(t.TempDir(), "missing-audit.jsonl"), auditExpectation{SessionID: "adv-test", Tool: "Bash", Event: "pre"}); err == nil || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("fake setup failure classified as %q, err=%v; stderr=%q", got, err, stderr)
	}
}

func runFakeClaudeProcess(t *testing.T, mode string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFakeClaudeFailureProcess$")
	cmd.Env = append(os.Environ(), "GO_WANT_FAKE_CLAUDE_FAILURE="+mode)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("fake %s error = %v, want process exit error", mode, err)
	}
	if code := exitErr.ExitCode(); code != 2 {
		t.Fatalf("fake %s exit = %d, want 2", mode, code)
	}
	return exitErr.ExitCode(), stdout.String(), stderr.String()
}

func TestFakeClaudeFailureProcess(t *testing.T) {
	switch os.Getenv("GO_WANT_FAKE_CLAUDE_FAILURE") {
	case "panic":
		fmt.Fprintln(os.Stderr, "panic: simulated Go runtime crash")
	case "setup":
		fmt.Fprintln(os.Stderr, "guardrail: cannot load base policy: simulated setup failure")
	default:
		return
	}
	os.Exit(2)
}

type auditExpectation struct {
	SessionID string
	Tool      string
	Event     string
}

func classifyClaudeResult(code int, stdout, stderr, auditPath string, expected auditExpectation) (string, error) {
	decision, err := classifyClaudeProcess(code, stdout, stderr)
	if err != nil {
		return "", err
	}
	record, err := readSingleAuditRecord(auditPath)
	if err != nil {
		return "", err
	}
	if record.Plane != "claude" || record.SessionID != expected.SessionID ||
		record.Tool != expected.Tool || record.Event != expected.Event {
		return "", fmt.Errorf("audit context mismatch: got plane=%q session=%q tool=%q event=%q",
			record.Plane, record.SessionID, record.Tool, record.Event)
	}
	if record.Decision != decision {
		return "", fmt.Errorf("audit decision %q disagrees with Claude process decision %q", record.Decision, decision)
	}
	return decision, nil
}

func classifyClaudeProcess(code int, stdout, stderr string) (string, error) {
	switch code {
	case 2:
		if stdout != "" {
			return "", errors.New("deny exit included contradictory stdout")
		}
		if !strings.HasPrefix(stderr, "guardrail: ") {
			return "", errors.New("deny stderr does not match Claude guardrail contract")
		}
		return "deny", nil
	case 0:
		if stdout == "" {
			return "allow", nil
		}
		var response struct {
			HookSpecificOutput struct {
				HookEventName            string `json:"hookEventName"`
				PermissionDecision       string `json:"permissionDecision"`
				PermissionDecisionReason string `json:"permissionDecisionReason"`
			} `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal([]byte(stdout), &response); err != nil {
			return "", fmt.Errorf("exit-zero stdout is not Claude hook JSON: %w", err)
		}
		hook := response.HookSpecificOutput
		if hook.PermissionDecision != "ask" || hook.PermissionDecisionReason == "" ||
			hook.HookEventName != "PreToolUse" {
			return "", errors.New("exit-zero stdout does not match Claude ask contract")
		}
		return "ask", nil
	default:
		return "", fmt.Errorf("hook exited with nonstandard status %d", code)
	}
}

func readSingleAuditRecord(path string) (audit.Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return audit.Record{}, fmt.Errorf("read audit record: %w", err)
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	var record audit.Record
	if err := decoder.Decode(&record); err != nil {
		return audit.Record{}, fmt.Errorf("parse audit record: %w", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return audit.Record{}, errors.New("audit contains multiple records")
		}
		return audit.Record{}, fmt.Errorf("parse trailing audit data: %w", err)
	}
	if _, err := time.Parse(time.RFC3339, record.TS); err != nil {
		return audit.Record{}, fmt.Errorf("audit timestamp %q is invalid: %w", record.TS, err)
	}
	return record, nil
}

func validateEntry(e entry, names map[string]bool) error {
	if e.Name == "" || names[e.Name] {
		return fmt.Errorf("name %q is empty or duplicated", e.Name)
	}
	names[e.Name] = true
	if e.Tool == "" || e.CWD == "" || e.RepoRoot == "" {
		return fmt.Errorf("%q must set tool, cwd, and repo_root", e.Name)
	}
	if (e.Command == "") == (len(e.Paths) == 0) {
		return fmt.Errorf("%q must set exactly one of command or paths", e.Name)
	}
	if len(e.Paths) > 1 {
		return fmt.Errorf("%q has %d paths; Claude accepts one file_path", e.Name, len(e.Paths))
	}
	if e.RepoAlias != "" {
		root := filepath.Clean(filepath.FromSlash(e.RepoRoot))
		alias := filepath.Clean(filepath.FromSlash(e.RepoAlias))
		if !e.RewriteLogicalRepoPaths || root == alias || !strings.EqualFold(root, alias) {
			return fmt.Errorf("%q repo_alias must be a case-only repo_root alias with logical rewriting enabled", e.Name)
		}
	}
	for _, ruleID := range e.Waive {
		if ruleID == "" {
			return fmt.Errorf("%q has an empty waiver rule ID", e.Name)
		}
	}
	switch e.Want {
	case "allow", "ask", "deny":
		return nil
	default:
		return fmt.Errorf("%q has invalid want %q", e.Name, e.Want)
	}
}

func fixturePath(fixtureRoot, base, name string) (string, error) {
	candidate := filepath.Clean(filepath.Join(base, filepath.FromSlash(name)))
	rel, err := filepath.Rel(fixtureRoot, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("fixture path %q escapes fixture root", name)
	}
	return candidate, nil
}

func createFixtureSymlink(fixtureRoot, repo string, symlink fixtureSymlink) error {
	path, err := fixturePath(fixtureRoot, repo, symlink.Path)
	if err != nil {
		return err
	}
	if path == repo {
		return fmt.Errorf("fixture symlink path %q must not equal the repository root", symlink.Path)
	}
	if rel, err := filepath.Rel(repo, path); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("fixture symlink path %q must be inside the repository", symlink.Path)
	}
	if filepath.IsAbs(symlink.Target) {
		return fmt.Errorf("fixture symlink target %q must be relative", symlink.Target)
	}
	if _, err := fixturePath(fixtureRoot, filepath.Dir(path), symlink.Target); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	for ancestor := parent; ancestor != repo; ancestor = filepath.Dir(ancestor) {
		info, err := os.Lstat(ancestor)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("inspect fixture symlink ancestor: %w", err)
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("fixture symlink path %q traverses symlink ancestor %q", symlink.Path, ancestor)
		}
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create fixture symlink parent: %w", err)
	}
	// Preserve .. ordering so it is evaluated after any target symlink component.
	rawTarget := parent + string(filepath.Separator) + filepath.FromSlash(symlink.Target)
	resolvedTarget, err := filepath.EvalSymlinks(rawTarget)
	if err != nil {
		return fmt.Errorf("resolve fixture symlink target %q: %w", symlink.Target, err)
	}
	if rel, err := filepath.Rel(fixtureRoot, resolvedTarget); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("fixture symlink target %q resolves outside fixture root", symlink.Target)
	}
	return os.Symlink(filepath.FromSlash(symlink.Target), path)
}

const windowsPrivilegeNotHeld syscall.Errno = 1314

func symlinkCapabilityUnavailable(err error) bool {
	var linkErr *os.LinkError
	return errors.As(err, &linkErr) &&
		(errors.Is(err, os.ErrPermission) ||
			errors.Is(err, errors.ErrUnsupported) ||
			(runtime.GOOS == "windows" && errors.Is(err, windowsPrivilegeNotHeld)))
}

func materializeRepo(t *testing.T, e entry) (string, string) {
	t.Helper()
	logicalRoot := filepath.Clean(filepath.FromSlash(e.RepoRoot))
	logicalCWD := filepath.Clean(filepath.FromSlash(e.CWD))
	if logicalRoot == string(filepath.Separator) {
		return logicalCWD, logicalRoot
	}
	rel, err := filepath.Rel(logicalRoot, logicalCWD)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("cwd %q must be inside repo_root %q", e.CWD, e.RepoRoot)
	}
	fixtureRoot := t.TempDir()
	repo := filepath.Join(fixtureRoot, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", repo, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("initialize repo fixture: %v: %s", err, out)
	}
	cwd := filepath.Join(repo, rel)
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range e.FixtureFiles {
		path, err := fixturePath(fixtureRoot, repo, name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("create fixture file parent: %v", err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatalf("create fixture file: %v", err)
		}
	}
	for _, symlink := range e.FixtureSymlinks {
		if err := createFixtureSymlink(fixtureRoot, repo, symlink); err != nil {
			if symlinkCapabilityUnavailable(err) {
				t.Skipf("symlinks unavailable: %v", err)
			}
			t.Fatal(err)
		}
	}
	if e.RepoAlias == "" {
		return cwd, repo
	}
	alias := filepath.Join(fixtureRoot, filepath.Base(filepath.FromSlash(e.RepoAlias)))
	if err := os.Symlink(repo, alias); err != nil {
		if symlinkCapabilityUnavailable(err) {
			t.Skipf("case-variant repository alias unavailable: %v", err)
		}
		t.Fatalf("create case-variant repository alias: %v", err)
	}
	return cwd, alias
}

func TestMaterializeRepoSupportsFilesystemRoot(t *testing.T) {
	cwd, root := materializeRepo(t, entry{CWD: "/", RepoRoot: "/"})
	if cwd != "/" || root != "/" {
		t.Fatalf("materializeRepo(root) = (%q, %q), want (/, /)", cwd, root)
	}
}

func TestMaterializeRepoSupportsCaseVariantAlias(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("case-only alias cannot coexist on a case-insensitive filesystem")
	}
	cwd, root := materializeRepo(t, entry{CWD: "/repo", RepoRoot: "/repo", RepoAlias: "/REPO"})
	if filepath.Base(root) != "REPO" {
		t.Fatalf("materialized rewrite root = %q, want case-variant REPO alias", root)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if cwd != resolved || filepath.Base(resolved) != "repo" {
		t.Fatalf("materialized cwd = %q, alias resolves to %q; want cwd at real repo", cwd, resolved)
	}
}

func TestMaterializeRepoCreatesSandboxedFixtures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	e := entry{
		CWD:          "/repo",
		RepoRoot:     "/repo",
		FixtureFiles: []string{"../outside/id_rsa"},
		FixtureSymlinks: []fixtureSymlink{
			{Path: "innocent.bin", Target: "../outside/id_rsa"},
		},
	}
	_, root := materializeRepo(t, e)
	want := filepath.Clean(filepath.Join(root, "../outside/id_rsa"))
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("fixture target not created: %v", err)
	}
	got, err := filepath.EvalSymlinks(filepath.Join(root, "innocent.bin"))
	if err != nil {
		t.Fatalf("fixture symlink not created: %v", err)
	}
	if got != want {
		t.Fatalf("fixture symlink resolves to %q, want %q", got, want)
	}
}

func TestCreateFixtureSymlinkRejectsChainedAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	fixtureRoot := t.TempDir()
	repo := filepath.Join(fixtureRoot, "repo")
	outside := filepath.Join(fixtureRoot, "outside")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := createFixtureSymlink(fixtureRoot, repo, fixtureSymlink{Path: "pivot", Target: "../outside"}); err != nil {
		t.Fatalf("create ancestor fixture symlink: %v", err)
	}
	if err := createFixtureSymlink(fixtureRoot, repo, fixtureSymlink{Path: "pivot/link", Target: "target"}); err == nil {
		t.Fatal("created fixture through a symlink ancestor")
	}
	if _, err := os.Lstat(filepath.Join(outside, "link")); !os.IsNotExist(err) {
		t.Fatalf("outside fixture created through symlink ancestor: %v", err)
	}
}

func TestCreateFixtureSymlinkRejectsEscapingRelativeTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	sandbox := t.TempDir()
	fixtureRoot := filepath.Join(sandbox, "fixture")
	repo := filepath.Join(fixtureRoot, "repo")
	outside := filepath.Join(fixtureRoot, "outside")
	escape := filepath.Join(sandbox, "escape")
	for _, path := range []string{repo, outside, escape} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := createFixtureSymlink(fixtureRoot, repo, fixtureSymlink{Path: "pivot", Target: "../outside"}); err != nil {
		t.Fatalf("create target fixture symlink: %v", err)
	}
	if err := createFixtureSymlink(fixtureRoot, repo, fixtureSymlink{Path: "link", Target: "pivot/../../escape"}); err == nil {
		t.Fatal("created fixture with a target outside the fixture root")
	}
	if _, err := os.Lstat(filepath.Join(repo, "link")); !os.IsNotExist(err) {
		t.Fatalf("fixture with escaping target was created: %v", err)
	}
	rawTarget := filepath.Join(repo, "pivot") + string(filepath.Separator) + filepath.FromSlash("../../escape")
	if resolved, err := filepath.EvalSymlinks(rawTarget); err != nil {
		t.Fatal(err)
	} else if resolved != escape {
		t.Fatalf("test target resolves to %q, want outside path %q", resolved, escape)
	}
}

func TestCreateFixtureSymlinkRejectsRepositoryPathWithoutHanging(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{name: "empty", path: ""},
		{name: "dot", path: "."},
		{name: "cleaned", path: "sub/.."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixtureRoot := t.TempDir()
			repo := filepath.Join(fixtureRoot, "repo")
			if err := os.MkdirAll(repo, 0o700); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				result <- createFixtureSymlink(fixtureRoot, repo, fixtureSymlink{Path: tc.path, Target: "target"})
			}()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("created fixture symlink at repository path")
				}
			case <-time.After(time.Second):
				t.Fatal("fixture symlink validation did not return")
			}
		})
	}
}

func TestSymlinkCapabilityUnavailable(t *testing.T) {
	linkError := func(err error) error {
		return &os.LinkError{Op: "symlink", Old: "target", New: "link", Err: err}
	}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "permission", err: linkError(os.ErrPermission), want: true},
		{name: "unsupported", err: linkError(errors.ErrUnsupported), want: true},
		{name: "Windows privilege not held", err: linkError(syscall.Errno(1314)), want: runtime.GOOS == "windows"},
		{name: "collision", err: linkError(os.ErrExist), want: false},
		{name: "unrelated link error", err: linkError(errors.New("boom")), want: false},
		{name: "non-link permission", err: os.ErrPermission, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := symlinkCapabilityUnavailable(tc.err); got != tc.want {
				t.Fatalf("symlinkCapabilityUnavailable(%v) = %t, want %t", tc.err, got, tc.want)
			}
		})
	}
}

func rewriteLogicalRepoPaths(e entry, physicalRoot string) (entry, error) {
	if !e.RewriteLogicalRepoPaths {
		return e, nil
	}
	logicalRoot := filepath.ToSlash(filepath.Clean(e.RepoRoot))
	if e.RepoAlias != "" {
		logicalRoot = filepath.ToSlash(filepath.Clean(e.RepoAlias))
	}
	physicalRoot = filepath.ToSlash(filepath.Clean(physicalRoot))
	replacePath := func(value string) (string, bool) {
		if value == logicalRoot {
			return physicalRoot, true
		}
		if strings.HasPrefix(value, logicalRoot+"/") {
			return physicalRoot + strings.TrimPrefix(value, logicalRoot), true
		}
		return value, false
	}

	if e.Command != "" {
		file, err := syntax.NewParser().Parse(strings.NewReader(e.Command), "")
		if err != nil {
			return entry{}, fmt.Errorf("parse materialized command: %w", err)
		}
		type replacement struct {
			start, end int
			value      string
		}
		var replacements []replacement
		syntax.Walk(file, func(node syntax.Node) bool {
			word, ok := node.(*syntax.Word)
			if !ok || len(word.Parts) != 1 {
				return true
			}
			literal, ok := word.Parts[0].(*syntax.Lit)
			if !ok {
				return false
			}
			value, replace := replacePath(literal.Value)
			if replace {
				replacements = append(replacements, replacement{
					start: int(word.Pos().Offset()), end: int(word.End().Offset()), value: value,
				})
			}
			return false
		})
		sort.Slice(replacements, func(i, j int) bool { return replacements[i].start > replacements[j].start })
		for _, replacement := range replacements {
			e.Command = e.Command[:replacement.start] + replacement.value + e.Command[replacement.end:]
		}
	}
	if len(e.Paths) > 0 {
		paths := append([]string(nil), e.Paths...)
		for i, path := range paths {
			if value, replace := replacePath(path); replace {
				paths[i] = value
			}
		}
		e.Paths = paths
	}
	return e, nil
}

func rewriteActualHomePaths(e entry, actualHome string) entry {
	if !e.RewriteActualHomePaths {
		return e
	}
	paths := append([]string(nil), e.Paths...)
	for i, candidate := range paths {
		if candidate == "/home/u" {
			paths[i] = actualHome
		} else if strings.HasPrefix(candidate, "/home/u/") {
			paths[i] = actualHome + strings.TrimPrefix(candidate, "/home/u")
		}
	}
	e.Paths = paths
	return e
}

func actualHomeEnvironment(goos string, actualHome string) string {
	if goos == "windows" {
		return "USERPROFILE=" + actualHome
	}
	return "HOME=" + actualHome
}

// Mutation caught: always setting HOME leaves Windows os.UserHomeDir reading the inherited USERPROFILE.
func TestNF17ReviewActualHomeEnvironmentUsesPlatformConvention(t *testing.T) {
	tests := []struct {
		goos string
		want string
	}{
		{"linux", "HOME=/actual/home"},
		{"darwin", "HOME=/actual/home"},
		{"windows", "USERPROFILE=/actual/home"},
	}
	for _, test := range tests {
		if got := actualHomeEnvironment(test.goos, "/actual/home"); got != test.want {
			t.Errorf("actualHomeEnvironment(%q) = %q, want %q", test.goos, got, test.want)
		}
	}
}

// Mutation caught: an implicit or prefix-only home rewrite makes corpus expectations machine-specific.
func TestNF17RewriteActualHomePathsIsExplicitAndExact(t *testing.T) {
	original := entry{Paths: []string{"/home/u/.claude/projects/p/memory/note.md", "/home/user/adjacent"}}
	if got := rewriteActualHomePaths(original, "/actual/home"); !reflect.DeepEqual(got.Paths, original.Paths) {
		t.Fatalf("disabled actual-home rewrite changed paths to %q", got.Paths)
	}
	original.RewriteActualHomePaths = true
	got := rewriteActualHomePaths(original, "/actual/home")
	want := []string{"/actual/home/.claude/projects/p/memory/note.md", "/home/user/adjacent"}
	if !reflect.DeepEqual(got.Paths, want) {
		t.Fatalf("enabled actual-home rewrite paths = %q, want %q", got.Paths, want)
	}
}

func TestRewriteLogicalRepoPathsIsExplicitAndTokenAware(t *testing.T) {
	physicalRoot := "/tmp/physical-repo"
	command := `> /repo/build.log; printf '%s\n' https://example.com/repo /repository /tmp/repo`

	disabled := entry{Command: command, Paths: []string{"/repo/a"}, RepoRoot: "/repo"}
	got, err := rewriteLogicalRepoPaths(disabled, physicalRoot)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != command || strings.Join(got.Paths, "|") != "/repo/a" {
		t.Fatalf("disabled materialization changed entry: command=%q paths=%v", got.Command, got.Paths)
	}

	enabled := disabled
	enabled.RewriteLogicalRepoPaths = true
	enabled.Paths = []string{"/repo/a", "/repository/b", "https://example.com/repo"}
	got, err = rewriteLogicalRepoPaths(enabled, physicalRoot)
	if err != nil {
		t.Fatal(err)
	}
	wantCommand := `> /tmp/physical-repo/build.log; printf '%s\n' https://example.com/repo /repository /tmp/repo`
	if got.Command != wantCommand {
		t.Errorf("command = %q, want %q", got.Command, wantCommand)
	}
	if want := "/tmp/physical-repo/a|/repository/b|https://example.com/repo"; strings.Join(got.Paths, "|") != want {
		t.Errorf("paths = %v, want %q", got.Paths, want)
	}

	enabled.Command = `echo "unterminated`
	if _, err := rewriteLogicalRepoPaths(enabled, physicalRoot); err == nil {
		t.Fatal("malformed opted-in command returned nil error")
	}
}
