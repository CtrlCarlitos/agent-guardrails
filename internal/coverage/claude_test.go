package coverage

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// A synthetic bundle with the two structures the scanner anchors on — a
// tool-name list and a legacy alias map — surrounded by the kind of noise a
// real bundle carries (HTML element lists, exception names, a version line).
const syntheticBundle = `// Version: 2.1.275
var noise=["HTMLDivElement","HTMLSpanElement","HTMLTableElement","SVGElement"];
var errs=["ValidationException","ThrottlingException","AccessDeniedException"];
var tools=["Bash","Read","Write","Edit","Glob","Grep","NotebookEdit","WebFetch","WebSearch","Task","TodoWrite","Skill","AskUserQuestion","ToolSearch","SendUserMessage","FutureToolA","FutureToolB"];
var aliases={KillBash:"TaskStop",BashOutput:"TaskOutput",AgentOutput:"TaskOutput",ListPeers:"ListAgents",Brief:"SendUserMessage",ReadMcpResourceDir:"ReadMcpResourceDirTool"};
var langs=["Go","Rust","Python"];
var mixed=["Bash","Zephir","Wren"];
`

func contracted(name string) bool {
	switch name {
	case "Bash", "Read", "Write", "Edit", "Glob", "Grep", "NotebookEdit", "WebFetch", "WebSearch",
		"Task", "TodoWrite", "Skill", "AskUserQuestion", "ToolSearch", "TaskStop", "TaskOutput",
		"ListAgents", "ReadMcpResourceDirTool", "PowerShell", "SendUserMessage":
		return true
	}
	return false
}

func TestScanClaudeBundleFindsUncontractedToolsFromToolLists(t *testing.T) {
	inv, err := ScanClaudeBundle(strings.NewReader(syntheticBundle), contracted)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Version != "2.1.275" {
		t.Fatalf("version = %q", inv.Version)
	}
	if got := strings.Join(inv.Uncontracted, ","); got != "FutureToolA,FutureToolB" {
		t.Fatalf("uncontracted = %q", got)
	}
	// Noise lists (no contracted majority) never contribute candidates.
	for _, name := range inv.Runtime {
		if strings.HasPrefix(name, "HTML") || strings.HasSuffix(name, "Exception") || name == "Zephir" || name == "Wren" {
			t.Fatalf("noise leaked into the runtime inventory: %q", name)
		}
	}
}

func TestScanClaudeBundleReadsLegacyAliasMap(t *testing.T) {
	inv, err := ScanClaudeBundle(strings.NewReader(syntheticBundle), contracted)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"KillBash": "TaskStop", "BashOutput": "TaskOutput", "AgentOutput": "TaskOutput", "ListPeers": "ListAgents", "Brief": "SendUserMessage", "ReadMcpResourceDir": "ReadMcpResourceDirTool"}
	if len(inv.Aliases) != len(want) {
		t.Fatalf("aliases = %v, want %v", inv.Aliases, want)
	}
	for k, v := range want {
		if inv.Aliases[k] != v {
			t.Fatalf("alias %s = %q, want %q", k, inv.Aliases[k], v)
		}
	}
	// An alias whose target is uncontracted is itself an uncontracted entry
	// point, reported through its target, not as a separate name.
	for _, name := range inv.Uncontracted {
		if name == "Brief" {
			t.Fatal("alias key reported as its own uncontracted tool")
		}
	}
}

func TestScanClaudeBundleReportsStaleContractEntries(t *testing.T) {
	inv, err := ScanClaudeBundle(strings.NewReader(syntheticBundle), contracted)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(inv.Stale(contractedNames()), ","); got != "PowerShell" {
		t.Fatalf("stale = %q, want PowerShell (contracted, absent from the bundle)", got)
	}
}

func contractedNames() []string {
	return []string{"Bash", "Read", "Write", "Edit", "Glob", "Grep", "NotebookEdit", "WebFetch", "WebSearch",
		"Task", "TodoWrite", "Skill", "AskUserQuestion", "ToolSearch", "TaskStop", "TaskOutput",
		"ListAgents", "ReadMcpResourceDirTool", "PowerShell"}
}

func TestScanClaudeBundleWithoutAnchorsIsEmptyNotAnError(t *testing.T) {
	inv, err := ScanClaudeBundle(strings.NewReader(`var x=["HTMLDivElement","HTMLSpanElement","SVGElement"];`), contracted)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Runtime) != 0 || len(inv.Uncontracted) != 0 || inv.Version != "" {
		t.Fatalf("inventory = %+v, want empty", inv)
	}
}

func TestClaudeBundlePathResolvesSymlinkOnPATH(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "versions", "2.1.275")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte(syntheticBundle), 0o755); err != nil {
		t.Fatal(err)
	}
	testenv.RequireSymlink(t, real, filepath.Join(dir, testenv.ExecutableName("claude")))
	t.Setenv("PATH", dir)
	got, err := ClaudeBundlePath()
	if err != nil {
		t.Fatal(err)
	}
	want := real
	if resolved, err := filepath.EvalSymlinks(real); err == nil {
		want = resolved // darwin: t.TempDir spelling resolves to /private/var
	}
	if got != want {
		t.Fatalf("bundle = %q, want %q", got, want)
	}
}

func TestClaudeBundlePathMissingIsAnError(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir()) // no installer versions dir either
	if _, err := ClaudeBundlePath(); err == nil {
		t.Fatal("expected an error without claude on PATH")
	}
}

// On Windows the native installer's ~/.local/bin/claude.exe is a launcher,
// not a symlink to the versioned bundle, and an npm-global install puts a
// claude.cmd shim on PATH. Neither carries the tool lists. The resolver
// falls back to the installer's versions directory ($XDG_DATA_HOME or
// ~/.local/share, then claude/versions) and takes the newest bundle there.
func TestClaudeBundlePathWindowsLauncherFallsBackToVersionsDir(t *testing.T) {
	bin := t.TempDir()
	launcher := filepath.Join(bin, claudeExe())
	if err := os.WriteFile(launcher, []byte("@echo off\r\nnode %~dp0\\cli.js %*\r\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	versions := filepath.Join(data, "claude", "versions")
	if err := os.MkdirAll(versions, 0o755); err != nil {
		t.Fatal(err)
	}
	older := filepath.Join(versions, "2.1.270")
	newest := filepath.Join(versions, "2.1.275")
	for _, p := range []string{older, newest} {
		if err := os.WriteFile(p, []byte(syntheticBundle), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ClaudeBundlePath()
	if err != nil {
		t.Fatal(err)
	}
	if got != newest {
		t.Fatalf("bundle = %q, want the newest versions entry %q", got, newest)
	}
}

// claudeExe is the launcher name LookPath finds on this host: Windows
// resolves PATH entries only with a PATHEXT extension.
func claudeExe() string {
	if runtime.GOOS == "windows" {
		return "claude.exe"
	}
	return "claude"
}

func TestClaudeBundlePathWindowsPrefersAPATHEntryThatIsABundle(t *testing.T) {
	bin := t.TempDir()
	bundle := filepath.Join(bin, claudeExe())
	if err := os.WriteFile(bundle, []byte(syntheticBundle), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("XDG_DATA_HOME", t.TempDir()) // no versions dir at all
	got, err := ClaudeBundlePath()
	if err != nil {
		t.Fatal(err)
	}
	// Windows may spell a temp dir in 8.3 short form while EvalSymlinks
	// returns the long form; compare identity, not text.
	want, _ := os.Stat(bundle)
	have, statErr := os.Stat(got)
	if statErr != nil || !os.SameFile(want, have) {
		t.Fatalf("bundle = %q, want the PATH entry %q", got, bundle)
	}
}

func TestClaudeBundlePathWindowsNamesBothPlacesWhenNeitherHasABundle(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, claudeExe()), []byte("shim"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	_, err := ClaudeBundlePath()
	if err == nil || !strings.Contains(err.Error(), "versions") {
		t.Fatalf("err = %v, want an error naming the versions directory", err)
	}
}
