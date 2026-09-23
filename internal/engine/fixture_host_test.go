package engine

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func setSystemTempRoot(t *testing.T, root string) {
	t.Helper()
	t.Setenv("TMPDIR", root)
	if runtime.GOOS == "windows" {
		t.Setenv("TEMP", root)
		t.Setenv("TMP", root)
	}
}

func bashFixturePath(path string) string {
	return strconv.Quote(posixHostPath(path))
}

// shellJoinedFixturePath mirrors shell parameter expansion: a slash written
// in command text remains a slash even when the seeded value is a Win32 path.
func shellJoinedFixturePath(base string, elements ...string) string {
	return strings.TrimSuffix(base, "/") + "/" + strings.Join(elements, "/")
}

// hostFrameFixture preserves the abstract fixture meaning while expressing
// adapter-owned coordinates in the running host's dialect. Bash command text
// remains POSIX-shaped; on Windows its fixture roots use MSYS drive spelling.
func hostFrameFixture(call ToolCall) ToolCall {
	if runtime.GOOS != "windows" {
		return call
	}
	call.CWD = hostFixturePath(call.CWD)
	call.RepoRoot = hostFixturePath(call.RepoRoot)
	paths := append([]string(nil), call.Paths...)
	for i, path := range paths {
		paths[i] = hostFixturePath(path)
	}
	call.Paths = paths
	for _, fixture := range []string{"/home/u", "/opt/svc", "/repo"} {
		call.Command = replaceFixturePrefix(call.Command, fixture, posixFixturePath(fixture))
	}
	return call
}

func hostFramePolicy(pol *policy.Policy) *policy.Policy {
	if runtime.GOOS != "windows" {
		return pol
	}
	copy := *pol
	copy.Slots = pol.Slots
	copy.Slots.SafeRoots = append([]string(nil), pol.Slots.SafeRoots...)
	for i, root := range copy.Slots.SafeRoots {
		copy.Slots.SafeRoots[i] = hostFixturePath(root)
	}
	return &copy
}

func evaluateHostFrameFixture(call ToolCall, pol *policy.Policy) policy.Verdict {
	return Evaluate(hostFrameFixture(call), hostFramePolicy(pol))
}

func checkPathsHostFrameFixture(call ToolCall, pol *policy.Policy) *policy.Verdict {
	return checkPaths(hostFrameFixture(call), hostFramePolicy(pol))
}

func checkBashHostFrameFixture(call ToolCall, pol *policy.Policy) *policy.Verdict {
	return checkBash(hostFrameFixture(call), hostFramePolicy(pol))
}

func checkSelfConfigHostFrameFixture(call ToolCall) *policy.Verdict {
	return checkSelfConfig(hostFrameFixture(call))
}

func checkCIInfraHostFrameFixture(call ToolCall) *policy.Verdict {
	return checkCIInfraLockfile(hostFrameFixture(call))
}

func hostFixturePath(path string) string {
	if runtime.GOOS != "windows" {
		return path
	}
	lower := strings.ToLower(path)
	if lower == "/repo" || strings.HasPrefix(lower, "/repo/") {
		relative := path[len("/repo"):]
		return filepath.Join(hostFixtureRepoRoot(), filepath.FromSlash(strings.TrimPrefix(relative, "/")))
	}
	if strings.HasPrefix(path, "/") {
		root := filepath.VolumeName(hostFixtureRepoRoot()) + string(filepath.Separator)
		return filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(path, "/")))
	}
	return path
}

func hostFixtureRepoRoot() string {
	directory, err := os.Getwd()
	if err != nil {
		panic("resolve fixture repository: " + err.Error())
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			panic("resolve fixture repository: go.mod not found")
		}
		directory = parent
	}
}

func posixFixturePath(path string) string {
	return posixHostPath(hostFixturePath(path))
}

func posixHostPath(host string) string {
	if runtime.GOOS != "windows" {
		return filepath.ToSlash(host)
	}
	volume := filepath.VolumeName(host)
	rest := strings.TrimPrefix(filepath.ToSlash(host), filepath.ToSlash(volume))
	return "/" + strings.ToLower(strings.TrimSuffix(volume, ":")) + rest
}

func outsideCommandFixturePath(name string) string {
	if runtime.GOOS != "windows" {
		return filepath.ToSlash(filepath.Join("/etc", name))
	}
	return posixHostPath(filepath.Join(outsideRepoTarget(), name))
}

func replaceFixturePrefix(input, fixture, replacement string) string {
	var output strings.Builder
	for cursor := 0; cursor < len(input); {
		relative := strings.Index(input[cursor:], fixture)
		if relative < 0 {
			output.WriteString(input[cursor:])
			break
		}
		start := cursor + relative
		end := start + len(fixture)
		output.WriteString(input[cursor:start])
		if end == len(input) || strings.ContainsRune("/\"' ;:\t\n", rune(input[end])) {
			output.WriteString(replacement)
		} else {
			output.WriteString(fixture)
		}
		cursor = end
	}
	return output.String()
}

func TestHostFrameFixtureTranslatesCoordinatesNotPolicyIntent(t *testing.T) {
	call := ToolCall{
		Tool: "Bash", Command: `cp /repo/input /home/u/output`,
		Paths: []string{"/repo/input", "/opt/svc/key.json"}, CWD: "/repo", RepoRoot: "/repo",
	}
	got := hostFrameFixture(call)
	if runtime.GOOS != "windows" {
		if got.Command != call.Command || got.CWD != call.CWD || got.RepoRoot != call.RepoRoot {
			t.Fatalf("POSIX host changed fixture frame: got %+v, want %+v", got, call)
		}
		return
	}
	repo := hostFixtureRepoRoot()
	if got.CWD != repo || got.RepoRoot != repo {
		t.Fatalf("host frame = (%q, %q), want %q", got.CWD, got.RepoRoot, repo)
	}
	wantCommand := "cp " + posixFixturePath("/repo/input") + " " + posixFixturePath("/home/u/output")
	if got.Command != wantCommand {
		t.Fatalf("command = %q, want MSYS fixture paths", got.Command)
	}
	wantOutside := filepath.Join(filepath.VolumeName(repo)+string(filepath.Separator), "opt", "svc", "key.json")
	if len(got.Paths) != 2 || got.Paths[0] != filepath.Join(repo, "input") || got.Paths[1] != wantOutside {
		t.Fatalf("native paths = %q, want Win32 fixture paths", got.Paths)
	}
}
