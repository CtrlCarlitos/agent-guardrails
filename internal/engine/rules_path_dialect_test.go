package engine

import (
	"runtime"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// ToolCall.CWD and RepoRoot are Win32 host paths; a Bash command's tokens are
// POSIX. `filepath` reads a POSIX absolute path as relative on Windows --
// measured, filepath.IsAbs("/etc") is false and filepath.Join(`C:\repo`,
// "/etc") is `C:\repo\etc` -- so every POSIX absolute path silently became
// repo-relative, landed inside the repo root, and was authorized (#255).
//
// `/` became the repo itself, which is why `rm -rf /` read as a delete of the
// working tree's own root and passed containment.
//
// These commands are valid POSIX shell input, reachable on Windows through Git
// Bash, so the verdict must not depend on which host is evaluating them. Each
// case therefore asserts one expectation for every platform: on Linux the two
// dialects coincide and these already hold, which makes Linux the reference.

func dialectRepoRoot() string {
	if runtime.GOOS == "windows" {
		return `C:\repo`
	}
	return "/repo"
}

// otherDialectRepoRoot is a second host-shaped repository root, for the cases
// that must show a grant or an authorization does not travel between repos.
func otherDialectRepoRoot() string {
	if runtime.GOOS == "windows" {
		return `C:\other`
	}
	return "/other"
}

func evalDialect(t *testing.T, command string) policy.Verdict {
	t.Helper()
	root := dialectRepoRoot()
	pol := pathPol()
	pol.Slots.SafeRoots = nil
	return Evaluate(ToolCall{Plane: "claude", Tool: "Bash", NativeTool: "Bash",
		Capability: policy.CapabilityCommand, Command: command, CWD: root, RepoRoot: root}, pol)
}

// The case that needs no wrapper, no redirect and no container.
func TestPosixRootDeleteDeniesOnEveryHost(t *testing.T) {
	for _, command := range []string{
		`rm -rf /`,
		`rm -fr /`,
		`/bin/bash -c 'rm -rf /'`,
		`sh -c "rm -rf /"`,
		`rm -rf /etc`,
	} {
		v := evalDialect(t, command)
		if v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny: a POSIX absolute path is not inside a host repo root", command, v)
		}
	}
}

// Writes outside the repository must reach the rule that owns them rather
// than being folded into the repo by a dialect mismatch.
func TestPosixOutOfRepoWritesDoNotLandInsideTheRepo(t *testing.T) {
	for _, command := range []string{
		`echo x > /etc/passwd`,
		`echo x > /etc/CLAUDE.md`,
		`cp /repo/x /dev/null/child`,
		`echo x >/dev/null/child`,
	} {
		if v := evalDialect(t, command); v.Decision == policy.Allow {
			t.Errorf("%q -> allow, want ask or deny: the destination is outside the repository", command)
		}
	}
}

// ADR-0023's seam must survive: an exact standard device is still a legal
// redirect target and must not regress into an ask.
func TestExactStandardDevicesStayAllowed(t *testing.T) {
	for _, command := range []string{
		`echo x > /dev/null`,
		`echo x > /dev/stdout`,
		`echo x 2> /dev/stderr`,
	} {
		if v := evalDialect(t, command); v.Decision != policy.Allow {
			t.Errorf("%q -> %+v, want allow: an exact standard device is ADR-0023's accepted seam", command, v)
		}
	}
}

// The mappable case. A Git Bash drive path names a real Win32 location, and
// posixDriveToWin32 already translates it lexically, so in-repo work written
// in POSIX form stays ordinary work.
func TestMappableDrivePathsResolveIntoTheRepo(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("drive mapping applies on windows hosts")
	}
	for _, command := range []string{
		`rm -rf /c/repo/build`,
		`echo x > /c/repo/out.txt`,
	} {
		if v := evalDialect(t, command); v.Decision != policy.Allow {
			t.Errorf("%q -> %+v, want allow: /c/repo maps to C:\\repo, which is the repository", command, v)
		}
	}
	// The same mapping must not authorize a drive path outside the repo.
	if v := evalDialect(t, `rm -rf /c/Windows/System32`); v.Decision != policy.Deny {
		t.Errorf("/c/Windows/System32 -> %+v, want deny: mappable is not the same as authorized", v)
	}
}

// System temp semantics after the lexical mapping: descendants are an
// authorized write seam, the root itself and escapes out of it are not.
func TestPosixTempRootKeepsItsWriteSeam(t *testing.T) {
	for _, command := range []string{
		`rm -rf /tmp/scratch`,
		`echo x > /tmp/scratch/out.txt`,
	} {
		if v := evalDialect(t, command); v.Decision != policy.Allow {
			t.Errorf("%q -> %+v, want allow: a temp descendant is an authorized write seam", command, v)
		}
	}
	for _, command := range []string{
		`rm -rf /tmp`,
		`rm -rf /tmp/../etc`,
	} {
		if v := evalDialect(t, command); v.Decision == policy.Allow {
			t.Errorf("%q -> allow, want non-allow: the temp root itself and escapes out of it are protected", command)
		}
	}
}

// In-repo work must not become collateral damage. This is the test that
// fails if the translation is too aggressive, and it is the one that matters
// most for whether the rule is usable.
func TestRepoRelativeWorkStaysAllowed(t *testing.T) {
	for _, command := range []string{
		`rm -rf ./build`,
		`rm -rf build`,
		`echo x > out.txt`,
		`echo x > ./sub/out.txt`,
		`cat ./README.md`,
	} {
		if v := evalDialect(t, command); v.Decision != policy.Allow {
			t.Errorf("%q -> %+v, want allow: ordinary in-repo work", command, v)
		}
	}
}
