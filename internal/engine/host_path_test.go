package engine

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// The translation must be the identity wherever the host dialect is already
// POSIX, or the Linux and macOS paths drift without anyone noticing: every
// rule in the engine reaches containment through it.
func TestPosixHostsTranslateNothing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the dialects diverge only on windows hosts")
	}
	for _, p := range []string{"/", "/etc", "/etc/passwd", "/tmp", "/tmp/scratch", "/c/repo/x", "rel/path", "./rel"} {
		host, mapped := hostPathForPosix(p)
		if !mapped || host != p {
			t.Errorf("hostPathForPosix(%q) = (%q, %v), want (%q, true)", p, host, mapped, p)
		}
		if unmappablePosixAbsolute(p) {
			t.Errorf("unmappablePosixAbsolute(%q) = true, want false: this host is POSIX", p)
		}
		if host, ok := posixTempToHost(p); ok {
			t.Errorf("posixTempToHost(%q) = (%q, true), want no mapping: /tmp is already a host path here", p, host)
		}
	}
}

func TestWindowsHostsTranslateEachPosixFamilyOnce(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("win32 translation applies on windows hosts")
	}
	temp := filepath.Clean(os.TempDir())
	for _, c := range []struct {
		posix string
		host  string
	}{
		// Relative tokens mean the same thing in both dialects; the caller
		// joins them against cwd.
		{"rel/path", "rel/path"},
		{"./rel", "./rel"},
		// MSYS drive paths name a real Win32 location.
		{"/c", `C:\`},
		{"/c/repo/x", `C:\repo\x`},
		{"/C/repo/x", `C:\repo\x`},
		// Under Git Bash /tmp is a real writable directory.
		{"/tmp", temp},
		{"/tmp/scratch/out.txt", filepath.Join(temp, "scratch", "out.txt")},
		// An escape out of /tmp is cleaned back out of the temp root, so it
		// lands outside it and the temp seam does not authorize it.
		{"/tmp/../etc", filepath.Join(filepath.Dir(temp), "etc")},
	} {
		host, mapped := hostPathForPosix(c.posix)
		if !mapped || host != c.host {
			t.Errorf("hostPathForPosix(%q) = (%q, %v), want (%q, true)", c.posix, host, mapped, c.host)
		}
	}
	// A Win32 host addresses none of these, and saying so is what routes them
	// to the rule that owns the risk rather than folding them into the repo.
	for _, p := range []string{"/", "/etc", "/etc/passwd", "/dev/null/child", "/usr/local/bin", "/tmpfoo", "/1/x"} {
		if _, mapped := hostPathForPosix(p); mapped {
			t.Errorf("hostPathForPosix(%q) reported a host location; want unmappable", p)
		}
		if !unmappablePosixAbsolute(p) {
			t.Errorf("unmappablePosixAbsolute(%q) = false, want true", p)
		}
	}
}

// The translation reconciles two dialects, so it only applies when there are
// two. A repo root that is itself an unaddressable POSIX path means the whole
// evaluation is in POSIX coordinates -- the shape every Linux-written fixture
// has -- and folding one side of that would be the same mistranslation in the
// other direction.
//
// This is a boundary worth stating rather than discovering: on a Windows host
// a POSIX repo root keeps POSIX containment, and only a host-shaped root (what
// an adapter actually supplies there) gets the Win32 reading. #255 is the
// mixed case, and the mixed case is the one production hits.
func TestTranslationAppliesOnlyToAMixedFrame(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("one frame cannot be mixed on a POSIX host")
	}
	posixFrame := func(command string) policy.Verdict {
		pol := pathPol()
		pol.Slots.SafeRoots = nil
		return Evaluate(ToolCall{Plane: "claude", Tool: "Bash", NativeTool: "Bash",
			Capability: policy.CapabilityCommand, Command: command, CWD: "/repo", RepoRoot: "/repo"}, pol)
	}
	if v := posixFrame(`echo x > /repo/build.log`); v.Decision != policy.Allow {
		t.Errorf("posix-rooted in-repo redirect -> %+v, want allow: both sides are POSIX", v)
	}
	if v := posixFrame(`rm -rf /etc`); v.Decision != policy.Deny {
		t.Errorf("posix-rooted out-of-repo delete -> %+v, want deny: containment still applies", v)
	}
	// The same command against the host-shaped root an adapter supplies on
	// this platform is the mixed frame, and gets the Win32 reading.
	if v := evalDialect(t, `echo x > /repo/build.log`); v.Decision == policy.Allow {
		t.Errorf("host-rooted POSIX redirect -> allow, want non-allow: /repo is not inside C:\repo")
	}
}
