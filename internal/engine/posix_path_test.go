package engine

import (
	"testing"
)

// TestPosixIsAbs verifies that posixIsAbs uses POSIX grammar ('/' prefix)
// and not Win32 grammar (drive letters, UNC).  Must pass on every host OS.
func TestPosixIsAbs(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/etc", true},
		{"/", true},
		{"/dev/null", true},
		{"/c/repo", true}, // Git Bash drive path — POSIX-absolute
		{".", false},
		{"..", false},
		{"./foo", false},
		{"../foo", false},
		{"foo/bar", false},
		{"", false},
		{`C:\Users`, false},       // Win32 absolute — not POSIX
		{`C:/Users`, false},       // Win32 with forward slash — not POSIX
		{`\\server\share`, false}, // UNC — not POSIX
	}
	for _, tt := range cases {
		if got := posixIsAbs(tt.path); got != tt.want {
			t.Errorf("posixIsAbs(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// TestPosixClean verifies POSIX lexical normalization using '/' separator.
// On Windows filepath.Clean would rewrite to backslashes; posixClean must not.
func TestPosixClean(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"/dev/./null", "/dev/null"},
		{"/dev/null", "/dev/null"},
		{"/etc/../etc/passwd", "/etc/passwd"},
		{"foo//bar", "foo/bar"},
		{"/", "/"},
		{".", "."},
		{"", "."},
	}
	for _, tt := range cases {
		if got := posixClean(tt.input); got != tt.want {
			t.Errorf("posixClean(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestPosixJoin verifies joining uses '/' on every host.
func TestPosixJoin(t *testing.T) {
	cases := []struct {
		elem []string
		want string
	}{
		{[]string{"/etc", "ssl"}, "/etc/ssl"},
		{[]string{"/repo", "src", "main.go"}, "/repo/src/main.go"},
		{[]string{".", "foo"}, "foo"},
		{[]string{"/base", "../sibling"}, "/sibling"},
	}
	for _, tt := range cases {
		if got := posixJoin(tt.elem...); got != tt.want {
			t.Errorf("posixJoin(%v) = %q, want %q", tt.elem, got, tt.want)
		}
	}
}

// TestPosixSplitList verifies POSIX ':' separation, not Win32 ';'.
func TestPosixSplitList(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"/etc:/usr/local", []string{"/etc", "/usr/local"}},
		{"/single", []string{"/single"}},
		{"", nil},
		{":/etc", []string{"", "/etc"}}, // empty entry = cwd
		{"/a:/b:/c", []string{"/a", "/b", "/c"}},
	}
	for _, tt := range cases {
		got := posixSplitList(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("posixSplitList(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("posixSplitList(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

// TestPosixStandardDevice verifies the four exempt devices and the
// canonical /dev/./null normalization, and that the exemption is exact.
func TestPosixStandardDevice(t *testing.T) {
	allow := []string{
		"/dev/null",
		"/dev/stdout",
		"/dev/stderr",
		"/dev/tty",
		"/dev/./null", // normalized to /dev/null by posixClean
	}
	for _, p := range allow {
		if !posixStandardDevice(p) {
			t.Errorf("posixStandardDevice(%q) = false, want true", p)
		}
	}

	deny := []string{
		"/dev/sda",
		"/dev/sda1",
		"/dev/null/child", // child path — not exempt
		"/dev/nullx",
		"/proc/self/fd/1",
		"NUL",     // Windows device — not in scope
		`\\.\NUL`, // Win32 device path — not in scope
		"/dev",    // the directory, not a device
		"",
		".",
	}
	for _, p := range deny {
		if posixStandardDevice(p) {
			t.Errorf("posixStandardDevice(%q) = true, want false", p)
		}
	}
}

// TestPosixDriveToWin32 verifies translation of MSYS/Git-Bash drive paths
// (/c, /c/, /c/repo) to Win32 paths (C:\, C:\repo) and strict rejection
// of non-drive POSIX root paths (/etc, /usr, etc.).
func TestPosixDriveToWin32(t *testing.T) {
	cases := []struct {
		input    string
		wantPath string
		wantOK   bool
	}{
		{"/c", `C:\`, true},
		{"/c/", `C:\`, true},
		{"/c/Users", `C:\Users`, true},
		{"/c/repo/src", `C:\repo\src`, true},
		{"/d/data", `D:\data`, true},
		{"/C/repo", `C:\repo`, true},
		{"/z/test/dir", `Z:\test\dir`, true},
		// Non-drives must be rejected
		{"/etc", "", false},
		{"/usr/bin", "", false},
		{"/dev/null", "", false},
		{"/bin/sh", "", false},
		{"/tmp", "", false},
		{"/c1", "", false},
		{"/c1/foo", "", false},
		{"/1/foo", "", false},
		{"/", "", false},
		{"", "", false},
		{".", "", false},
		{"./c/foo", "", false},
		{"c/foo", "", false},
		{`C:\foo`, "", false},
	}
	for _, tt := range cases {
		gotPath, gotOK := posixDriveToWin32(tt.input)
		if gotOK != tt.wantOK || gotPath != tt.wantPath {
			t.Errorf("posixDriveToWin32(%q) = (%q, %v), want (%q, %v)",
				tt.input, gotPath, gotOK, tt.wantPath, tt.wantOK)
		}
	}
}
