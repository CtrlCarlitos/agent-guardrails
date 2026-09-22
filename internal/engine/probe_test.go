package engine

import (
	"runtime"
	"testing"
)

func TestHostProbePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Win32 absolute paths
		if p, ok := hostProbePath(`C:\Users`); !ok || p != `C:\Users` {
			t.Errorf("hostProbePath(`C:\\Users`) = (%q, %v), want (`C:\\Users`, true)", p, ok)
		}
		// MSYS/Git-Bash drive paths
		if p, ok := hostProbePath(`/c/Users`); !ok || p != `C:\Users` {
			t.Errorf("hostProbePath(`/c/Users`) = (%q, %v), want (`C:\\Users`, true)", p, ok)
		}
		if p, ok := hostProbePath(`/d/repo/src`); !ok || p != `D:\repo\src` {
			t.Errorf("hostProbePath(`/d/repo/src`) = (%q, %v), want (`D:\\repo\\src`, true)", p, ok)
		}
		// Non-drive POSIX paths must not be probeable on Windows
		if p, ok := hostProbePath(`/etc`); ok {
			t.Errorf("hostProbePath(`/etc`) = (%q, %v), want false", p, ok)
		}
		if p, ok := hostProbePath(`/usr/bin`); ok {
			t.Errorf("hostProbePath(`/usr/bin`) = (%q, %v), want false", p, ok)
		}
		if p, ok := hostProbePath(`/dev/null`); ok {
			t.Errorf("hostProbePath(`/dev/null`) = (%q, %v), want false", p, ok)
		}
	} else {
		// On Unix, all paths are probeable as-is
		if p, ok := hostProbePath(`/etc`); !ok || p != `/etc` {
			t.Errorf("hostProbePath(`/etc`) = (%q, %v), want (`/etc`, true)", p, ok)
		}
		if p, ok := hostProbePath(`/c/Users`); !ok || p != `/c/Users` {
			t.Errorf("hostProbePath(`/c/Users`) = (%q, %v), want (`/c/Users`, true)", p, ok)
		}
	}
}
