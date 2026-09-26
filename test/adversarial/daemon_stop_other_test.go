//go:build !windows

package adversarial

import "testing"

// Off Windows a running daemon does not stop the build directory from being
// removed (a file can be unlinked while it is executing), and the daemon
// idles out by itself, so there is nothing to stop here.
func stopApprovalDaemon(t *testing.T, stateRoot string) {}
