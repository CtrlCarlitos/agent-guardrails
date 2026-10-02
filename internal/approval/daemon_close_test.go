package approval

import (
	"net"
	"testing"
	"time"
)

// #504: on windows-latest CI, TestDefaultDaemonSupportsLongStateDirectory hung
// for 10 minutes in Daemon.Close: go-winio's pipe listener Close sends one
// close signal and then waits for the listener goroutine forever. If that
// goroutine consumes the signal inside a pending connect that then ends with
// an error other than ErrPipeListenerClosed, it loops back and never exits.
// Daemon.Close now waits a bounded time for the platform listener.

type stuckListener struct{ release chan struct{} }

func (l stuckListener) Accept() (net.Conn, error) { <-l.release; return nil, net.ErrClosed }
func (l stuckListener) Close() error              { <-l.release; return nil }
func (l stuckListener) Addr() net.Addr            { return &net.UnixAddr{Name: "stuck", Net: "unix"} }

func TestDaemonCloseIsBoundedWhenTheListenerHangs(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	d := &Daemon{listener: stuckListener{release: release}, broker: New(), browsers: map[string]*Browser{}, closed: make(chan struct{})}

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- d.Close() }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Close reported success although the listener never closed")
		}
		if elapsed := time.Since(start); elapsed > daemonListenerCloseTimeout+5*time.Second {
			t.Errorf("Close took %v", elapsed)
		}
	case <-time.After(daemonListenerCloseTimeout + 10*time.Second):
		t.Fatal("Daemon.Close blocked on a listener that never closes")
	}
	select {
	case <-d.closed:
	default:
		t.Error("the daemon was not marked closed")
	}
}
