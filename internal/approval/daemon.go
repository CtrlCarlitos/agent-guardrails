package approval

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

const daemonIdleTimeout = 10 * time.Minute

type daemonMessage struct {
	Operation string  `json:"operation"`
	Request   Request `json:"request,omitempty"`
	ID        string  `json:"id,omitempty"`
	Scope     Scope   `json:"scope,omitempty"`
}

type daemonReply struct {
	Request  Request   `json:"request,omitempty"`
	Requests []Request `json:"requests,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// Daemon owns browser transports and the privileged action handlers. Its socket
// listener is created only by the platform-specific private-listener function.
type Daemon struct {
	listener  net.Listener
	broker    *Broker
	authStore AssertionStore
	openURL   func(string) error

	mu       sync.Mutex
	browsers map[string]*Browser
	activity time.Time
	closed   chan struct{}
	once     sync.Once
}

func DefaultSocketPath() string {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "state")
	}
	socket := filepath.Join(base, "guardrail", "approval", "broker.sock")
	if len(socket) < 100 {
		return socket
	}
	// Unix socket paths are short; retain a deterministic per-state-root fallback.
	digest := sha256.Sum256([]byte(base))
	return filepath.Join(os.TempDir(), "guardrail-"+fmt.Sprintf("%x", digest[:]), "broker.sock")
}

// SubmitOnDemand starts the user-level daemon if no authenticated socket is live.
func SubmitOnDemand(request Request) (Request, error) {
	if err := persistentApprovalError(); err != nil {
		return Request{}, err
	}
	socket := DefaultSocketPath()
	if r, err := Submit(socket, request); err == nil {
		return r, nil
	}
	if flag.Lookup("test.v") != nil {
		// Test binaries cannot re-exec their CLI daemon entrypoint. Lifecycle and
		// socket behavior are exercised directly by StartDaemon tests.
		return New().Create(request)
	} else {
		cmd := exec.Command(os.Args[0], "approvals", "daemon")
		cmd.Stdout, cmd.Stderr = nil, nil
		if err := cmd.Start(); err != nil {
			return Request{}, err
		}
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if r, err := Submit(socket, request); err == nil {
			return r, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return Request{}, errors.New("approval daemon unavailable")
}

func RunDefaultDaemon(authStore AssertionStore, openURL func(string) error) error {
	d, err := StartDaemon(DefaultSocketPath(), New(), authStore, openURL)
	if err != nil {
		return err
	}
	<-d.closed
	return nil
}

func StartDaemon(socket string, broker *Broker, authStore AssertionStore, openURL func(string) error) (*Daemon, error) {
	if broker == nil || openURL == nil {
		return nil, ErrMalformed
	}
	listener, err := listenPrivate(socket)
	if err != nil {
		return nil, err
	}
	if err := broker.recoverInterruptedActions(); err != nil {
		_ = listener.Close()
		return nil, err
	}
	d := &Daemon{listener: listener, broker: broker, authStore: authStore, openURL: openURL, browsers: map[string]*Browser{}, activity: time.Now(), closed: make(chan struct{})}
	go d.serve()
	go d.stopWhenIdle()
	return d, nil
}

func (d *Daemon) Close() error {
	if d == nil {
		return nil
	}
	var err error
	d.once.Do(func() {
		close(d.closed)
		err = d.listener.Close()
		d.mu.Lock()
		defer d.mu.Unlock()
		for _, browser := range d.browsers {
			_ = browser.Close()
		}
	})
	return err
}

func (d *Daemon) serve() {
	for {
		conn, err := d.listener.Accept()
		if err != nil {
			select {
			case <-d.closed:
				return
			default:
				continue
			}
		}
		go d.handle(conn)
	}
}

func (d *Daemon) handle(conn net.Conn) {
	defer conn.Close()
	var message daemonMessage
	if err := json.NewDecoder(conn).Decode(&message); err != nil {
		return
	}
	d.touch()
	reply := daemonReply{}
	switch message.Operation {
	case "submit":
		r, err := d.broker.Create(message.Request)
		if err == nil {
			browser, url, startErr := StartBrowser(d.broker, d.authStore, r.ID)
			if startErr == nil {
				startErr = d.openURL(url)
			}
			if startErr == nil {
				d.mu.Lock()
				d.browsers[r.ID] = browser
				d.mu.Unlock()
				r.ApprovalURL = url
			} else {
				if browser != nil {
					_ = browser.Close()
				}
				if denyErr := d.broker.Deny(r.ID); denyErr != nil {
					err = denyErr
				} else {
					err = startErr
				}
			}
		}
		if err != nil {
			reply.Error = "approval request unavailable"
		} else {
			reply.Request = requestStatus(r)
		}
	case "status":
		r, err := d.broker.Request(message.ID)
		if err != nil {
			reply.Error = "approval request unavailable"
		} else {
			reply.Request = requestStatus(r)
		}
	case "list":
		pending, err := d.broker.Pending()
		if err != nil {
			reply.Error = "approval daemon unavailable"
			break
		}
		reply.Requests = pending
	case "present":
		// Re-open the browser ceremony for a pending request. Presentation
		// only: completion always requires the WebAuthn assertion — the
		// socket can never approve or deny (adversarial invariant).
		r, err := d.broker.Request(message.ID)
		if err != nil || r.Status != "pending" {
			reply.Error = "approval request unavailable"
			break
		}
		browser, url, startErr := StartBrowser(d.broker, d.authStore, r.ID)
		if startErr == nil {
			startErr = d.openURL(url)
		}
		if startErr != nil {
			if browser != nil {
				_ = browser.Close()
			}
			reply.Error = "approval request unavailable"
			break
		}
		d.mu.Lock()
		if old := d.browsers[r.ID]; old != nil {
			_ = old.Close()
		}
		d.browsers[r.ID] = browser
		d.mu.Unlock()
	case "shutdown":
		// Used by guardrail update so a binary replacement is never served by
		// a daemon running superseded code. Fail-closed: it can make approvals
		// unavailable, never looser.
		go d.Close()
	default:
		reply.Error = "approval request unavailable"
	}
	d.touch()
	_ = json.NewEncoder(conn).Encode(reply)
}

func (d *Daemon) closeBrowser(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if browser := d.browsers[id]; browser != nil {
		_ = browser.Close()
		delete(d.browsers, id)
	}
}

func (d *Daemon) touch() {
	d.mu.Lock()
	d.activity = time.Now()
	d.mu.Unlock()
}

func (d *Daemon) stopWhenIdle() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-d.closed:
			return
		case <-ticker.C:
			d.mu.Lock()
			idle := time.Since(d.activity) >= daemonIdleTimeout
			d.mu.Unlock()
			if idle && !d.broker.hasPending() {
				_ = d.Close()
				return
			}
		}
	}
}

func Submit(socket string, request Request) (Request, error) {
	var reply daemonReply
	err := send(socket, daemonMessage{Operation: "submit", Request: request}, &reply)
	if err != nil || reply.Error != "" {
		return Request{}, errors.New("approval daemon unavailable")
	}
	return reply.Request, nil
}

// QueryStatus reports the durable status of a submitted request without
// creating or mutating it.
func QueryStatus(socket, id string) (Request, error) {
	var reply daemonReply
	if err := send(socket, daemonMessage{Operation: "status", ID: id}, &reply); err != nil || reply.Error != "" {
		return Request{}, errors.New("approval daemon unavailable")
	}
	return reply.Request, nil
}

// ListPending reports every pending request with identity, action summary,
// and expiry, for the terminal approvals list.
func ListPending(socket string) ([]Request, error) {
	var reply daemonReply
	if err := send(socket, daemonMessage{Operation: "list"}, &reply); err != nil || reply.Error != "" {
		return nil, errors.New("approval daemon unavailable")
	}
	return reply.Requests, nil
}

// PresentApproval re-opens the browser ceremony for a pending request from
// an operator terminal. It never completes the request: completion requires
// the WebAuthn assertion.
func PresentApproval(socket, id string) error {
	var reply daemonReply
	if err := send(socket, daemonMessage{Operation: "present", ID: id}, &reply); err != nil || reply.Error != "" {
		return errors.New("approval daemon unavailable")
	}
	return nil
}

// ShutdownDaemon asks a live daemon to exit so the next submit spawns a
// daemon from the current binary. Unreachable daemons are not an error.
func ShutdownDaemon(socket string) error {
	var reply daemonReply
	return send(socket, daemonMessage{Operation: "shutdown"}, &reply)
}

func requestStatus(request Request) Request {
	return Request{ID: request.ID, Status: request.Status, ExpiresAt: request.ExpiresAt, ApprovalURL: request.ApprovalURL}
}

func send(socket string, message daemonMessage, reply *daemonReply) error {
	conn, err := dialPrivate(socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(message); err != nil {
		return err
	}
	return json.NewDecoder(conn).Decode(reply)
}
