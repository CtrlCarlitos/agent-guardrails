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
	Request Request `json:"request,omitempty"`
	Error   string  `json:"error,omitempty"`
}

// Daemon owns browser transports and the privileged action handlers. Its socket
// listener is created only by the platform-specific private-listener function.
type Daemon struct {
	listener net.Listener
	broker   *Broker
	openURL  func(string) error

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

func RunDefaultDaemon(openURL func(string) error) error {
	d, err := StartDaemon(DefaultSocketPath(), New(), openURL)
	if err != nil {
		return err
	}
	<-d.closed
	return nil
}

func StartDaemon(socket string, broker *Broker, openURL func(string) error) (*Daemon, error) {
	if broker == nil || openURL == nil {
		return nil, ErrMalformed
	}
	listener, err := listenPrivate(socket)
	if err != nil {
		return nil, err
	}
	d := &Daemon{listener: listener, broker: broker, openURL: openURL, browsers: map[string]*Browser{}, activity: time.Now(), closed: make(chan struct{})}
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
			browser, url, startErr := StartBrowser(d.broker, r.ID)
			if startErr != nil {
				err = startErr
			} else if err = d.openURL(url); err == nil {
				d.mu.Lock()
				d.browsers[r.ID] = browser
				d.mu.Unlock()
			} else {
				_ = browser.Close()
			}
		}
		if err != nil {
			if r.ID != "" {
				_ = d.broker.Deny(r.ID)
			}
			reply.Error = "approval request unavailable"
		} else {
			reply.Request = r
		}
	case "approve":
		if err := d.broker.Approve(message.ID, message.Scope); err != nil {
			reply.Error = "approval request unavailable"
		} else {
			d.closeBrowser(message.ID)
		}
	case "deny":
		if err := d.broker.Deny(message.ID); err != nil {
			reply.Error = "approval request unavailable"
		} else {
			d.closeBrowser(message.ID)
		}
	case "request":
		r, err := d.broker.Request(message.ID)
		if err != nil {
			reply.Error = "approval request unavailable"
		} else {
			reply.Request = r
		}
	default:
		reply.Error = "approval request unavailable"
	}
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

func Approve(socket, id string, scope Scope) error {
	var reply daemonReply
	if err := send(socket, daemonMessage{Operation: "approve", ID: id, Scope: scope}, &reply); err != nil || reply.Error != "" {
		return errors.New("approval daemon unavailable")
	}
	return nil
}

func Deny(socket, id string) error {
	var reply daemonReply
	if err := send(socket, daemonMessage{Operation: "deny", ID: id}, &reply); err != nil || reply.Error != "" {
		return errors.New("approval daemon unavailable")
	}
	return nil
}

func Lookup(socket, id string) (Request, error) {
	var reply daemonReply
	if err := send(socket, daemonMessage{Operation: "request", ID: id}, &reply); err != nil || reply.Error != "" {
		return Request{}, errors.New("approval daemon unavailable")
	}
	return reply.Request, nil
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
