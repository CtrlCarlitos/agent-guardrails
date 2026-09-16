// Package approval owns operator-only approval requests.
package approval

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"sync"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/session"
)

const (
	requestSessionID = "guardrail-approval-broker-v1"
	requestTTL       = 5 * time.Minute
	maxRequests      = 128
)

type Scope string

const (
	Allow       Scope = "allow"
	OnceScope   Scope = "once"
	RepoScope   Scope = "repo"
	GlobalScope Scope = "global"
	DenyScope   Scope = "deny"
)

var (
	ErrNotFound  = errors.New("approval request not found")
	ErrConsumed  = errors.New("approval request already completed")
	ErrExpired   = errors.New("approval request expired")
	ErrScope     = errors.New("approval scope does not match request")
	ErrMalformed = errors.New("malformed approval request")

	actionsMu sync.RWMutex
	actions   = map[string]func(Request) error{}
)

type Request struct {
	ID         string
	Plane      string
	SessionID  string
	RepoRoot   string
	Host       string
	Scope      Scope
	Reason     string
	Action     string
	Parameters map[string]string
	ExpiresAt  time.Time
	Status     string
}

type Broker struct{ now func() time.Time }

func New() *Broker { return &Broker{now: time.Now} }

func StatePath() string { return session.Path(requestSessionID) }

// RegisterAction makes a small, trusted operation available to broker approval.
// It is intentionally process-local: agents cannot register actions through input.
func RegisterAction(name string, handler func(Request) error) {
	actionsMu.Lock()
	defer actionsMu.Unlock()
	if handler == nil {
		delete(actions, name)
		return
	}
	actions[name] = handler
}

func (b *Broker) Create(r Request) (Request, error) {
	if b == nil || b.now == nil {
		return Request{}, ErrMalformed
	}
	if err := validateRequest(r); err != nil {
		return Request{}, err
	}
	if r.ID == "" {
		id, err := randomID()
		if err != nil {
			return Request{}, err
		}
		r.ID = id
	}
	if r.ExpiresAt.IsZero() {
		r.ExpiresAt = b.now().UTC().Add(requestTTL)
	} else if r.ExpiresAt.After(b.now().UTC().Add(requestTTL)) {
		return Request{}, ErrMalformed
	}
	r.ExpiresAt = r.ExpiresAt.UTC()
	r.Status = "pending"
	record := durable(r)
	err := session.Transaction(requestSessionID, func(st *session.State) error {
		if st.ApprovalRequests == nil {
			st.ApprovalRequests = make(map[string]session.ApprovalRequest)
		}
		prune(st.ApprovalRequests, b.now().UTC())
		if len(st.ApprovalRequests) >= maxRequests {
			return errors.New("approval request store is full")
		}
		if _, exists := st.ApprovalRequests[r.ID]; exists {
			return errors.New("approval request identity collision")
		}
		st.ApprovalRequests[r.ID] = record
		return nil
	})
	return r, err
}

func (b *Broker) Request(id string) (Request, error) {
	var out Request
	err := session.Transaction(requestSessionID, func(st *session.State) error {
		if st.ApprovalRequests == nil {
			return ErrNotFound
		}
		prune(st.ApprovalRequests, b.now().UTC())
		r, ok := st.ApprovalRequests[id]
		if !ok {
			return ErrNotFound
		}
		out = restore(r)
		return nil
	})
	return out, err
}

func (b *Broker) Approve(id string, scope Scope) error {
	var request Request
	err := session.Transaction(requestSessionID, func(st *session.State) error {
		r, err := pending(st, id, scope, b.now().UTC())
		if err != nil {
			return err
		}
		r.Status = "executing"
		st.ApprovalRequests[id] = r
		request = restore(r)
		return nil
	})
	if err != nil {
		return err
	}
	if request.Action == "" {
		return b.complete(id, "approved")
	}
	actionsMu.RLock()
	handler := actions[request.Action]
	actionsMu.RUnlock()
	if handler == nil || handler(request) != nil {
		_ = b.complete(id, "denied")
		return errors.New("approved action could not be completed")
	}
	return b.complete(id, "completed")
}

func (b *Broker) Deny(id string) error { return b.transition(id, "denied") }

func (b *Broker) Expire(id string) error { return b.transition(id, "expired") }

func (b *Broker) complete(id, status string) error { return b.transition(id, status) }

func (b *Broker) transition(id, status string) error {
	return session.Transaction(requestSessionID, func(st *session.State) error {
		r, ok := st.ApprovalRequests[id]
		if !ok {
			return ErrNotFound
		}
		if r.Status != "pending" && r.Status != "executing" {
			return ErrConsumed
		}
		r.Status = status
		st.ApprovalRequests[id] = r
		return nil
	})
}

func pending(st *session.State, id string, scope Scope, now time.Time) (session.ApprovalRequest, error) {
	r, ok := st.ApprovalRequests[id]
	if !ok {
		return session.ApprovalRequest{}, ErrNotFound
	}
	if r.Status != "pending" {
		return session.ApprovalRequest{}, ErrConsumed
	}
	if !r.ExpiresAt.After(now) {
		r.Status = "expired"
		st.ApprovalRequests[id] = r
		return session.ApprovalRequest{}, ErrExpired
	}
	if Scope(r.Scope) != scope {
		return session.ApprovalRequest{}, ErrScope
	}
	return r, nil
}

func validateRequest(r Request) error {
	if r.Plane == "" || r.SessionID == "" || !filepath.IsAbs(r.RepoRoot) || r.Scope == "" || r.Reason == "" {
		return ErrMalformed
	}
	if r.Host != "" && policy.ValidateWebHost(r.Host) != nil {
		return ErrMalformed
	}
	if r.Action != "" && r.Action != "night-on" && r.Action != "night-off" && r.Action != "web-host-grant" && r.Action != "web-host-revoke" {
		return ErrMalformed
	}
	return nil
}

func durable(r Request) session.ApprovalRequest {
	params := make(map[string]string)
	if r.Action == "night-on" {
		if until := r.Parameters["until"]; until != "" {
			params["until"] = until
		}
	}
	return session.ApprovalRequest{ID: r.ID, Plane: r.Plane, SessionDigest: digest(r.SessionID), RepoRoot: filepath.Clean(r.RepoRoot), Host: r.Host, Scope: string(r.Scope), ReasonDigest: digest(r.Reason), Action: r.Action, Parameters: params, ExpiresAt: r.ExpiresAt, Status: r.Status}
}

func restore(r session.ApprovalRequest) Request {
	return Request{ID: r.ID, Plane: r.Plane, RepoRoot: r.RepoRoot, Host: r.Host, Scope: Scope(r.Scope), Reason: "operator action request", Action: r.Action, Parameters: maps.Clone(r.Parameters), ExpiresAt: r.ExpiresAt, Status: r.Status}
}

func prune(records map[string]session.ApprovalRequest, now time.Time) {
	for id, r := range records {
		if r.Status == "pending" && !r.ExpiresAt.After(now) {
			r.Status = "expired"
			records[id] = r
		}
	}
}

func randomID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate approval identity: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
