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
	"strings"
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
	ID                    string
	Plane                 string
	SessionID             string
	RepoRoot              string
	Host                  string
	Scope                 Scope
	Reason                string
	Action                string
	Parameters            map[string]string
	IssuedAt              time.Time
	ExpiresAt             time.Time
	Status                string
	Transport             string
	CredentialFingerprint string
	ApprovalURL           string
}

// Summary renders the operator-facing detail line for the approval page:
// the exact plane batch for lifecycle actions and the exact host batch for
// egress actions, empty otherwise.
func (r Request) Summary() string {
	if r.Action == "plane-enable" || r.Action == "plane-disable" {
		if list := r.Parameters["planes"]; list != "" {
			return "planes: " + list
		}
	}
	if r.Action == "recover" {
		if repair := r.Parameters["repair"]; repair != "" {
			return "repair: " + repair
		}
	}
	if r.Action == "recover" {
		if repair := r.Parameters["repair"]; repair != "" {
			return "repair: " + repair
		}
	}
	if r.Action == "web-host-grant" || r.Action == "web-host-revoke" {
		if list := r.Parameters["hosts"]; list != "" {
			return "hosts: " + list + " (" + r.Parameters["scope"] + ")"
		}
	}
	return ""
}

type CompletionAttribution struct {
	Transport             string
	CredentialFingerprint string
}

type Broker struct {
	now         func() time.Time
	mu          sync.Mutex
	attribution map[string]CompletionAttribution
}

func New() *Broker {
	return &Broker{now: time.Now, attribution: make(map[string]CompletionAttribution)}
}

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
	now := b.now().UTC()
	if r.Action == "night-on" {
		expiresAt, err := canonicalNightExpiry(r.Parameters["until"], now)
		if err != nil {
			return Request{}, ErrMalformed
		}
		r.Parameters = map[string]string{"expires_at": expiresAt}
	}
	if r.ID == "" {
		id, err := randomID()
		if err != nil {
			return Request{}, err
		}
		r.ID = id
	}
	if r.ExpiresAt.IsZero() {
		r.ExpiresAt = now.Add(requestTTL)
	} else if r.ExpiresAt.After(now.Add(requestTTL)) {
		return Request{}, ErrMalformed
	}
	r.IssuedAt = now
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

func (b *Broker) hasPending() bool {
	pending := false
	_ = session.Transaction(requestSessionID, func(st *session.State) error {
		prune(st.ApprovalRequests, b.now().UTC())
		for _, request := range st.ApprovalRequests {
			if request.Status == "pending" || request.Status == "executing" {
				pending = true
				break
			}
		}
		return nil
	})
	return pending
}

// recoverInterruptedActions makes idempotent canonical actions retryable after
// a daemon process dies between recording execution and recording completion.
func (b *Broker) recoverInterruptedActions() error {
	return session.Transaction(requestSessionID, func(st *session.State) error {
		prune(st.ApprovalRequests, b.now().UTC())
		for id, request := range st.ApprovalRequests {
			if request.Status == "executing" {
				request.Status = "pending"
				st.ApprovalRequests[id] = request
			}
		}
		return nil
	})
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
	b.mu.Lock()
	if attribution, ok := b.attribution[id]; ok {
		request.Transport = attribution.Transport
		request.CredentialFingerprint = attribution.CredentialFingerprint
		delete(b.attribution, id)
	}
	b.mu.Unlock()
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

// SetCompletionAttribution associates privacy-safe WebAuthn attribution with
// the exact pending request. Browser verification calls this immediately
// before approval; it is intentionally process-local and never durable state.
func (b *Broker) SetCompletionAttribution(id string, attribution CompletionAttribution) {
	if b == nil || id == "" || attribution.Transport == "" || attribution.CredentialFingerprint == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attribution[id] = attribution
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
	if r.Action != "" && r.Action != "night-on" && r.Action != "night-off" && r.Action != "web-host-grant" && r.Action != "web-host-revoke" && r.Action != "plane-enable" && r.Action != "plane-disable" && r.Action != "recover" {
		return ErrMalformed
	}
	if r.Action == "night-on" && (len(r.Parameters) != 1 || r.Parameters["until"] == "") {
		return ErrMalformed
	}
	if (r.Action == "web-host-grant" || r.Action == "web-host-revoke") && !validWebHostParameters(r) {
		return ErrMalformed
	}
	if (r.Action == "plane-enable" || r.Action == "plane-disable") && !validPlaneList(r.Parameters) {
		return ErrMalformed
	}
	if r.Action == "recover" && !validRecoverRepair(r.Parameters) {
		return ErrMalformed
	}
	return nil
}

func validWebHostParameters(r Request) bool {
	if len(r.Parameters) != 2 {
		return false
	}
	if r.Parameters["scope"] != "repo" && r.Parameters["scope"] != "global" {
		return false
	}
	if Scope(r.Parameters["scope"]) != r.Scope {
		return false
	}
	list := r.Parameters["hosts"]
	if list == "" {
		return false
	}
	for _, host := range strings.Split(list, ",") {
		if policy.ValidateWebHost(host) != nil {
			return false
		}
	}
	return true
}

func validRecoverRepair(params map[string]string) bool {
	if len(params) != 1 {
		return false
	}
	switch params["repair"] {
	case "claude-settings", "opencode-config", "antigravity-hooks":
		return true
	}
	return false
}

func validPlaneList(params map[string]string) bool {
	if len(params) != 1 {
		return false
	}
	list := params["planes"]
	if list == "" {
		return false
	}
	for _, plane := range strings.Split(list, ",") {
		if plane != "claude" && plane != "opencode" && plane != "antigravity" {
			return false
		}
	}
	return true
}

func canonicalNightExpiry(until string, now time.Time) (string, error) {
	clock, err := time.ParseInLocation("15:04", until, time.Local)
	if err != nil || clock.Format("15:04") != until {
		return "", ErrMalformed
	}
	localNow := now.In(time.Local)
	expiresAt := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), clock.Hour(), clock.Minute(), 0, 0, time.Local)
	if !expiresAt.After(localNow) {
		expiresAt = expiresAt.AddDate(0, 0, 1)
	}
	return expiresAt.UTC().Format(time.RFC3339Nano), nil
}

func durable(r Request) session.ApprovalRequest {
	params := make(map[string]string)
	if r.Action == "night-on" {
		if expiresAt := r.Parameters["expires_at"]; expiresAt != "" {
			params["expires_at"] = expiresAt
		}
	}
	if r.Action == "web-host-grant" || r.Action == "web-host-revoke" {
		params["scope"] = string(r.Scope)
		params["hosts"] = r.Parameters["hosts"]
	}
	if r.Action == "recover" {
		params["repair"] = r.Parameters["repair"]
	}
	if r.Action == "plane-enable" || r.Action == "plane-disable" {
		params["planes"] = r.Parameters["planes"]
	}
	if r.Action == "recover" {
		params["repair"] = r.Parameters["repair"]
	}
	return session.ApprovalRequest{ID: r.ID, Plane: r.Plane, SessionDigest: digest(r.SessionID), RepoRoot: filepath.Clean(r.RepoRoot), Host: r.Host, Scope: string(r.Scope), ReasonDigest: digest(r.Reason), Action: r.Action, Parameters: params, IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt, Status: r.Status}
}

func restore(r session.ApprovalRequest) Request {
	return Request{ID: r.ID, Plane: r.Plane, RepoRoot: r.RepoRoot, Host: r.Host, Scope: Scope(r.Scope), Reason: "operator action request", Action: r.Action, Parameters: maps.Clone(r.Parameters), IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt, Status: r.Status}
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
