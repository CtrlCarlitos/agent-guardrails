package operatorauth

import (
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	webauthn "github.com/go-webauthn/webauthn/webauthn"
)

// Binding is the canonical authorization request representation signed by an
// authenticator assertion.
type Binding struct {
	RequestID string `json:"request_id"`
	Action    string `json:"action"`
	RepoRoot  string `json:"repo_root"`
	Host      string `json:"host"`
	Scope     string `json:"scope"`
	ExpiresAt string `json:"expires_at"`
}

// BindingFor creates a canonical binding for every authorization-relevant
// request field.
func BindingFor(request approval.Request) Binding {
	return Binding{
		RequestID: request.ID,
		Action:    request.Action,
		RepoRoot:  request.RepoRoot,
		Host:      request.Host,
		Scope:     string(request.Scope),
		ExpiresAt: request.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
}

// Digest returns the domain-separated canonical request digest.
func (b Binding) Digest() [32]byte {
	encoded, err := json.Marshal(b)
	if err != nil {
		panic(err)
	}
	return sha256.Sum256(append([]byte("guardrail-approval-v1\x00"), encoded...))
}

// Ceremony will hold ephemeral WebAuthn assertion state in later tasks. It is
// intentionally separate from Store so no ceremony data can be persisted.
type Ceremony struct {
	verifier *webauthn.WebAuthn
}
