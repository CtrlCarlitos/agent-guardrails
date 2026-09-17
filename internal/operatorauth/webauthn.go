package operatorauth

import (
	"crypto/sha256"
	"encoding/json"
	"sort"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	webauthn "github.com/go-webauthn/webauthn/webauthn"
)

// Binding is the canonical authorization request representation signed by an
// authenticator assertion.
type Binding struct {
	RequestID  string      `json:"request_id"`
	IssuedAt   string      `json:"issued_at"`
	Action     string      `json:"action"`
	Parameters []Parameter `json:"parameters"`
	RepoRoot   string      `json:"repo_root"`
	Host       string      `json:"host"`
	Scope      string      `json:"scope"`
	ExpiresAt  string      `json:"expires_at"`
}

// Parameter is one lexically ordered canonical action parameter.
type Parameter struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// BindingFor creates a canonical binding for every authorization-relevant
// request field.
func BindingFor(request approval.Request) Binding {
	return Binding{
		RequestID:  request.ID,
		IssuedAt:   request.IssuedAt.UTC().Format(time.RFC3339Nano),
		Action:     request.Action,
		Parameters: bindingParameters(request.Parameters),
		RepoRoot:   request.RepoRoot,
		Host:       request.Host,
		Scope:      string(request.Scope),
		ExpiresAt:  request.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
}

func bindingParameters(parameters map[string]string) []Parameter {
	keys := make([]string, 0, len(parameters))
	for key := range parameters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Parameter, 0, len(keys))
	for _, key := range keys {
		result = append(result, Parameter{Key: key, Value: parameters[key]})
	}
	return result
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
