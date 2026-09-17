package operatorauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
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

// Ceremony is an in-memory WebAuthn ceremony. Options are either a
// protocol.CredentialCreation or protocol.CredentialAssertion.
type Ceremony struct {
	ID        string
	Binding   Binding
	ExpiresAt time.Time
	Options   any
}

const ceremonyLifetime = 5 * time.Minute

type ceremonyState struct {
	ceremony Ceremony
	verifier *webauthn.WebAuthn
	session  webauthn.SessionData
	user     operatorUser
}

type registrationGrant struct{ expiresAt time.Time }

type operatorUser struct{ credentials []webauthn.Credential }

func (u operatorUser) WebAuthnID() []byte                         { return []byte("guardrail-operator") }
func (u operatorUser) WebAuthnName() string                       { return "Guardrail operator" }
func (u operatorUser) WebAuthnDisplayName() string                { return "Guardrail operator" }
func (u operatorUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// BeginRegistration starts a single-use, user-verified enrollment ceremony.
func (s *Store) BeginRegistration(origin string) (Ceremony, error) {
	registered, err := s.hasCredentials()
	if err != nil {
		return Ceremony{}, err
	}
	if registered {
		return Ceremony{}, errors.New("initial registration requires no enrolled credentials")
	}
	return s.beginRegistration(origin)
}

// BeginAdditionalRegistration consumes a grant issued by a verified enrolled
// authenticator assertion and starts one registration ceremony.
func (s *Store) BeginAdditionalRegistration(origin string) (Ceremony, error) {
	if err := s.takeRegistrationGrant(); err != nil {
		return Ceremony{}, err
	}
	return s.beginRegistration(origin)
}

func (s *Store) beginRegistration(origin string) (Ceremony, error) {
	verifier, err := newVerifier(origin)
	if err != nil {
		return Ceremony{}, err
	}
	user := operatorUser{}
	options, session, err := verifier.BeginRegistration(user, webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired}))
	if err != nil {
		return Ceremony{}, fmt.Errorf("begin registration: %w", err)
	}
	ceremony := Ceremony{ID: ceremonyID(), ExpiresAt: time.Now().Add(ceremonyLifetime), Options: options}
	session.Expires = ceremony.ExpiresAt
	s.remember(ceremonyState{ceremony: ceremony, verifier: verifier, session: *session, user: user})
	return ceremony, nil
}

// FinishRegistration verifies a registration response and removes its ceremony.
func (s *Store) FinishRegistration(ceremonyID string, response []byte) (Credential, error) {
	state, err := s.take(ceremonyID)
	if err != nil {
		return Credential{}, err
	}
	if _, ok := state.ceremony.Options.(*protocol.CredentialCreation); !ok {
		return Credential{}, errors.New("ceremony is not a registration")
	}
	if time.Now().After(state.ceremony.ExpiresAt) {
		return Credential{}, errors.New("registration ceremony expired")
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return Credential{}, fmt.Errorf("parse registration response: %w", err)
	}
	credential, err := state.verifier.CreateCredential(state.user, state.session, parsed)
	if err != nil {
		return Credential{}, fmt.Errorf("verify registration response: %w", err)
	}
	return credentialRecord(*credential)
}

// BeginAssertion starts a single-use, user-verified approval assertion.
func (s *Store) BeginAssertion(request approval.Request, origin string) (Ceremony, error) {
	if !time.Now().Before(request.ExpiresAt) {
		return Ceremony{}, errors.New("approval request expired")
	}
	verifier, err := newVerifier(origin)
	if err != nil {
		return Ceremony{}, err
	}
	user, err := s.user()
	if err != nil {
		return Ceremony{}, err
	}
	binding := BindingFor(request)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return Ceremony{}, fmt.Errorf("generate assertion nonce: %w", err)
	}
	digest := binding.Digest()
	challenge := append(nonce, digest[:]...)
	options, session, err := verifier.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired), webauthn.WithChallenge(challenge))
	if err != nil {
		return Ceremony{}, fmt.Errorf("begin assertion: %w", err)
	}
	ceremony := Ceremony{ID: ceremonyID(), Binding: binding, ExpiresAt: request.ExpiresAt, Options: options}
	session.Expires = ceremony.ExpiresAt
	s.remember(ceremonyState{ceremony: ceremony, verifier: verifier, session: *session, user: user})
	return ceremony, nil
}

// FinishAssertion verifies an approval assertion and removes its ceremony.
func (s *Store) FinishAssertion(ceremonyID string, response []byte) (Credential, error) {
	state, err := s.take(ceremonyID)
	if err != nil {
		return Credential{}, err
	}
	if _, ok := state.ceremony.Options.(*protocol.CredentialAssertion); !ok {
		return Credential{}, errors.New("ceremony is not an assertion")
	}
	if time.Now().After(state.ceremony.ExpiresAt) {
		return Credential{}, errors.New("assertion ceremony expired")
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return Credential{}, fmt.Errorf("parse assertion response: %w", err)
	}
	credential, err := state.verifier.ValidateLogin(state.user, state.session, parsed)
	if err != nil {
		return Credential{}, fmt.Errorf("verify assertion response: %w", err)
	}
	result, err := credentialRecord(*credential)
	if err != nil {
		return Credential{}, err
	}
	if state.ceremony.Binding.Action == "authenticator-add" {
		s.issueRegistrationGrant(state.ceremony.ExpiresAt)
	}
	return result, nil
}

// BeginApprovalAssertion adapts an assertion ceremony for the approval browser.
func (s *Store) BeginApprovalAssertion(request approval.Request, origin string) (approval.Assertion, error) {
	ceremony, err := s.BeginAssertion(request, origin)
	if err != nil {
		return approval.Assertion{}, err
	}
	return approval.Assertion{ID: ceremony.ID, Options: ceremony.Options}, nil
}

// FinishApprovalAssertion verifies the browser response without exposing credentials.
func (s *Store) FinishApprovalAssertion(ceremonyID string, response []byte) error {
	_, err := s.FinishAssertion(ceremonyID, response)
	return err
}

func newVerifier(origin string) (*webauthn.WebAuthn, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "localhost" || parsed.Port() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return nil, errors.New("origin must be an exact http://localhost:<port> origin")
	}
	if port, err := strconv.ParseUint(parsed.Port(), 10, 16); err != nil || port == 0 {
		return nil, errors.New("origin must have a valid localhost port")
	}
	verifier, err := webauthn.New(&webauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "Guardrail",
		RPOrigins:     []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configure WebAuthn verifier: %w", err)
	}
	return verifier, nil
}

func (s *Store) remember(state ceremonyState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ceremonies[state.ceremony.ID] = state
}

func (s *Store) take(id string) (ceremonyState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.ceremonies[id]
	if !ok {
		return ceremonyState{}, errors.New("unknown or consumed ceremony")
	}
	delete(s.ceremonies, id)
	return state, nil
}

func (s *Store) user() (operatorUser, error) {
	if err := ensurePrivateDir(filepath.Dir(s.Path()), false); err != nil {
		return operatorUser{}, err
	}
	if err := validateRegularFile(s.Path()); err != nil {
		return operatorUser{}, err
	}
	data, err := os.ReadFile(s.Path())
	if err != nil {
		return operatorUser{}, fmt.Errorf("read credential store: %w", err)
	}
	var stored []Credential
	if err := json.Unmarshal(data, &stored); err != nil {
		return operatorUser{}, fmt.Errorf("decode credential store: %w", err)
	}
	if err := validateCredentials(stored); err != nil {
		return operatorUser{}, err
	}
	credentials := make([]webauthn.Credential, 0, len(stored))
	for _, credential := range stored {
		id, _ := base64.RawURLEncoding.DecodeString(credential.ID)
		publicKey, _ := base64.RawURLEncoding.DecodeString(credential.PublicKey)
		transports := make([]protocol.AuthenticatorTransport, len(credential.Transports))
		for index, transport := range credential.Transports {
			transports[index] = protocol.AuthenticatorTransport(transport)
		}
		credentials = append(credentials, webauthn.Credential{ID: id, PublicKey: publicKey, Transport: transports, Authenticator: webauthn.Authenticator{SignCount: credential.SignCount}})
	}
	return operatorUser{credentials: credentials}, nil
}

func credentialRecord(credential webauthn.Credential) (Credential, error) {
	var publicKey webauthncose.PublicKeyData
	if err := webauthncbor.Unmarshal(credential.PublicKey, &publicKey); err != nil {
		return Credential{}, fmt.Errorf("decode credential public key: %w", err)
	}
	transports := make([]string, len(credential.Transport))
	for index, transport := range credential.Transport {
		transports[index] = string(transport)
	}
	return Credential{
		ID:         base64.RawURLEncoding.EncodeToString(credential.ID),
		PublicKey:  base64.RawURLEncoding.EncodeToString(credential.PublicKey),
		Algorithm:  int(publicKey.Algorithm),
		SignCount:  credential.Authenticator.SignCount,
		Transports: transports,
	}, nil
}

// Attribution returns a stable credential fingerprint and transport metadata
// without exposing the credential ID or public key to audit callers.
func (c Credential) Attribution() CredentialAttribution {
	id, err := base64.RawURLEncoding.DecodeString(c.ID)
	if err != nil {
		return CredentialAttribution{Transports: append([]string(nil), c.Transports...)}
	}
	digest := sha256.Sum256(id)
	return CredentialAttribution{Fingerprint: hex.EncodeToString(digest[:8]), Transports: append([]string(nil), c.Transports...)}
}

func (s *Store) hasCredentials() (bool, error) {
	if _, err := os.Lstat(s.Path()); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("inspect credential store: %w", err)
	}
	if _, err := s.user(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) issueRegistrationGrant(expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grant = &registrationGrant{expiresAt: expiresAt}
}

func (s *Store) takeRegistrationGrant() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.grant == nil || !time.Now().Before(s.grant.expiresAt) {
		s.grant = nil
		return errors.New("no valid additional-registration grant")
	}
	s.grant = nil
	return nil
}

func ceremonyID() string {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		panic(fmt.Sprintf("generate ceremony ID: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
