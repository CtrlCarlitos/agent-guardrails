package operatorauth_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
)

func TestBindingUsesCanonicalAuthorizationFields(t *testing.T) {
	issuedAt := time.Date(2026, 9, 16, 12, 33, 56, 789, time.FixedZone("UTC-7", -7*60*60))
	expiresAt := time.Date(2026, 9, 16, 12, 34, 56, 789, time.FixedZone("UTC-7", -7*60*60))
	request := approval.Request{
		ID: "r1", IssuedAt: issuedAt, Action: "web-host-grant", Parameters: map[string]string{"scope": "repo", "host": "example.com"}, RepoRoot: "/repo", Host: "example.com", Scope: approval.RepoScope, ExpiresAt: expiresAt,
	}

	want := sha256.Sum256([]byte("guardrail-approval-v1\x00{\"request_id\":\"r1\",\"issued_at\":\"2026-09-16T19:33:56.000000789Z\",\"action\":\"web-host-grant\",\"parameters\":[{\"key\":\"host\",\"value\":\"example.com\"},{\"key\":\"scope\",\"value\":\"repo\"}],\"repo_root\":\"/repo\",\"host\":\"example.com\",\"scope\":\"repo\",\"expires_at\":\"2026-09-16T19:34:56.000000789Z\"}"))
	if got := operatorauth.BindingFor(request).Digest(); got != want {
		t.Fatalf("binding digest = %x, want %x", got, want)
	}
}

func TestBindingChangesForEveryAuthorizationField(t *testing.T) {
	base := approval.Request{ID: "r1", IssuedAt: time.Now(), Action: "web-host-grant", Parameters: map[string]string{"host": "example.com"}, RepoRoot: "/repo", Host: "example.com", Scope: approval.RepoScope, ExpiresAt: time.Now().Add(time.Minute)}
	want := operatorauth.BindingFor(base).Digest()
	for _, changed := range []approval.Request{
		{ID: "r2", IssuedAt: base.IssuedAt, Action: base.Action, Parameters: base.Parameters, RepoRoot: base.RepoRoot, Host: base.Host, Scope: base.Scope, ExpiresAt: base.ExpiresAt},
		{ID: base.ID, IssuedAt: base.IssuedAt.Add(time.Second), Action: base.Action, Parameters: base.Parameters, RepoRoot: base.RepoRoot, Host: base.Host, Scope: base.Scope, ExpiresAt: base.ExpiresAt},
		{ID: base.ID, IssuedAt: base.IssuedAt, Action: "web-host-revoke", Parameters: base.Parameters, RepoRoot: base.RepoRoot, Host: base.Host, Scope: base.Scope, ExpiresAt: base.ExpiresAt},
		{ID: base.ID, IssuedAt: base.IssuedAt, Action: base.Action, Parameters: map[string]string{"host": "other.example"}, RepoRoot: base.RepoRoot, Host: base.Host, Scope: base.Scope, ExpiresAt: base.ExpiresAt},
		{ID: base.ID, IssuedAt: base.IssuedAt, Action: base.Action, Parameters: base.Parameters, RepoRoot: "/other", Host: base.Host, Scope: base.Scope, ExpiresAt: base.ExpiresAt},
		{ID: base.ID, IssuedAt: base.IssuedAt, Action: base.Action, Parameters: base.Parameters, RepoRoot: base.RepoRoot, Host: "other.example", Scope: base.Scope, ExpiresAt: base.ExpiresAt},
		{ID: base.ID, IssuedAt: base.IssuedAt, Action: base.Action, Parameters: base.Parameters, RepoRoot: base.RepoRoot, Host: base.Host, Scope: approval.GlobalScope, ExpiresAt: base.ExpiresAt},
		{ID: base.ID, IssuedAt: base.IssuedAt, Action: base.Action, Parameters: base.Parameters, RepoRoot: base.RepoRoot, Host: base.Host, Scope: base.Scope, ExpiresAt: base.ExpiresAt.Add(time.Second)},
	} {
		if got := operatorauth.BindingFor(changed).Digest(); got == want {
			t.Fatal("changed authorization field retained digest")
		}
	}
}

func TestStoreWritesOnlyPublicCredentialFields(t *testing.T) {
	store := operatorauth.NewStore(t.TempDir())
	if err := store.Replace([]operatorauth.Credential{{ID: "AQI", PublicKey: "public", Algorithm: -7}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("challenge")) || bytes.Contains(data, []byte("assertion")) {
		t.Fatal("secret ceremony data persisted")
	}
}

func TestStoreReplaceRejectsInvalidCredentialSets(t *testing.T) {
	valid := operatorauth.Credential{ID: "AQI", PublicKey: "public", Algorithm: -7}
	for name, credentials := range map[string][]operatorauth.Credential{
		"empty":                nil,
		"malformed ID":         {{ID: "*", PublicKey: valid.PublicKey, Algorithm: valid.Algorithm}},
		"malformed public key": {{ID: valid.ID, PublicKey: "*", Algorithm: valid.Algorithm}},
		"duplicate ID":         {valid, valid},
	} {
		t.Run(name, func(t *testing.T) {
			if err := operatorauth.NewStore(t.TempDir()).Replace(credentials); err == nil {
				t.Fatal("Replace succeeded for invalid credential set")
			}
		})
	}
}

func TestStoreReplaceRejectsNonPrivateAndSymlinkedPaths(t *testing.T) {
	root := t.TempDir()
	authDir := filepath.Join(root, "operator-auth")
	if err := os.Mkdir(authDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(authDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := operatorauth.NewStore(root).Replace([]operatorauth.Credential{{ID: "AQI", PublicKey: "public", Algorithm: -7}}); err == nil {
		t.Fatal("Replace succeeded in non-private directory")
	}

	privateRoot := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Symlink(target, filepath.Join(privateRoot, "operator-auth")); err != nil {
		t.Fatal(err)
	}
	if err := operatorauth.NewStore(privateRoot).Replace([]operatorauth.Credential{{ID: "AQI", PublicKey: "public", Algorithm: -7}}); err == nil {
		t.Fatal("Replace succeeded through a symlink")
	}
}

func TestClearForRecoveryRemovesOnlyAValidCredentialStore(t *testing.T) {
	store := enrolledStore(t)
	if err := store.ClearForRecovery(); err != nil {
		t.Fatalf("clear for recovery: %v", err)
	}
	if _, err := os.Lstat(store.Path()); !os.IsNotExist(err) {
		t.Fatalf("credential store still exists or could not be inspected: %v", err)
	}
	if _, err := store.BeginRegistration("http://localhost:12345"); err != nil {
		t.Fatalf("recovery did not restore initial enrollment posture: %v", err)
	}
}

func TestBeginRegistrationRequiresExactLoopbackOriginAndUserVerification(t *testing.T) {
	store := operatorauth.NewStore(t.TempDir())
	ceremony, err := store.BeginRegistration("http://localhost:12345")
	if err != nil {
		t.Fatal(err)
	}
	options := ceremony.Options.(*protocol.CredentialCreation)
	if options.Response.RelyingParty.ID != "localhost" {
		t.Fatalf("RP ID = %q, want localhost", options.Response.RelyingParty.ID)
	}
	if options.Response.AuthenticatorSelection.UserVerification != protocol.VerificationRequired {
		t.Fatal("registration does not require user verification")
	}
	if _, err := store.BeginRegistration("https://localhost:12345"); err == nil {
		t.Fatal("non-loopback HTTP origin accepted")
	}
}

func TestBeginAssertionRequiresUserVerificationAndExactBinding(t *testing.T) {
	request := approval.Request{
		ID: "request-1", IssuedAt: time.Now(), Action: "web-host-grant", Parameters: map[string]string{"host": "example.com"}, RepoRoot: "/repo", Host: "example.com", Scope: approval.RepoScope, ExpiresAt: time.Now().Add(time.Minute),
	}
	store := enrolledStore(t)
	ceremony, err := store.BeginAssertion(request, "http://localhost:12345")
	if err != nil {
		t.Fatal(err)
	}
	options := ceremony.Options.(*protocol.CredentialAssertion)
	if options.Response.UserVerification != protocol.VerificationRequired {
		t.Fatal("assertion does not require user verification")
	}
	if len(options.Response.AllowedCredentials) != 1 || string(options.Response.AllowedCredentials[0].CredentialID) != "\x01\x02" {
		t.Fatal("assertion allow list does not contain the enrolled credential")
	}
	challenge, err := base64.RawURLEncoding.DecodeString(options.Response.Challenge.String())
	if err != nil {
		t.Fatal(err)
	}
	want := operatorauth.BindingFor(request).Digest()
	if len(challenge) < len(want) || !bytes.Equal(challenge[len(challenge)-len(want):], want[:]) {
		t.Fatal("assertion challenge does not bind the exact request")
	}
}

func TestBeginAssertionRejectsExpiredRequest(t *testing.T) {
	request := approval.Request{
		ID: "expired", IssuedAt: time.Now().Add(-time.Minute), Action: "web-host-grant", RepoRoot: "/repo", Scope: approval.RepoScope, ExpiresAt: time.Now().Add(-time.Second),
	}
	store := enrolledStore(t)
	if _, err := store.BeginAssertion(request, "http://localhost:12345"); err == nil {
		t.Fatal("expired request started an assertion ceremony")
	}
}

func TestFinishAssertionConsumesCeremonyOnFailure(t *testing.T) {
	request := approval.Request{
		ID: "request-2", IssuedAt: time.Now(), Action: "web-host-grant", RepoRoot: "/repo", Scope: approval.RepoScope, ExpiresAt: time.Now().Add(time.Minute),
	}
	store := enrolledStore(t)
	ceremony, err := store.BeginAssertion(request, "http://localhost:12345")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinishAssertion(ceremony.ID, []byte("not an assertion")); err == nil {
		t.Fatal("malformed assertion accepted")
	}
	if _, err := store.FinishAssertion(ceremony.ID, []byte("not an assertion")); err == nil {
		t.Fatal("failed ceremony was replayed")
	}
}

func enrolledStore(t *testing.T) operatorauth.Store {
	t.Helper()
	store := operatorauth.NewStore(t.TempDir())
	if err := store.Replace([]operatorauth.Credential{{ID: "AQI", PublicKey: "AQI", Algorithm: -7}}); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestRegistrationIsInitialOnlyAndPersistsTransportAttribution(t *testing.T) {
	store := operatorauth.NewStore(t.TempDir())
	first, err := store.BeginRegistration("http://localhost:12345")
	if err != nil {
		t.Fatal(err)
	}
	authenticator := newAuthenticator(t)
	credential, err := store.FinishRegistration(first.ID, authenticator.registrationResponse(t, first, "http://localhost:12345"))
	if err != nil {
		t.Fatal(err)
	}
	if credential.Algorithm != -8 {
		t.Fatalf("credential algorithm = %d, want -8", credential.Algorithm)
	}
	if got := credential.Attribution(); got.Fingerprint == "" || len(got.Transports) != 1 || got.Transports[0] != "usb" {
		t.Fatalf("credential attribution = %#v", got)
	}
	persisted, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(persisted, []byte(`"transports":["usb"]`)) {
		t.Fatal("credential transport metadata was not persisted")
	}
	if _, err := store.BeginRegistration("http://localhost:12345"); err == nil {
		t.Fatal("registration started despite an enrolled credential")
	}
}

func TestStaleInitialRegistrationCannotReplaceFirstEnrollment(t *testing.T) {
	store := operatorauth.NewStore(t.TempDir())
	first, err := store.BeginRegistration("http://localhost:12345")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.BeginRegistration("http://localhost:12345")
	if err != nil {
		t.Fatal(err)
	}
	firstAuthenticator := newAuthenticator(t)
	secondAuthenticator := newAuthenticator(t)
	results := make(chan struct {
		credential operatorauth.Credential
		err        error
	}, 2)
	go func() {
		credential, err := store.FinishRegistration(first.ID, firstAuthenticator.registrationResponse(t, first, "http://localhost:12345"))
		results <- struct {
			credential operatorauth.Credential
			err        error
		}{credential, err}
	}()
	go func() {
		credential, err := store.FinishRegistration(second.ID, secondAuthenticator.registrationResponse(t, second, "http://localhost:12345"))
		results <- struct {
			credential operatorauth.Credential
			err        error
		}{credential, err}
	}()
	firstResult, secondResult := <-results, <-results
	if (firstResult.err == nil) == (secondResult.err == nil) {
		t.Fatalf("initial enrollment results = (%v, %v), want exactly one success", firstResult.err, secondResult.err)
	}
	credentials, err := store.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 {
		t.Fatalf("stored credentials = %d, want 1", len(credentials))
	}
	if credentials[0].ID != firstResult.credential.ID && credentials[0].ID != secondResult.credential.ID {
		t.Fatal("stored credential did not match the sole successful enrollment")
	}
}

func TestVerifiedAssertionGrantsOneAdditionalRegistration(t *testing.T) {
	store, authenticator := enrolledFixture(t)
	request := approval.Request{ID: "manage", IssuedAt: time.Now(), Action: "authenticator-add", RepoRoot: "/repo", Scope: approval.RepoScope, ExpiresAt: time.Now().Add(time.Minute)}
	assertion, err := store.BeginAssertion(request, "http://localhost:12345")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinishAssertion(assertion.ID, authenticator.assertionResponse(t, assertion, "http://localhost:12345", true, "localhost")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginAdditionalRegistration("http://localhost:12345"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginAdditionalRegistration("http://localhost:12345"); err == nil {
		t.Fatal("additional-registration grant replayed")
	}
}

func TestNonManagementAssertionCannotGrantAdditionalRegistration(t *testing.T) {
	store, authenticator := enrolledFixture(t)
	request := approval.Request{ID: "night", IssuedAt: time.Now(), Action: "night-mode", RepoRoot: "/repo", Scope: approval.RepoScope, ExpiresAt: time.Now().Add(time.Minute)}
	assertion, err := store.BeginAssertion(request, "http://localhost:12345")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinishAssertion(assertion.ID, authenticator.assertionResponse(t, assertion, "http://localhost:12345", true, "localhost")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginAdditionalRegistration("http://localhost:12345"); err == nil {
		t.Fatal("non-management assertion issued an additional-registration grant")
	}
}

func TestAssertionVerificationRejectsBoundariesAndReplays(t *testing.T) {
	store, authenticator := enrolledFixture(t)
	request := approval.Request{ID: "approve", IssuedAt: time.Now(), Action: "web-host-grant", Parameters: map[string]string{"host": "example.com"}, RepoRoot: "/repo", Host: "example.com", Scope: approval.RepoScope, ExpiresAt: time.Now().Add(time.Minute)}
	for name, mutate := range map[string]func(CeremonyFixture) []byte{
		"wrong origin": func(c CeremonyFixture) []byte {
			return authenticator.assertionResponse(t, c.Ceremony, "http://localhost:54321", true, "localhost")
		},
		"wrong RP ID": func(c CeremonyFixture) []byte {
			return authenticator.assertionResponse(t, c.Ceremony, "http://localhost:12345", true, "example.com")
		},
		"wrong challenge": func(c CeremonyFixture) []byte {
			return authenticator.assertionResponse(t, c.Ceremony, "http://localhost:12345", true, "localhost")
		},
		"missing user verification": func(c CeremonyFixture) []byte {
			return authenticator.assertionResponse(t, c.Ceremony, "http://localhost:12345", false, "localhost")
		},
	} {
		t.Run(name, func(t *testing.T) {
			ceremony, err := store.BeginAssertion(request, "http://localhost:12345")
			if err != nil {
				t.Fatal(err)
			}
			fixture := CeremonyFixture{Ceremony: ceremony}
			response := mutate(fixture)
			if name == "wrong challenge" {
				response = authenticator.assertionResponseForChallenge(t, ceremony, "http://localhost:12345", true, "localhost", []byte("a different signed binding challenge"))
			}
			if _, err := store.FinishAssertion(ceremony.ID, response); err == nil {
				t.Fatal("invalid assertion accepted")
			}
		})
	}
	ceremony, err := store.BeginAssertion(request, "http://localhost:12345")
	if err != nil {
		t.Fatal(err)
	}
	response := authenticator.assertionResponse(t, ceremony, "http://localhost:12345", true, "localhost")
	if _, err := store.FinishAssertion(ceremony.ID, response); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinishAssertion(ceremony.ID, response); err == nil {
		t.Fatal("valid assertion replay accepted")
	}
}

type CeremonyFixture struct{ Ceremony operatorauth.Ceremony }

type authenticatorFixture struct {
	id   []byte
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newAuthenticator(t *testing.T) authenticatorFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return authenticatorFixture{id: []byte("test-credential-id"), pub: pub, priv: priv}
}

func enrolledFixture(t *testing.T) (operatorauth.Store, authenticatorFixture) {
	t.Helper()
	store := operatorauth.NewStore(t.TempDir())
	authenticator := newAuthenticator(t)
	registration, err := store.BeginRegistration("http://localhost:12345")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.FinishRegistration(registration.ID, authenticator.registrationResponse(t, registration, "http://localhost:12345"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Replace([]operatorauth.Credential{credential}); err != nil {
		t.Fatal(err)
	}
	return store, authenticator
}

func (a authenticatorFixture) registrationResponse(t *testing.T, ceremony operatorauth.Ceremony, origin string) []byte {
	t.Helper()
	options := ceremony.Options.(*protocol.CredentialCreation)
	clientData := clientData(t, "webauthn.create", options.Response.Challenge.String(), origin)
	authData := a.authenticatorData(t, "localhost", protocol.FlagUserPresent|protocol.FlagUserVerified|protocol.FlagAttestedCredentialData, true)
	attestation, err := cbor.Marshal(map[string]any{"fmt": "none", "authData": authData, "attStmt": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	return marshalResponse(t, map[string]any{
		"id": base64.RawURLEncoding.EncodeToString(a.id), "rawId": base64.RawURLEncoding.EncodeToString(a.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": base64.RawURLEncoding.EncodeToString(clientData), "attestationObject": base64.RawURLEncoding.EncodeToString(attestation), "transports": []string{"usb"}},
	})
}

func (a authenticatorFixture) assertionResponse(t *testing.T, ceremony operatorauth.Ceremony, origin string, uv bool, rpID string) []byte {
	t.Helper()
	options := ceremony.Options.(*protocol.CredentialAssertion)
	return a.assertionResponseForChallenge(t, ceremony, origin, uv, rpID, []byte(options.Response.Challenge))
}

func (a authenticatorFixture) assertionResponseForChallenge(t *testing.T, ceremony operatorauth.Ceremony, origin string, uv bool, rpID string, challenge []byte) []byte {
	t.Helper()
	clientData := clientData(t, "webauthn.get", base64.RawURLEncoding.EncodeToString(challenge), origin)
	flags := protocol.FlagUserPresent
	if uv {
		flags |= protocol.FlagUserVerified
	}
	authData := a.authenticatorData(t, rpID, flags, false)
	hash := sha256.Sum256(clientData)
	signature := ed25519.Sign(a.priv, append(authData, hash[:]...))
	return marshalResponse(t, map[string]any{
		"id": base64.RawURLEncoding.EncodeToString(a.id), "rawId": base64.RawURLEncoding.EncodeToString(a.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": base64.RawURLEncoding.EncodeToString(clientData), "authenticatorData": base64.RawURLEncoding.EncodeToString(authData), "signature": base64.RawURLEncoding.EncodeToString(signature)},
	})
}

func (a authenticatorFixture) authenticatorData(t *testing.T, rpID string, flags protocol.AuthenticatorFlags, attested bool) []byte {
	t.Helper()
	rpHash := sha256.Sum256([]byte(rpID))
	data := append([]byte{}, rpHash[:]...)
	data = append(data, byte(flags), 0, 0, 0, 1)
	if !attested {
		return data
	}
	publicKey, err := cbor.Marshal(map[int]any{1: int64(1), 3: int64(-8), -1: int64(6), -2: []byte(a.pub)})
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, make([]byte, 16)...)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(a.id)))
	data = append(data, length...)
	data = append(data, a.id...)
	return append(data, publicKey...)
}

func clientData(t *testing.T, ceremony, challenge, origin string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"type": ceremony, "challenge": challenge, "origin": origin})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func marshalResponse(t *testing.T, response map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
