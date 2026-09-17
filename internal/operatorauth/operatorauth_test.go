package operatorauth_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
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
