package operatorauth_test

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
)

func TestBindingUsesCanonicalAuthorizationFields(t *testing.T) {
	expiresAt := time.Date(2026, 9, 16, 12, 34, 56, 789, time.FixedZone("UTC-7", -7*60*60))
	request := approval.Request{
		ID: "r1", Action: "web-host-grant", RepoRoot: "/repo", Host: "example.com", Scope: approval.RepoScope, ExpiresAt: expiresAt,
	}

	want := sha256.Sum256([]byte("guardrail-approval-v1\x00{\"request_id\":\"r1\",\"action\":\"web-host-grant\",\"repo_root\":\"/repo\",\"host\":\"example.com\",\"scope\":\"repo\",\"expires_at\":\"2026-09-16T19:34:56.000000789Z\"}"))
	if got := operatorauth.BindingFor(request).Digest(); got != want {
		t.Fatalf("binding digest = %x, want %x", got, want)
	}
}

func TestBindingChangesForEveryAuthorizationField(t *testing.T) {
	base := approval.Request{ID: "r1", Action: "web-host-grant", RepoRoot: "/repo", Host: "example.com", Scope: approval.RepoScope, ExpiresAt: time.Now().Add(time.Minute)}
	want := operatorauth.BindingFor(base).Digest()
	for _, changed := range []approval.Request{
		{ID: "r2", Action: base.Action, RepoRoot: base.RepoRoot, Host: base.Host, Scope: base.Scope, ExpiresAt: base.ExpiresAt},
		{ID: base.ID, Action: "web-host-revoke", RepoRoot: base.RepoRoot, Host: base.Host, Scope: base.Scope, ExpiresAt: base.ExpiresAt},
		{ID: base.ID, Action: base.Action, RepoRoot: "/other", Host: base.Host, Scope: base.Scope, ExpiresAt: base.ExpiresAt},
		{ID: base.ID, Action: base.Action, RepoRoot: base.RepoRoot, Host: "other.example", Scope: base.Scope, ExpiresAt: base.ExpiresAt},
		{ID: base.ID, Action: base.Action, RepoRoot: base.RepoRoot, Host: base.Host, Scope: approval.GlobalScope, ExpiresAt: base.ExpiresAt},
		{ID: base.ID, Action: base.Action, RepoRoot: base.RepoRoot, Host: base.Host, Scope: base.Scope, ExpiresAt: base.ExpiresAt.Add(time.Second)},
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
