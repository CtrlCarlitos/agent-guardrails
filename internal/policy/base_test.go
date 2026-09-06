package policy

import (
	"slices"
	"strings"
	"testing"
)

func TestLoadBase(t *testing.T) {
	p, err := LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Slots.SecretGlobs) < 12 {
		t.Errorf("SecretGlobs = %d entries, want >= 12", len(p.Slots.SecretGlobs))
	}
	wantSecretDirs := []string{
		"**/.ssh/**", "/root/.ssh/**", "**/.aws/**", "**/.config/gcloud/**",
		"**/.docker/config.json", "**/.gnupg/**",
	}
	for _, want := range wantSecretDirs {
		if !slices.Contains(p.Slots.SecretDirs, want) {
			t.Errorf("SecretDirs missing %q: %v", want, p.Slots.SecretDirs)
		}
	}
	for _, moved := range wantSecretDirs[:5] {
		if slices.Contains(p.Slots.SecretGlobs, moved) {
			t.Errorf("SecretGlobs still contains migrated directory %q: %v", moved, p.Slots.SecretGlobs)
		}
	}
	wantSecretAskGlobs := []string{
		"**/*.pem", "**/*.p12", "**/*.pfx", "**/*.keystore", "**/service-account*.json",
	}
	if !slices.Equal(p.Slots.SecretAskGlobs, wantSecretAskGlobs) {
		t.Errorf("SecretAskGlobs = %v, want %v", p.Slots.SecretAskGlobs, wantSecretAskGlobs)
	}
	for _, moved := range wantSecretAskGlobs {
		if slices.Contains(p.Slots.SecretGlobs, moved) {
			t.Errorf("SecretGlobs still contains ambiguous pattern %q: %v", moved, p.Slots.SecretGlobs)
		}
	}
	wantPrivateKeyDeny := []string{
		"**/id_rsa*", "**/id_ed25519*", "**/id_ecdsa*", "**/id_dsa*",
		"**/*_rsa", "**/*_ed25519", "**/*_ecdsa", "**/*.private.key",
		"**/*-private-key.*", "**/private*.key",
	}
	for _, want := range wantPrivateKeyDeny {
		if !slices.Contains(p.Slots.SecretGlobs, want) {
			t.Errorf("SecretGlobs missing private-key deny %q: %v", want, p.Slots.SecretGlobs)
		}
	}
	if slices.Contains(p.Slots.SecretGlobs, "**/*.key") || slices.Contains(p.Slots.SecretGlobs, "*.key") {
		t.Errorf("SecretGlobs retains broad *.key pattern: %v", p.Slots.SecretGlobs)
	}
	// Full-path globs only: the bare ".env.example" duplicate went with the
	// basename fallback (review M-2/M-4/M-5).
	if !slices.Contains(p.Slots.SecretAllow, "**/.env.example") {
		t.Errorf("SecretAllow missing **/.env.example: %v", p.Slots.SecretAllow)
	}
	if !slices.Contains(p.Slots.SecretAllow, "**/*.pub") {
		t.Errorf("SecretAllow missing **/*.pub: %v", p.Slots.SecretAllow)
	}
	allGlobs := append(append(append(p.Slots.SecretDirs, p.Slots.SecretGlobs...), p.Slots.SecretAskGlobs...), p.Slots.SecretAllow...)
	for _, g := range allGlobs {
		if !strings.Contains(g, "/") {
			t.Errorf("bare glob %q would match only a path that is exactly that name; prefix it with **/", g)
		}
	}
	if p.Waived == nil {
		t.Error("Waived must be a non-nil map")
	}
}
