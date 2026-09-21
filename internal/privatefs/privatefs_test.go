package privatefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsAndUnixSecureDirMakesCreatedArtifactsPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := SecureDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDir(dir); err != nil {
		t.Fatalf("secured directory did not validate: %v", err)
	}

	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFile(path); err != nil {
		t.Fatalf("file created inside secured directory did not validate: %v", err)
	}
}

func TestPrivacyValidationRejectsWrongArtifactKinds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SecureDir(dir); err != nil {
		t.Fatal(err)
	}

	if err := ValidateDir(path); err == nil {
		t.Fatal("regular file validated as private directory")
	}
	if err := ValidateFile(dir); err == nil {
		t.Fatal("directory validated as private regular file")
	}
}
