package operatorauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	operatorAuthDirectory = "operator-auth"
	credentialFilename    = "authenticators.json"
)

// Credential is the public record required to verify a WebAuthn assertion.
type Credential struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
	Algorithm int    `json:"algorithm"`
	SignCount uint32 `json:"sign_count"`
}

// Store persists the operator's public WebAuthn credential records.
type Store struct {
	root string
}

// NewStore returns a Store rooted at the operator state directory.
func NewStore(root string) Store {
	return Store{root: root}
}

// Path is the credential store path.
func (s Store) Path() string {
	return filepath.Join(s.root, operatorAuthDirectory, credentialFilename)
}

// Replace atomically replaces all credential records. An empty replacement is
// rejected so credential removal cannot accidentally disable approvals.
func (s Store) Replace(credentials []Credential) error {
	if err := validateCredentials(credentials); err != nil {
		return err
	}
	if err := ensureDir(s.root); err != nil {
		return err
	}
	dir := filepath.Join(s.root, operatorAuthDirectory)
	if err := ensurePrivateDir(dir, true); err != nil {
		return err
	}
	if err := validateRegularFile(s.Path()); err != nil {
		return err
	}

	data, err := json.Marshal(credentials)
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".authenticators-*")
	if err != nil {
		return fmt.Errorf("create credential temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("set credential temporary file permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write credential temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync credential temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close credential temporary file: %w", err)
	}
	if err := validateRegularFile(s.Path()); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.Path()); err != nil {
		return fmt.Errorf("replace credential store: %w", err)
	}
	parent, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open credential directory: %w", err)
	}
	defer parent.Close()
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("sync credential directory: %w", err)
	}
	return nil
}

func validateCredentials(credentials []Credential) error {
	if len(credentials) == 0 {
		return errors.New("credential set must not be empty")
	}
	ids := make(map[string]struct{}, len(credentials))
	for _, credential := range credentials {
		if !isBase64URL(credential.ID) || !isBase64URL(credential.PublicKey) {
			return errors.New("credential ID and public key must be unpadded base64url")
		}
		if _, exists := ids[credential.ID]; exists {
			return errors.New("credential IDs must be unique")
		}
		ids[credential.ID] = struct{}{}
	}
	return nil
}

func isBase64URL(value string) bool {
	if value == "" || len(value)%4 == 1 {
		return false
	}
	for _, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func ensurePrivateDir(path string, create bool) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) && create {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create credential directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect credential directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("credential directory %q is not private", path)
	}
	return nil
}

func ensureDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect credential state directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("credential state directory is not a directory")
	}
	return nil
}

func validateRegularFile(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect credential store: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("credential store is not a private regular file")
	}
	return nil
}
