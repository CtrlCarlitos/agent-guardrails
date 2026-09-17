package operatorauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	operatorAuthDirectory = "operator-auth"
	credentialFilename    = "authenticators.json"
)

// Credential is the public record required to verify a WebAuthn assertion.
type Credential struct {
	ID         string   `json:"id"`
	PublicKey  string   `json:"public_key"`
	Algorithm  int      `json:"algorithm"`
	SignCount  uint32   `json:"sign_count"`
	Transports []string `json:"transports,omitempty"`
}

// CredentialAttribution is the non-sensitive credential information suitable
// for an audit record.
type CredentialAttribution struct {
	Fingerprint string
	Transports  []string
}

// Store persists the operator's public WebAuthn credential records.
type Store struct {
	root       string
	ceremonies map[string]ceremonyState
	grant      *registrationGrant
	mu         *sync.Mutex
}

// NewStore returns a Store rooted at the operator state directory.
func NewStore(root string) Store {
	return Store{root: root, ceremonies: make(map[string]ceremonyState), mu: &sync.Mutex{}}
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

func (s Store) commitInitialCredential(credential Credential) error {
	if err := ensureDir(s.root); err != nil {
		return err
	}
	dir := filepath.Join(s.root, operatorAuthDirectory)
	if err := ensurePrivateDir(dir, true); err != nil {
		return err
	}
	release, err := acquireEnrollmentLock(dir)
	if err != nil {
		return err
	}
	defer release()
	enrolled, err := s.hasCredentials()
	if err != nil {
		return err
	}
	if enrolled {
		return errors.New("initial registration requires no enrolled credentials")
	}
	return s.Replace([]Credential{credential})
}

func acquireEnrollmentLock(dir string) (func(), error) {
	path := filepath.Join(dir, ".enrollment.lock")
	for attempts := 0; attempts < 500; attempts++ {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			if err := file.Close(); err != nil {
				_ = os.Remove(path)
				return nil, fmt.Errorf("close enrollment lock: %w", err)
			}
			return func() {
				_ = os.Remove(path)
				if parent, err := os.Open(dir); err == nil {
					_ = parent.Sync()
					_ = parent.Close()
				}
			}, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("create enrollment lock: %w", err)
		}
		if err := validateRegularFile(path); err != nil {
			return nil, fmt.Errorf("inspect enrollment lock: %w", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil, errors.New("enrollment creation lock unavailable")
}

// ClearForRecovery removes the public credential store after a local recovery
// confirmation. It intentionally does not reuse Replace, whose empty-set
// rejection protects normal credential management from disabling approvals.
func (s Store) ClearForRecovery() error {
	if _, err := os.Lstat(s.Path()); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect credential store: %w", err)
	}
	dir := filepath.Dir(s.Path())
	if err := ensurePrivateDir(dir, false); err != nil {
		return err
	}
	if err := validateRegularFile(s.Path()); err != nil {
		return err
	}
	if err := os.Remove(s.Path()); err != nil {
		return fmt.Errorf("clear credential store: %w", err)
	}
	parent, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open credential directory: %w", err)
	}
	defer parent.Close()
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("sync credential directory: %w", err)
	}
	s.mu.Lock()
	s.ceremonies = make(map[string]ceremonyState)
	s.grant = nil
	s.mu.Unlock()
	return nil
}

// Credentials returns the validated public credential records.
func (s Store) Credentials() ([]Credential, error) {
	if err := ensurePrivateDir(filepath.Dir(s.Path()), false); err != nil {
		return nil, err
	}
	if err := validateRegularFile(s.Path()); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.Path())
	if err != nil {
		return nil, fmt.Errorf("read credential store: %w", err)
	}
	var credentials []Credential
	if err := json.Unmarshal(data, &credentials); err != nil {
		return nil, fmt.Errorf("decode credential store: %w", err)
	}
	if err := validateCredentials(credentials); err != nil {
		return nil, err
	}
	return credentials, nil
}

// AddCredential persists one verified registration without replacing existing
// authenticators.
func (s Store) AddCredential(credential Credential) error {
	credentials, err := s.Credentials()
	if err != nil {
		return err
	}
	return s.Replace(append(credentials, credential))
}

// RemoveCredentialFingerprint removes one credential only when another
// credential remains enrolled. Callers must complete a management assertion
// before invoking it.
func (s Store) RemoveCredentialFingerprint(fingerprint string) error {
	credentials, err := s.Credentials()
	if err != nil {
		return err
	}
	if len(credentials) < 2 {
		return errors.New("cannot remove the final enrolled authenticator")
	}
	filtered := make([]Credential, 0, len(credentials)-1)
	removed := false
	for _, credential := range credentials {
		if credential.Attribution().Fingerprint == fingerprint {
			removed = true
			continue
		}
		filtered = append(filtered, credential)
	}
	if !removed {
		return errors.New("credential fingerprint not found")
	}
	return s.Replace(filtered)
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
