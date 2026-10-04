// Package actiongrant stores exact-action requests in operator-owned machinery.
// Full input is private ceremony material, never audit-log authorization input.
package actiongrant

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/privatefs"
	"github.com/gofrs/flock"
)

const TTL = 15 * time.Minute
const maxRecords = 128
const maxBody = 16 << 20

type Action struct {
	Plane   string
	Session string
	Repo    string
	CWD     string
	Tool    string
	Rule    string
	Kind    string
	Text    string
	Paths   []string
}

func (a Action) Digest() string {
	raw, _ := json.Marshal(a)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (a Action) valid() bool {
	for _, value := range []string{a.Plane, a.Session, a.Repo, a.CWD, a.Tool, a.Rule, a.Kind, a.Text} {
		if !utf8.ValidString(value) {
			return false
		}
	}
	for _, value := range a.Paths {
		if !utf8.ValidString(value) {
			return false
		}
	}
	return a.Plane == "codex" && a.Session != "" && filepath.IsAbs(a.Repo) && filepath.IsAbs(a.CWD) &&
		a.Tool != "" && a.Rule != "" && !policy.NeverGrantable(a.Rule) && a.Text != "" && len(a.Text) <= 8<<20 &&
		((a.Kind == "command" && a.Tool == "Bash") || (a.Kind == "patch" && a.Tool == "apply_patch" && len(a.Paths) > 0))
}

type Request struct {
	ID        string
	Action    Action
	Digest    string
	Issued    time.Time
	Expires   time.Time
	Status    string
	Transport string
}

type Store struct{ Dir string }

func Default() (Store, error) {
	dir, err := policy.OperatorConfigDir()
	return Store{Dir: filepath.Join(dir, "actions")}, err
}

func validID(id string) bool {
	if len(id) != 64 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func (s Store) locked(run func() error) error {
	if !filepath.IsAbs(s.Dir) {
		return errors.New("action store requires an absolute directory")
	}
	if _, err := os.Lstat(s.Dir); os.IsNotExist(err) {
		if err := os.MkdirAll(s.Dir, 0o700); err != nil {
			return err
		}
		if err := privatefs.SecureDir(s.Dir); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := privatefs.ValidateDir(s.Dir); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(s.Dir, ".lock"), flock.SetPermissions(0o600))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ok, err := lock.TryLockContext(ctx, 10*time.Millisecond)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("action store is busy")
	}
	defer lock.Unlock()
	return run()
}

func (s Store) load(id string) (Request, error) {
	var r Request
	if !validID(id) {
		return r, errors.New("invalid action request identity")
	}
	path := filepath.Join(s.Dir, id+".json")
	if err := privatefs.ValidateFile(path); err != nil {
		return r, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return r, err
	}
	if info.Size() > maxBody {
		return r, errors.New("oversized action request")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return r, err
	}
	if r.ID != id || !r.Action.valid() || r.Digest != r.Action.Digest() || !r.Expires.After(r.Issued) || r.Expires.Sub(r.Issued) > TTL {
		return r, errors.New("action request integrity check failed")
	}
	return r, nil
}

func (s Store) write(r Request) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(raw) > maxBody {
		return errors.New("oversized action request")
	}
	f, err := os.CreateTemp(s.Dir, ".action-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0o600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := privatefs.ValidateFile(name); err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(s.Dir, r.ID+".json"))
}

func (s Store) records(now time.Time) ([]Request, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	var out []Request
	for _, entry := range entries {
		name := entry.Name()
		if filepath.Ext(name) != ".json" {
			continue
		}
		id := name[:len(name)-5]
		r, err := s.load(id)
		if err != nil {
			return nil, err
		}
		if !now.Before(r.Expires) {
			if err := os.Remove(filepath.Join(s.Dir, name)); err != nil {
				return nil, err
			}
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func (s Store) Create(a Action, now time.Time) (out Request, err error) {
	if !a.valid() {
		return out, errors.New("action cannot be granted")
	}
	err = s.locked(func() error {
		records, err := s.records(now)
		if err != nil {
			return err
		}
		for _, r := range records {
			if r.Digest == a.Digest() && r.Status == "pending" {
				out = r
				return nil
			}
		}
		if len(records) >= maxRecords {
			return errors.New("action request store is full")
		}
		var id [32]byte
		if _, err := rand.Read(id[:]); err != nil {
			return err
		}
		out = Request{ID: hex.EncodeToString(id[:]), Action: a, Digest: a.Digest(), Issued: now.UTC(), Expires: now.UTC().Add(TTL), Status: "pending"}
		return s.write(out)
	})
	return out, err
}

func (s Store) Read(id string, now time.Time) (out Request, err error) {
	err = s.locked(func() error {
		var err error
		out, err = s.load(id)
		if err != nil {
			return err
		}
		if !now.Before(out.Expires) {
			return errors.New("action request expired")
		}
		return nil
	})
	return out, err
}

// AuthorizeWithAudit holds the store lock through the audit write. A retry can
// only consume the approval after its issuance has been recorded successfully.
func (s Store) AuthorizeWithAudit(id, digest, transport string, now time.Time, record func(Request) error) error {
	if transport != "terminal-prompt" && transport != "webauthn" {
		return errors.New("unsupported approval transport")
	}
	return s.locked(func() error {
		r, err := s.load(id)
		if err != nil {
			return err
		}
		if r.Digest != digest || r.Status != "pending" || !now.Before(r.Expires) {
			return errors.New("action is not pending or no longer matches")
		}
		r.Status = "approved"
		r.Transport = transport
		if record == nil {
			return errors.New("approval audit is required")
		}
		if err := record(r); err != nil {
			return err
		}
		return s.write(r)
	})
}

func (s Store) Revoke(id string, now time.Time) error {
	return s.locked(func() error {
		r, err := s.load(id)
		if err != nil {
			return err
		}
		if r.Status != "pending" && r.Status != "approved" {
			return fmt.Errorf("action is %s", r.Status)
		}
		r.Status = "revoked"
		return s.write(r)
	})
}

func (s Store) Consume(a Action, now time.Time) (out Request, spent bool, err error) {
	if !a.valid() {
		return out, false, nil
	}
	err = s.locked(func() error {
		records, err := s.records(now)
		if err != nil {
			return err
		}
		for _, r := range records {
			if r.Status != "approved" || r.Digest != a.Digest() || (r.Transport != "terminal-prompt" && r.Transport != "webauthn") {
				continue
			}
			r.Status = "consumed"
			if err := s.write(r); err != nil {
				return err
			}
			out = r
			spent = true
			return nil
		}
		return nil
	})
	return out, spent, err
}
