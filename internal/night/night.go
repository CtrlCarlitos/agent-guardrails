// Package night manages the operator-controlled, expiring night-mode marker.
package night

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/BurntSushi/toml"
	"github.com/CtrlCarlitos/agent-guardrails/internal/pathutil"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/privatefs"
)

const (
	ScopeGlobal  = "global"
	ScopeRepo    = "repo"
	ScopeSession = "session"
)

type Marker struct {
	Until   time.Time `toml:"until"`
	SetBy   string    `toml:"set_by"`
	Scope   string    `toml:"scope,omitempty"`
	Repo    string    `toml:"repo,omitempty"`
	Session string    `toml:"session,omitempty"`
}

type State struct {
	Marker
	Active bool
}

func DefaultPath() (string, error) {
	dir, err := policy.OperatorConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "night.toml"), nil
}

func validateMarker(marker Marker) error {
	if marker.Until.IsZero() {
		return errors.New("until is required")
	}
	if marker.SetBy == "" {
		return errors.New("set_by is required")
	}
	scope := marker.Scope
	if scope == "" {
		scope = ScopeGlobal
	}
	switch scope {
	case ScopeGlobal:
		if marker.Repo != "" {
			return errors.New("repo cannot be set for global scope")
		}
		if marker.Session != "" {
			return errors.New("session cannot be set for global scope")
		}
	case ScopeRepo:
		if marker.Repo == "" {
			return errors.New("repo is required for repo scope")
		}
		if !filepath.IsAbs(marker.Repo) {
			return errors.New("repo must be an absolute path")
		}
		if marker.Session != "" {
			return errors.New("session cannot be set for repo scope")
		}
	case ScopeSession:
		if marker.Session == "" {
			return errors.New("session is required for session scope")
		}
		if strings.IndexFunc(marker.Session, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return errors.New("session must not contain whitespace or control characters")
		}
		if marker.Repo != "" {
			return errors.New("repo cannot be set for session scope")
		}
	default:
		return fmt.Errorf("unknown scope %q (want global, repo, or session)", marker.Scope)
	}
	return nil
}

func Load(path string, now time.Time) (State, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("reading night marker: %w", err)
	}
	if err := privatefs.ValidateFile(path); err != nil {
		return State{}, fmt.Errorf("reading night marker: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return State{}, fmt.Errorf("reading night marker: %w", err)
	}
	var marker Marker
	metadata, err := toml.Decode(string(raw), &marker)
	if err != nil {
		return State{}, fmt.Errorf("parsing night marker: %w", err)
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		return State{}, fmt.Errorf("parsing night marker: unknown key %q", undecoded[0])
	}
	if err := validateMarker(marker); err != nil {
		return State{}, fmt.Errorf("parsing night marker: %w", err)
	}
	return State{Marker: marker, Active: now.Before(marker.Until)}, nil
}

func Write(path string, marker Marker) error {
	if err := validateMarker(marker); err != nil {
		return fmt.Errorf("writing night marker: %w", err)
	}
	if marker.Scope == ScopeGlobal {
		marker.Scope = ""
	}
	var raw bytes.Buffer
	if err := toml.NewEncoder(&raw).Encode(marker); err != nil {
		return fmt.Errorf("encoding night marker: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating night marker directory: %w", err)
	}
	dir := filepath.Dir(path)
	if err := privatefs.SecureDir(dir); err != nil {
		return fmt.Errorf("securing night marker directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".night-*.tmp")
	if err != nil {
		return fmt.Errorf("creating night marker: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("securing night marker: %w", err)
	}
	if _, err := tmp.Write(raw.Bytes()); err != nil {
		tmp.Close()
		return fmt.Errorf("writing night marker: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing night marker: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("installing night marker: %w", err)
	}
	if err := privatefs.ValidateFile(path); err != nil {
		return fmt.Errorf("validating night marker: %w", err)
	}
	return nil
}

func Remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing night marker: %w", err)
	}
	return nil
}

// EffectiveScope returns the marker's normalized scope, defaulting an omitted
// scope to global for backwards compatibility with pre-#83 markers.
func (s State) EffectiveScope() string {
	if s.Scope == "" {
		return ScopeGlobal
	}
	return s.Scope
}

// Matches reports whether this active night lease applies to a tool call in
// repoRoot and sessionID.
func (s State) Matches(repoRoot, sessionID string) bool {
	if !s.Active {
		return false
	}
	switch s.EffectiveScope() {
	case ScopeGlobal:
		return true
	case ScopeRepo:
		return repoRoot != "" && s.Repo != "" && pathutil.Same(s.Repo, repoRoot)
	case ScopeSession:
		return sessionID != "" && s.Session != "" && s.Session == sessionID
	default:
		return false
	}
}

func (s State) Banner() string {
	if !s.Active {
		return ""
	}
	until := s.Until.Format(time.RFC3339)
	switch s.EffectiveScope() {
	case ScopeRepo:
		return "NIGHT MODE (repo " + s.Repo + ") until " + until
	case ScopeSession:
		return "NIGHT MODE (session " + s.Session + ") until " + until
	default:
		return "NIGHT MODE until " + until
	}
}
