// Package night manages the operator-controlled, expiring night-mode marker.
package night

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

type Marker struct {
	Until time.Time `toml:"until"`
	SetBy string    `toml:"set_by"`
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

func Load(path string, now time.Time) (State, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("reading night marker: %w", err)
	}
	if !info.Mode().IsRegular() {
		return State{}, errors.New("reading night marker: marker is not a regular file")
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
	if marker.Until.IsZero() {
		return State{}, errors.New("parsing night marker: until is required")
	}
	if marker.SetBy == "" {
		return State{}, errors.New("parsing night marker: set_by is required")
	}
	return State{Marker: marker, Active: now.Before(marker.Until)}, nil
}

func Write(path string, marker Marker) error {
	if marker.Until.IsZero() {
		return errors.New("writing night marker: until is required")
	}
	if marker.SetBy == "" {
		return errors.New("writing night marker: set_by is required")
	}
	var raw bytes.Buffer
	if err := toml.NewEncoder(&raw).Encode(marker); err != nil {
		return fmt.Errorf("encoding night marker: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating night marker directory: %w", err)
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspecting night marker directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("inspecting night marker directory: path is not a real directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
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
	return nil
}

func Remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing night marker: %w", err)
	}
	return nil
}

func (s State) Banner() string {
	if !s.Active {
		return ""
	}
	return "NIGHT MODE until " + s.Until.Format(time.RFC3339)
}
