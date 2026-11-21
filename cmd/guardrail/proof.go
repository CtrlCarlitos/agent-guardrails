package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/coverage"
	"github.com/CtrlCarlitos/agent-guardrails/internal/privatefs"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

const proofSchemaVersion = 1

// ProofRecord is the consolidated per-machine enforcement proof (#110), stored
// at $XDG_STATE_HOME/guardrail/proof.json on Unix and
// %LOCALAPPDATA%\guardrail\proof.json on Windows.
type ProofRecord struct {
	SchemaVersion    int                   `json:"schema_version"`
	GuardrailVersion string                `json:"guardrail_version"`
	SelftestPassedAt string                `json:"selftest_passed_at,omitempty"`
	UpdatedAt        string                `json:"updated_at"`
	Planes           map[string]PlaneProof `json:"planes"`
}

// PlaneProof captures one plane's enforcement proof keyed on runtime version
// and settings-file hash alongside lifecycle, floor, and coverage state.
type PlaneProof struct {
	Present              bool     `json:"present"`
	RuntimeVersion       string   `json:"runtime_version,omitempty"`
	SettingsHash         string   `json:"settings_hash,omitempty"`
	LifecycleRegistered  bool     `json:"lifecycle_registered"`
	LifecycleState       string   `json:"lifecycle_state"`
	FloorCurrent         bool     `json:"floor_current"`
	CoverageUncontracted []string `json:"coverage_uncontracted,omitempty"`
	Proven               bool     `json:"proven"`
	Reasons              []string `json:"reasons,omitempty"`
}

// stateBaseDir returns the per-user state root: LOCALAPPDATA on Windows,
// XDG_STATE_HOME (defaulting to ~/.local/state) on Unix.
func stateBaseDir() (string, error) {
	if runtime.GOOS == "windows" {
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return base, nil
		}
	}
	if base := os.Getenv("XDG_STATE_HOME"); base != "" {
		return base, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "AppData", "Local"), nil
	}
	return filepath.Join(home, ".local", "state"), nil
}

func proofRecordPath() (string, error) {
	base, err := stateBaseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "guardrail", "proof.json"), nil
}

// loadProofRecord reads proof.json. Any missing, corrupt, or unreadable file
// yields ok=false (fail-open for posture; callers treat as unproven).
func loadProofRecord() (ProofRecord, bool) {
	path, err := proofRecordPath()
	if err != nil {
		return ProofRecord{}, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ProofRecord{}, false
	}
	var rec ProofRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return ProofRecord{}, false
	}
	if rec.GuardrailVersion == "" {
		return ProofRecord{}, false
	}
	return rec, true
}

func saveProofRecord(rec ProofRecord) error {
	path, err := proofRecordPath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := privatefs.SecureDir(dir); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp, err := os.CreateTemp(dir, ".proof-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := errors.Join(tmp.Chmod(0o600), writeBytes(tmp, raw), tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func writeBytes(f *os.File, b []byte) error {
	_, err := f.Write(b)
	return err
}

func planeSettingsHash(plane string) string {
	path, err := planeConfigPath(plane)
	if err != nil {
		return "unknown"
	}
	h := sha256.New()
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "absent"
		}
		return "unreadable"
	}
	h.Write(raw)
	if plane == "codex" {
		rulesPath := filepath.Join(filepath.Dir(path), "rules", "guardrail.rules")
		if rulesRaw, err := os.ReadFile(rulesPath); err == nil {
			h.Write([]byte{0})
			h.Write(rulesRaw)
		}
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func planeStateIsAbsent(state string) bool {
	return state == "absent" || strings.HasPrefix(state, "no ")
}

func planeStateIsRegistered(state string) bool {
	return strings.HasPrefix(state, "guardrail ") && !planeStateIsProblem(state)
}

// selftestProofState returns the recorded selftest pass timestamp for release
// (empty if not passed for release) and, when unproven, the previous version
// that last passed (if known). Reads proof.json first and migrates from the
// legacy selftest-passed marker when proof.json is absent.
func selftestProofState(release string) (passedAt string, previousVersion string) {
	if rec, ok := loadProofRecord(); ok {
		if rec.GuardrailVersion == release && rec.SelftestPassedAt != "" {
			return rec.SelftestPassedAt, ""
		}
		if rec.SelftestPassedAt != "" && rec.GuardrailVersion != "" {
			previousVersion = rec.GuardrailVersion
		}
	}
	if legacy := selftestPassedVersion(); legacy != "" {
		if legacy == release {
			return "migrated", ""
		}
		if previousVersion == "" {
			previousVersion = legacy
		}
	}
	return "", previousVersion
}

// computeProof evaluates live proof state for every plane and combines it with
// recorded (or freshly passed) selftest evidence.
func computeProof(release string, selftestNow *time.Time) ProofRecord {
	now := time.Now().UTC()
	passedAt := ""
	prevVer := ""
	if selftestNow != nil {
		passedAt = selftestNow.UTC().Format(time.RFC3339)
	} else {
		passedAt, prevVer = selftestProofState(release)
	}

	rec := ProofRecord{
		SchemaVersion:    proofSchemaVersion,
		GuardrailVersion: release,
		SelftestPassedAt: passedAt,
		UpdatedAt:        now.Format(time.RFC3339),
		Planes:           make(map[string]PlaneProof, len(supportedPlanes)),
	}

	for _, plane := range supportedPlanes {
		state := planeStatusState(plane)
		present := !planeStateIsAbsent(state)
		registered := planeStateIsRegistered(state)
		hash := planeSettingsHash(plane)
		floorOK := true
		if present {
			floorOK = planeFloorDrift(plane) == 0
		}

		pp := PlaneProof{
			Present:             present,
			SettingsHash:        hash,
			LifecycleRegistered: registered,
			LifecycleState:      state,
			FloorCurrent:        floorOK,
		}

		if plane == "claude" && present {
			contracted, _ := claudeContracted()
			if d, err := coverage.ClaudeDrift(contracted, release); err == nil {
				if d.Version != "" {
					pp.RuntimeVersion = "Claude Code " + d.Version
				}
				if len(d.Uncontracted) > 0 {
					pp.CoverageUncontracted = append([]string(nil), d.Uncontracted...)
				}
			}
		}

		if !present {
			pp.Proven = false
			rec.Planes[plane] = pp
			continue
		}

		var reasons []string
		if !registered {
			reasons = append(reasons, safetext.SingleLine(state))
		}
		if !floorOK {
			reasons = append(reasons, "floor drifted")
		}
		if len(pp.CoverageUncontracted) > 0 {
			reasons = append(reasons, formatUncontractedReason(pp.CoverageUncontracted))
		}
		if passedAt == "" {
			if prevVer != "" {
				reasons = append(reasons, "selftest last passed on "+safetext.SingleLine(prevVer))
			} else {
				reasons = append(reasons, "selftest not passed")
			}
		}
		pp.Reasons = reasons
		pp.Proven = len(reasons) == 0
		rec.Planes[plane] = pp
	}
	return rec
}

func formatUncontractedReason(tools []string) string {
	clean := make([]string, len(tools))
	for i, t := range tools {
		clean[i] = safetext.SingleLine(t)
	}
	noun := "tools"
	if len(clean) == 1 {
		noun = "tool"
	}
	return fmt.Sprintf("%d uncontracted %s: %s", len(clean), noun, strings.Join(clean, ", "))
}

// unifiedProofPosture returns the single SessionStart advisory line built from
// proof.json (migrating legacy selftest-passed and reading cached Claude
// coverage). Returns "" when everything is proven. Fails open on any read or
// bundle discovery error.
func unifiedProofPosture(release string) string {
	passedAt, prevVer := selftestProofState(release)
	var reasons []string

	runtimeLabel := ""
	contracted, _ := claudeContracted()
	if d, err := coverage.ClaudeDrift(contracted, release); err == nil {
		if d.Version != "" {
			runtimeLabel = "Claude Code " + safetext.SingleLine(d.Version)
		}
		if len(d.Uncontracted) > 0 {
			reasons = append(reasons, formatUncontractedReason(d.Uncontracted))
		}
	}

	if passedAt == "" {
		if prevVer != "" {
			reasons = append(reasons, "selftest last passed on "+safetext.SingleLine(prevVer))
		} else {
			reasons = append(reasons, "selftest not passed")
		}
	}

	// If a proof record exists for this release, verify Claude's settings file
	// has not changed out from under it.
	if rec, ok := loadProofRecord(); ok && rec.GuardrailVersion == release {
		if prev, exists := rec.Planes["claude"]; exists && prev.SettingsHash != "" && prev.SettingsHash != "absent" {
			liveHash := planeSettingsHash("claude")
			if liveHash != prev.SettingsHash {
				reasons = append(reasons, "settings changed since last proof")
			}
		}
	}

	if len(reasons) == 0 {
		return ""
	}
	subject := safetext.SingleLine(release)
	if runtimeLabel != "" {
		subject += " on " + runtimeLabel
	}
	return fmt.Sprintf("guardrail: unproven for %s (%s) — run guardrail status", subject, strings.Join(reasons, "; "))
}
