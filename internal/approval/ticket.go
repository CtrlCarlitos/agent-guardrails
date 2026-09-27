package approval

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/privatefs"
	"github.com/gofrs/flock"
)

// Approval tickets (ADR-0033). In prompt mode the hook answers an agent's
// canonical operator command with the plane's native ask and records a
// ticket. When the human approves, the host runs the command with no
// terminal; the CLI claims the ticket as its proof of approval.
//
// A ticket holds no secret. It is honoured because of where it is (a
// directory P5 denies agents write access to) and what it binds (the exact
// command and working directory the CLI is itself running with). It lives ten
// minutes, is claimed by an atomic rename so exactly one run can spend it,
// and is voided by the issuing session's next hook call.

// TicketTTL is how long a host ask may stay unanswered. It matches the ten
// minutes the ask guidance already names.
const TicketTTL = 10 * time.Minute

const ticketVersion = 1

// Ticket is one host-approved (or host-asked) operator command.
type Ticket struct {
	Version       int       `json:"version"`
	Command       string    `json:"command"`
	CWD           string    `json:"cwd"`
	RepoRoot      string    `json:"repo_root"`
	Plane         string    `json:"plane"`
	Action        string    `json:"action"`
	SessionDigest string    `json:"session_digest"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// TicketDir is <state root>/guardrail/approval-tickets: LOCALAPPDATA on
// Windows, XDG_STATE_HOME or ~/.local/state elsewhere.
func TicketDir() (string, error) {
	var base string
	if runtime.GOOS == "windows" {
		base = os.Getenv("LOCALAPPDATA")
		if base == "" || !filepath.IsAbs(base) {
			return "", errors.New("LOCALAPPDATA must be an absolute path")
		}
	} else {
		base = os.Getenv("XDG_STATE_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, ".local", "state")
		}
		if !filepath.IsAbs(base) {
			return "", errors.New("XDG_STATE_HOME must be an absolute path")
		}
	}
	return filepath.Join(base, "guardrail", "approval-tickets"), nil
}

// CanonicalTicketDir is the spelling a ticket binds: absolute, cleaned,
// symlinks resolved when possible, and case-folded on Windows where the
// filesystem is case-insensitive and hosts disagree on drive-letter case.
func CanonicalTicketDir(dir string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	dir = filepath.Clean(dir)
	if runtime.GOOS == "windows" {
		dir = strings.ToLower(dir)
	}
	return dir
}

func sessionDigest(sessionID string) string {
	sum := sha256.Sum256([]byte("guardrail-approval-session-v1\x00" + sessionID))
	return hex.EncodeToString(sum[:])
}

func sessionPrefix(sessionID string) string { return sessionDigest(sessionID)[:16] }

// bindingDigest is SHA-256 over a versioned, length-prefixed tuple of the
// command and the canonical directory, so no two tuples share a name.
func bindingDigest(command, cwd string) string {
	h := sha256.New()
	h.Write([]byte("guardrail-approval-ticket-v1\x00"))
	for _, field := range []string{command, CanonicalTicketDir(cwd)} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(field)))
		h.Write(n[:])
		h.Write([]byte(field))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func ensureTicketDir() (string, error) {
	dir, err := TicketDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := privatefs.SecureDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// IssueTicket records t for sessionID, replacing that session's ticket for the
// same command and directory. Only the hook calls it.
func IssueTicket(t Ticket, sessionID string, now time.Time) error {
	if t.Command == "" || t.CWD == "" {
		return errors.New("approval ticket needs a command and a working directory")
	}
	dir, err := ensureTicketDir()
	if err != nil {
		return err
	}
	now = now.UTC()
	t.Version = ticketVersion
	t.CWD = CanonicalTicketDir(t.CWD)
	t.SessionDigest = sessionDigest(sessionID)
	t.IssuedAt = now
	t.ExpiresAt = now.Add(TicketTTL)
	raw, err := json.Marshal(t)
	if err != nil {
		return err
	}
	pruneExpiredTickets(dir, now)
	name := sessionPrefix(sessionID) + "-" + bindingDigest(t.Command, t.CWD) + ".json"
	tmp, err := os.CreateTemp(dir, ".issue-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, filepath.Join(dir, name))
}

func ticketCandidates(command, cwd string) ([]string, string, error) {
	dir, err := TicketDir()
	if err != nil {
		return nil, "", err
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*-"+bindingDigest(command, cwd)+".json"))
	return matches, dir, err
}

func readTicket(path string) (Ticket, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Ticket{}, err
	}
	var t Ticket
	if err := json.Unmarshal(raw, &t); err != nil {
		return Ticket{}, err
	}
	return t, nil
}

func (t Ticket) valid(command, cwd string, now time.Time) bool {
	return t.Version == ticketVersion && t.Command == command &&
		t.CWD == CanonicalTicketDir(cwd) && now.Before(t.ExpiresAt) && !t.IssuedAt.After(now.Add(time.Minute))
}

// PeekTicket reports whether a live ticket exists for command in cwd without
// spending it. A command uses it to decide whether an approval is reachable.
func PeekTicket(command, cwd string, now time.Time) bool {
	candidates, _, err := ticketCandidates(command, cwd)
	if err != nil {
		return false
	}
	for _, path := range candidates {
		if t, err := readTicket(path); err == nil && t.valid(command, cwd, now.UTC()) {
			return true
		}
	}
	return false
}

// ClaimTicket spends the ticket for command in cwd. The claim is read and
// delete under the ticket directory's exclusive OS lock, so of any number of
// concurrent claimants (threads or processes) exactly one sees the file and
// removes it. A rename is not that primitive on Windows: two MoveFileEx calls
// that opened the source before either finished can both succeed. The file is
// removed whether or not its contents hold, so a claimed ticket is gone.
func ClaimTicket(command, cwd string, now time.Time) (Ticket, bool, error) {
	candidates, dir, err := ticketCandidates(command, cwd)
	if err != nil || len(candidates) == 0 {
		return Ticket{}, false, err
	}
	lock := flock.New(filepath.Join(dir, ".lock"), flock.SetPermissions(0o600))
	if err := lock.Lock(); err != nil {
		return Ticket{}, false, err
	}
	defer lock.Unlock()
	now = now.UTC()
	for _, path := range candidates {
		t, readErr := readTicket(path)
		if err := os.Remove(path); err != nil {
			// Gone already: another claimant spent it before this one held
			// the lock. Any other failure leaves it unspent, so it is not used.
			continue
		}
		if readErr == nil && t.valid(command, cwd, now) {
			return t, true, nil
		}
	}
	return Ticket{}, false, nil
}

// VoidSessionTickets removes sessionID's outstanding tickets, except the one
// binding keepCommand in keepCWD (a re-issue of the same ask). The hook calls
// it on every other pre-execution call from that session.
func VoidSessionTickets(sessionID, keepCommand, keepCWD string) error {
	dir, err := TicketDir()
	if err != nil {
		// No resolvable ticket directory: no ticket can have been issued.
		return nil
	}
	matches, err := filepath.Glob(filepath.Join(dir, sessionPrefix(sessionID)+"-*.json"))
	if err != nil || len(matches) == 0 {
		return err
	}
	keep := ""
	if keepCommand != "" {
		keep = sessionPrefix(sessionID) + "-" + bindingDigest(keepCommand, keepCWD) + ".json"
	}
	var firstErr error
	for _, path := range matches {
		if filepath.Base(path) == keep {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func pruneExpiredTickets(dir string, now time.Time) {
	matches, _ := filepath.Glob(filepath.Join(dir, "*-*.json"))
	for _, path := range matches {
		if t, err := readTicket(path); err != nil || !now.Before(t.ExpiresAt) {
			_ = os.Remove(path)
		}
	}
}
