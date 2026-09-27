package approval_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// ADR-0033: a host-approved ask leaves one ticket the TTY-less CLI run can
// claim. These pin every property the ADR's soundness argument relies on.

func ticketFixture(t *testing.T) (cwd string, now time.Time) {
	t.Helper()
	testenv.SetState(t, t.TempDir())
	cwd = t.TempDir()
	return cwd, time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
}

func issue(t *testing.T, command, cwd, session string, now time.Time) {
	t.Helper()
	err := approval.IssueTicket(approval.Ticket{Command: command, CWD: cwd, RepoRoot: cwd, Plane: "claude", Action: "plane-enable"}, session, now)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTicketIsClaimedOnceForTheExactCommandAndDirectory(t *testing.T) {
	cwd, now := ticketFixture(t)
	issue(t, "guardrail plane enable claude", cwd, "s1", now)

	if _, ok, _ := approval.ClaimTicket("guardrail plane enable opencode", cwd, now); ok {
		t.Fatal("a ticket must not authorize a different command")
	}
	if _, ok, _ := approval.ClaimTicket("guardrail plane enable claude", t.TempDir(), now); ok {
		t.Fatal("a ticket must not authorize the same command in another directory")
	}
	if !approval.PeekTicket("guardrail plane enable claude", cwd, now) {
		t.Fatal("peek must see the live ticket")
	}
	got, ok, err := approval.ClaimTicket("guardrail plane enable claude", cwd, now.Add(time.Minute))
	if err != nil || !ok {
		t.Fatalf("claim = %v, %v; want the ticket", ok, err)
	}
	if got.Command != "guardrail plane enable claude" || got.Plane != "claude" || got.Action != "plane-enable" {
		t.Fatalf("claimed ticket = %+v", got)
	}
	if _, ok, _ := approval.ClaimTicket("guardrail plane enable claude", cwd, now.Add(time.Minute)); ok {
		t.Fatal("a ticket must be single-use")
	}
	if approval.PeekTicket("guardrail plane enable claude", cwd, now) {
		t.Fatal("a claimed ticket must be gone")
	}
}

func TestTicketExpiresAfterTenMinutes(t *testing.T) {
	cwd, now := ticketFixture(t)
	issue(t, "guardrail night off", cwd, "s1", now)
	if _, ok, _ := approval.ClaimTicket("guardrail night off", cwd, now.Add(approval.TicketTTL+time.Second)); ok {
		t.Fatal("an expired ticket must not be claimable")
	}
	if approval.TicketTTL != 10*time.Minute {
		t.Fatalf("TicketTTL = %v, want the 10 minutes the ask guidance names", approval.TicketTTL)
	}
	dir, err := approval.TicketDir()
	if err != nil {
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.json")); len(left) != 0 {
		t.Fatalf("an expired ticket seen by a claim must be removed, left %v", left)
	}
}

// The approved command is the session's next action; any other call from the
// same session means the ask was answered no (or never ran), so its ticket
// must not outlive that call.
func TestTicketIsVoidedByTheSessionsNextCall(t *testing.T) {
	cwd, now := ticketFixture(t)
	issue(t, "guardrail plane disable --all", cwd, "s1", now)
	issue(t, "guardrail recover claude-settings", cwd, "s2", now)

	if err := approval.VoidSessionTickets("s1", "", ""); err != nil {
		t.Fatal(err)
	}
	if approval.PeekTicket("guardrail plane disable --all", cwd, now) {
		t.Fatal("the session's next call must void its ticket")
	}
	if !approval.PeekTicket("guardrail recover claude-settings", cwd, now) {
		t.Fatal("voiding one session must leave another session's ticket")
	}
	// A re-issue of the same canonical command keeps (replaces) its ticket.
	issue(t, "guardrail plane disable --all", cwd, "s1", now)
	if err := approval.VoidSessionTickets("s1", "guardrail plane disable --all", cwd); err != nil {
		t.Fatal(err)
	}
	if !approval.PeekTicket("guardrail plane disable --all", cwd, now) {
		t.Fatal("re-issuing the same ask must not void its own ticket")
	}
}

func TestTicketConcurrentClaimsHaveOneWinner(t *testing.T) {
	cwd, now := ticketFixture(t)
	issue(t, "guardrail setup", cwd, "s1", now)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, _ := approval.ClaimTicket("guardrail setup", cwd, now); ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("concurrent claims won %d times, want exactly 1", wins)
	}
}

// A file placed in the ticket directory is honoured only if it binds the
// command and directory it is named for: renaming a ticket onto another
// command's name does not move its authorization.
func TestTicketContentMustMatchItsName(t *testing.T) {
	cwd, now := ticketFixture(t)
	issue(t, "guardrail plane enable claude", cwd, "s1", now)
	dir, err := approval.TicketDir()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %v, %v", entries, err)
	}
	// Re-key the claude ticket under the disable command's binding.
	issue(t, "guardrail plane disable --all", cwd, "s9", now)
	var disableName string
	all, _ := os.ReadDir(dir)
	for _, e := range all {
		if e.Name() != entries[0].Name() {
			disableName = e.Name()
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, disableName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := approval.ClaimTicket("guardrail plane disable --all", cwd, now); ok {
		t.Fatal("a ticket whose content binds another command must not be honoured")
	}
}

func TestTicketDirectoryIsUnderTheStateRoot(t *testing.T) {
	state := t.TempDir()
	testenv.SetState(t, state)
	dir, err := approval.TicketDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(state, "guardrail", "approval-tickets")
	if dir != want {
		t.Fatalf("TicketDir = %q, want %q", dir, want)
	}
}

func TestWindowsTicketDirectorySpellingIsCaseInsensitive(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("drive letters and case-insensitive paths are Windows semantics")
	}
	cwd, now := ticketFixture(t)
	issue(t, "guardrail night off", cwd, "s1", now)
	if _, ok, _ := approval.ClaimTicket("guardrail night off", strings.ToUpper(cwd), now); !ok {
		t.Fatal("the same Windows directory spelled in another case must find the ticket")
	}
}
