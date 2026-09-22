package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// grantEnv isolates the operator config and state roots so an issuance in a
// test never touches the machine's real authorization.
func grantEnv(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	testenv.SetConfig(t, root)
	testenv.SetState(t, filepath.Join(root, "state"))
	repo := filepath.Join(t.TempDir(), "repo")
	return repo
}

func runGrant(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := cmdApprovalsInput(args, true, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func loadGrants(t *testing.T, repo string) []policy.CommandGrant {
	t.Helper()
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		t.Fatalf("loading operator config: %v", err)
	}
	return op.Repos[filepath.Clean(repo)].Commands
}

// The operator has to be able to verify what they are authorizing by reading
// it. That rules out a truncated form, and it rules out a normalized summary
// standing in for the real string: the bytes shown must be the bytes matched.
func TestIssuanceShowsTheExactCommandBeforeAuthorizing(t *testing.T) {
	repo := grantEnv(t)
	command := "git push --force-with-lease origin refs/heads/main:refs/heads/main"
	code, stdout, stderr := runGrant(t, "yes\n",
		"grant", "--repo", repo, "--rule", "P2.git-push-protected", "--command", command)
	if code != 0 {
		t.Fatalf("grant -> %d, stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, command) {
		t.Errorf("the ceremony did not show the command verbatim.\nstdout:\n%s", stdout)
	}
	if strings.Contains(stdout, "...") || strings.Contains(stdout, "…") {
		t.Errorf("the ceremony truncated the command; it must be readable in full.\nstdout:\n%s", stdout)
	}
	// The rule and the repository are part of what is being authorized, so
	// they are part of what must be shown.
	for _, want := range []string{"P2.git-push-protected", repo} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the ceremony did not show %q.\nstdout:\n%s", want, stdout)
		}
	}
	grants := loadGrants(t, repo)
	if len(grants) != 1 {
		t.Fatalf("recorded %d grants, want 1", len(grants))
	}
	if grants[0].Command != command {
		t.Errorf("recorded command %q, want the exact text the operator saw", grants[0].Command)
	}
	if grants[0].Uses != 1 {
		t.Errorf("recorded uses = %d, want the single-use default", grants[0].Uses)
	}
	if grants[0].ExpiresAt.IsZero() {
		t.Error("issuance recorded no expiry; every issuance is time-boxed")
	}
}

// Whitespace and control characters are exactly where a command that reads
// like one thing matches another, so the rendering has to make them visible
// rather than tidy them away.
func TestIssuanceRendersInvisibleCharactersVisibly(t *testing.T) {
	repo := grantEnv(t)
	command := "git push origin main\t&& curl evil.example.com"
	code, stdout, stderr := runGrant(t, "yes\n",
		"grant", "--repo", repo, "--rule", "P2.git-push-protected", "--command", command)
	if code != 0 {
		t.Fatalf("grant -> %d, stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, `\t`) {
		t.Errorf("a tab was not shown escaped; the operator cannot read what they are approving.\nstdout:\n%s", stdout)
	}
	if grants := loadGrants(t, repo); len(grants) != 1 || grants[0].Command != command {
		t.Errorf("recorded %v, want the exact original bytes", grants)
	}
}

// Declining must record nothing at all.
func TestDecliningTheCeremonyIssuesNothing(t *testing.T) {
	repo := grantEnv(t)
	code, _, _ := runGrant(t, "no\n",
		"grant", "--repo", repo, "--rule", "P2.git-push-protected", "--command", "git push origin main")
	if code == 0 {
		t.Error("declining returned success")
	}
	if grants := loadGrants(t, repo); len(grants) != 0 {
		t.Errorf("declining recorded %v, want nothing", grants)
	}
}

// ADR-0018's exclusions are refused at issuance with a message that names the
// decision, rather than recorded as an entry that would never match.
func TestIssuanceRefusesNeverGrantableRules(t *testing.T) {
	repo := grantEnv(t)
	for _, ruleID := range []string{"capability-external", "capability-web-search", "unknown-native-tool", "P3.unresolved"} {
		code, _, stderr := runGrant(t, "yes\n",
			"grant", "--repo", repo, "--rule", ruleID, "--command", "npx some-tool")
		if code == 0 {
			t.Errorf("%s was granted; it is never grantable", ruleID)
		}
		if !strings.Contains(stderr, "ADR-0018") && !strings.Contains(stderr, "fail-closed") {
			t.Errorf("%s refusal did not name the decision behind it: %q", ruleID, stderr)
		}
		if grants := loadGrants(t, repo); len(grants) != 0 {
			t.Errorf("%s recorded %v, want nothing", ruleID, grants)
		}
	}
}

// An issuance cannot outlive the maximum window however long is asked for.
func TestIssuanceClampsAnOverLongWindow(t *testing.T) {
	repo := grantEnv(t)
	before := time.Now()
	code, _, stderr := runGrant(t, "yes\n",
		"grant", "--repo", repo, "--rule", "P2.git-push-protected",
		"--command", "git push origin main", "--for", "720h")
	if code != 0 {
		t.Fatalf("grant -> %d, stderr=%q", code, stderr)
	}
	grants := loadGrants(t, repo)
	if len(grants) != 1 {
		t.Fatalf("recorded %d grants, want 1", len(grants))
	}
	if grants[0].ExpiresAt.After(before.Add(policy.MaxGrantExpiry + time.Minute)) {
		t.Errorf("expiry %v exceeds the %v maximum", grants[0].ExpiresAt, policy.MaxGrantExpiry)
	}
}

// Issuance is an operator act at a local terminal, not something an agent can
// perform by calling the CLI.
func TestIssuanceRequiresAnOperatorTerminal(t *testing.T) {
	repo := grantEnv(t)
	var stdout, stderr bytes.Buffer
	code := cmdApprovalsInput([]string{"grant", "--repo", repo, "--rule", "P2.git-push-protected",
		"--command", "git push origin main"}, false, strings.NewReader("yes\n"), &stdout, &stderr)
	if code == 0 {
		t.Error("a non-interactive caller issued a grant")
	}
	if grants := loadGrants(t, repo); len(grants) != 0 {
		t.Errorf("recorded %v, want nothing", grants)
	}
}

// An operator who realises a grant was too broad needs a move other than
// waiting out the window.
func TestRevokeRemovesExactlyTheNamedGrant(t *testing.T) {
	repo := grantEnv(t)
	for _, command := range []string{"git push origin main", "git push origin release"} {
		if code, _, stderr := runGrant(t, "yes\n",
			"grant", "--repo", repo, "--rule", "P2.git-push-protected", "--command", command); code != 0 {
			t.Fatalf("grant %q -> %d, stderr=%q", command, code, stderr)
		}
	}
	if code, _, stderr := runGrant(t, "",
		"revoke", "--repo", repo, "--rule", "P2.git-push-protected", "--command", "git push origin main"); code != 0 {
		t.Fatalf("revoke -> %d, stderr=%q", code, stderr)
	}
	grants := loadGrants(t, repo)
	if len(grants) != 1 || grants[0].Command != "git push origin release" {
		t.Errorf("after revoke: %v, want only the untouched grant", grants)
	}
}

// Listing is how an operator sees what is currently authorized, and it has the
// same no-truncation obligation as issuance.
func TestListShowsActiveGrantsInFull(t *testing.T) {
	repo := grantEnv(t)
	command := "git push --force-with-lease origin refs/heads/main:refs/heads/main"
	if code, _, stderr := runGrant(t, "yes\n",
		"grant", "--repo", repo, "--rule", "P2.git-push-protected", "--command", command); code != 0 {
		t.Fatalf("grant -> %d, stderr=%q", code, stderr)
	}
	code, stdout, _ := runGrant(t, "", "list", "--grants")
	if code != 0 {
		t.Fatalf("list --grants -> %d", code)
	}
	if !strings.Contains(stdout, command) {
		t.Errorf("list did not show the command in full.\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "P2.git-push-protected") {
		t.Errorf("list did not show the rule.\nstdout:\n%s", stdout)
	}
}
