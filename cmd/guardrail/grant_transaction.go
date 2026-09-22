package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/gofrs/flock"
)

// mutateCommandGrants rewrites one repository's command grants under the same
// machine-wide lock every other operator-config mutation takes.
//
// Issuance, revocation and consumption all go through here. Consumption is the
// reason the lock matters rather than being belt-and-braces: two concurrent
// tool calls matching the same single-use grant must not both spend it, and
// the window between reading a count and writing it back is exactly where that
// would happen.
func mutateCommandGrants(repo string, mutate func([]policy.CommandGrant) []policy.CommandGrant) error {
	dir, err := allowanceJournalDir()
	if err != nil {
		return err
	}
	if err := ensureAllowanceDir(dir); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(dir, "operator.lock"), flock.SetPermissions(0o600))
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	if err := recoverAllowanceJournals(dir); err != nil {
		return err
	}

	op, err := policy.LoadOperatorConfig()
	if err != nil {
		return err
	}
	if op.Repos == nil {
		op.Repos = map[string]policy.RepoGrant{}
	}
	// Resolve to the key matching already uses. Indexing the map with a
	// cleaned path instead would write a second entry whenever the repo root
	// arrives by an equivalent spelling, and consumption would then never
	// find the grant that keeps matching.
	cleaned := op.GrantKey(repo)
	entry := op.Repos[cleaned]
	entry.Commands = mutate(entry.Commands)
	if len(entry.Commands) == 0 {
		entry.Commands = nil
	}
	op.Repos[cleaned] = entry

	raw, err := operatorConfigContent(op)
	if err != nil {
		return err
	}
	path := policy.OperatorConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := securePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	return writeSyncedPrivateFile(path, raw, 0o600)
}

// consumeCommandGrant spends one use of the grant that authorized this call.
//
// It re-checks the match under the lock rather than trusting the decision made
// before it: the verdict was computed against a config read without the lock,
// and a concurrent call or a revocation may have spent or removed the grant in
// between. A consumption that finds nothing to spend reports false, and the
// caller keeps the original Ask -- the same shape the night-mode path uses
// when its audit write fails, and for the same reason. An allow must never
// outlive the record that accounts for it.
func consumeCommandGrant(repo, ruleID, command string, now time.Time) (spent bool, err error) {
	err = mutateCommandGrants(repo, func(existing []policy.CommandGrant) []policy.CommandGrant {
		for i, g := range existing {
			if g.RuleID != ruleID || g.Command != command || !g.Live(now) {
				continue
			}
			spent = true
			existing[i].Uses = g.RemainingUses() - 1
			return existing
		}
		return existing
	})
	return spent, err
}
