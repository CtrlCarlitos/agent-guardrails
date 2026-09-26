package genconfig

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// The declarative floor is retired for claude and opencode (ADR-0028 phases C
// and B). The Engine enforces everything the floor mirrored, so a generated
// copy in a settings file the operator owns is redundant, drifts, and cannot
// be told apart from the operator's own entries. This file holds what is left
// of it: the frozen list of entries guardrail wrote, now or in an earlier
// release, so `plane enable` can remove exactly those and nothing else.
//
// Nothing here is emitted any more. ClaudeConfig and OpencodeConfig generate
// hooks and the plugin entry only.

// OpencodeConfig is the fragment merged into opencode.json: the plugin entry
// and nothing else. `pol` is unused now and kept so callers do not change.
func OpencodeConfig(pol *policy.Policy, pluginPath string) Fragment {
	return Fragment{"plugin": []string{pluginPath}}
}

// retiredClaudeDeny are entries an earlier release generated that the current
// generators no longer list, so a settings file can still hold them. `dd` and
// the five `git clean` globs were retired as no-op floor classes in #297
// (M4/C1); the rm globs by removeRetiredBashFloorRules before that.
var retiredClaudeDeny = []string{
	"Bash(dd *)",
	"Bash(git clean -f*)", "Bash(git clean -xf*)", "Bash(git clean -fx*)",
	"Bash(git clean -df*)", "Bash(git clean -fd*)",
}

// legacyClaudePermissions is every deny and ask entry guardrail has written
// to a Claude settings file. The allow tier is not here: its one entry is
// still generated and is not a copy of an Engine verdict.
func legacyClaudePermissions(pol *policy.Policy) map[string][]string {
	deny := append(bashDenyGlobs(), secretDenyGlobs(pol)...)
	deny = append(deny, claudeSelfConfigDenyGlobs()...)
	deny = append(deny, retiredClaudeDeny...)
	ask := append(bashAskGlobs(), secretAskGlobs(pol)...)
	ask = append(ask, ciInfraLockAskGlobs()...)
	for _, pattern := range retiredBashFloorPatterns {
		deny = append(deny, "Bash("+pattern+")")
		ask = append(ask, "Bash("+pattern+")")
	}
	return map[string][]string{"deny": deny, "ask": ask}
}

// legacyOpencodePermission is every rule guardrail has written under
// opencode.json's `permission`, keyed category (bash, read, edit) then
// pattern. The retired rm/find patterns are listed with both verdicts because
// the earlier cleanup deleted them whatever their value.
func legacyOpencodePermission(pol *policy.Policy) map[string]map[string]any {
	out := map[string]map[string]any{}
	raw, err := json.Marshal(legacyOpencodeFragment(pol, "guardrail.js")["permission"])
	if err == nil {
		_ = json.Unmarshal(raw, &out)
	}
	if out["bash"] == nil {
		out["bash"] = map[string]any{}
	}
	for _, glob := range retiredClaudeDeny {
		if p, ok := stripWrapper("Bash(", glob); ok {
			for _, translated := range translateOpenCodeCommandGlob(p) {
				out["bash"][translated] = "deny"
			}
		}
	}
	// Before #270 the generator copied each command glob through untranslated,
	// so a settings file written by that release holds the glob as Claude
	// spells it (`git config core.hooksPath /**`). Deny wins over ask on a
	// collision, as it did when they were generated.
	for _, entry := range []struct {
		globs    []string
		decision string
	}{{bashAskGlobs(), "ask"}, {bashDenyGlobs(), "deny"}} {
		for _, glob := range entry.globs {
			if p, ok := stripWrapper("Bash(", glob); ok {
				if _, exists := out["bash"][p]; !exists || entry.decision == "deny" {
					out["bash"][p] = entry.decision
				}
			}
		}
	}
	return out
}

// legacyFloorFragment is everything guardrail may have written, for ownership
// drift: what this binary generates plus the retired floor. Entries
// present in a file that no manifest claims. It is the Stale detector's view
// of what older releases left behind.
func legacyFloorFragment(plane string) (Fragment, bool) {
	base, err := policy.LoadBase()
	if err != nil {
		return nil, false
	}
	switch plane {
	case "claude":
		frag := ClaudeConfig(base, "guardrail")
		perms := legacyClaudePermissions(base)
		current, _ := frag["permissions"].(map[string]any)
		current["deny"], current["ask"] = perms["deny"], perms["ask"]
		return frag, true
	case "opencode":
		frag := OpencodeConfig(base, "guardrail.js")
		frag["permission"] = legacyOpencodeFragment(base, "guardrail.js")["permission"]
		return frag, true
	}
	return nil, false
}

// pruneLegacyFloorDoc removes from doc every entry that is exactly a legacy
// floor entry, and only those. A value the operator changed, an entry
// guardrail never wrote, and every key outside the floor are left alone.
// Containers the removal emptied are dropped; a container the operator also
// uses is not empty and survives. It reports how many entries it removed.
func pruneLegacyFloorDoc(doc map[string]any, plane string) int {
	base, err := policy.LoadBase()
	if err != nil {
		return 0
	}
	switch plane {
	case "claude":
		return pruneClaudeFloor(doc, legacyClaudePermissions(base))
	case "opencode":
		return pruneOpencodeFloor(doc, legacyOpencodePermission(base))
	}
	return 0
}

func pruneClaudeFloor(doc map[string]any, legacy map[string][]string) int {
	permissions, ok := toStringAnyMap(doc["permissions"])
	if !ok {
		return 0
	}
	removed := 0
	for _, tier := range []string{"deny", "ask"} {
		entries, ok := toAnySlice(permissions[tier])
		if !ok {
			continue
		}
		known := make(map[string]bool, len(legacy[tier]))
		for _, e := range legacy[tier] {
			known[e] = true
		}
		kept := make([]any, 0, len(entries))
		for _, entry := range entries {
			if s, isString := entry.(string); isString && known[s] {
				removed++
				continue
			}
			kept = append(kept, entry)
		}
		if len(kept) == len(entries) {
			continue
		}
		if len(kept) == 0 {
			delete(permissions, tier)
		} else {
			permissions[tier] = kept
		}
	}
	if removed > 0 && len(permissions) == 0 {
		delete(doc, "permissions")
	}
	return removed
}

func pruneOpencodeFloor(doc map[string]any, legacy map[string]map[string]any) int {
	permission, ok := toStringAnyMap(doc["permission"])
	if !ok {
		return 0
	}
	removed := 0
	for category, rules := range legacy {
		current, ok := toStringAnyMap(permission[category])
		if !ok {
			continue
		}
		for pattern, want := range rules {
			// `*` is opencode's base rule for the category, which an operator
			// writes as often as guardrail did; it cannot be attributed.
			if pattern == "*" {
				continue
			}
			have, present := current[pattern]
			if !present {
				continue
			}
			if have == want {
				delete(current, pattern)
				removed++
			}
		}
		if len(current) == 0 {
			delete(permission, category)
		}
	}
	// The retired rm/find patterns go whatever value the file carries, as the
	// earlier cleanup (removeRetiredBashFloorRules) did.
	if current, ok := toStringAnyMap(permission["bash"]); ok {
		for _, pattern := range retiredBashFloorPatterns {
			if _, present := current[pattern]; present {
				delete(current, pattern)
				removed++
			}
		}
		if len(current) == 0 {
			delete(permission, "bash")
		}
	}
	if removed > 0 && len(permission) == 0 {
		delete(doc, "permission")
	}
	return removed
}

// LegacyFloorEntries counts the floor entries guardrail wrote that are still
// in the plane's settings file. It reads and never writes. A missing file, or
// a plane that never had a floor, counts zero.
func LegacyFloorEntries(path, plane string) (int, error) {
	if plane != "claude" && plane != "opencode" {
		return 0, nil
	}
	doc, err := ReadJSONObject(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return pruneLegacyFloorDoc(doc, plane), nil
}

// PruneLegacyFloor removes the floor entries guardrail wrote from the plane's
// settings file and retires their ownership records. It touches nothing else
// in the file, writes atomically, and is idempotent. It reports how many
// entries it removed; when that is zero the file is not rewritten.
func PruneLegacyFloor(path, plane string) (int, error) {
	if plane != "claude" && plane != "opencode" {
		return 0, nil
	}
	doc, err := ReadJSONObject(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	before := snapshot(doc)
	removed := pruneLegacyFloorDoc(doc, plane)
	if removed == 0 {
		return 0, nil
	}
	if err := writeJSONAtomic(path, doc); err != nil {
		return 0, err
	}
	recordOwnership(plane, path, before, doc, true)
	return removed, nil
}

func writeJSONAtomic(path string, doc map[string]any) error {
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".guardrail-settings-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
