package genconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// MergeInto deep-merges frag into the JSON object stored at path, creating the
// file if absent. The written file's mode is CreateTemp's default 0600 —
// intentional, as settings files may carry secrets; callers wanting 0644 can
// chmod after.
func MergeInto(path string, frag Fragment) error {
	return mergeInto(path, "", frag, false)
}

// MergePlaneInto merges a generated plane fragment and applies exact migrations
// for obsolete guardrail-owned settings from earlier releases.
func MergePlaneInto(path, plane string, frag Fragment) error {
	return mergePlaneInto(path, plane, frag, false)
}

// ReconcilePlaneInto performs the same settings merge as MergePlaneInto and
// additionally reconciles an existing ownership manifest. It is reserved for
// the operator-requested repair of manifest Missing/Stale drift: exact current
// generated entries are adopted, and records for absent entries are retired.
func ReconcilePlaneInto(path, plane string, frag Fragment) error {
	return mergePlaneInto(path, plane, frag, true)
}

func mergePlaneInto(path, plane string, frag Fragment, reconcileOwnership bool) error {
	switch plane {
	case "claude", "opencode", "antigravity", "codex":
		return mergeInto(path, plane, frag, reconcileOwnership)
	default:
		return fmt.Errorf("unsupported plane %q", plane)
	}
}

// RemovePlaneFrom removes only Guardrail-owned integration entries for a plane.
// It is intentionally idempotent so declarative installers can reconcile off state.
//
// Manifest first: the record written at merge time says exactly which entries
// guardrail added and what each changed key held before, so removal restores
// rather than deletes and never touches an entry it did not write.
//
// Without a manifest -- every installation predating it, and any host whose
// state directory was cleared -- removal falls back to the in-band signals
// that survive state loss: the `guardrail-` hook id and the plugin file's
// basename. Permission entries have no in-band signal, which is the whole
// reason the manifest exists, so the fallback leaves them and reports rather
// than guessing. Leaving them is the honest answer and it is what the old code
// already did for claude; what it must not do is delete the operator's
// entries alongside guardrail's, which is what it did for opencode.
func RemovePlaneFrom(path, plane string) error {
	_, err := RemovePlaneFromReporting(path, plane)
	return err
}

// RemovePlaneFromReporting is RemovePlaneFrom with the detail doctor and the
// plane lifecycle need: what was removed, what was restored, and what was left
// because the operator had edited it since.
func RemovePlaneFromReporting(path, plane string) (RemovalReport, error) {
	report := RemovalReport{}
	if plane != "claude" && plane != "opencode" && plane != "antigravity" && plane != "codex" {
		return report, fmt.Errorf("unsupported plane %q", plane)
	}

	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return report, nil
	}
	if err != nil {
		return report, err
	}
	var existing map[string]any
	if err := json.Unmarshal(raw, &existing); err != nil || existing == nil {
		return report, fmt.Errorf("%s is not a JSON object; refusing to overwrite", path)
	}

	manifest, _ := LoadManifest(plane)
	if manifest != nil && sameTarget(manifest.Target, path) {
		report = applyManifestRemoval(existing, manifest)
		_ = clearManifest(plane)
	} else {
		report = removeByInBandMarkers(existing, plane)
		report.Fallback = true
	}

	out, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return report, err
	}
	out = append(out, 10)
	return report, os.WriteFile(path, out, 0o600)
}

// sameTarget compares the manifest's recorded target with the file being
// disabled. A manifest for a different file is not this file's record, and
// applying it would remove entries by coincidence of shape.
func sameTarget(recorded, path string) bool {
	if recorded == "" {
		return false
	}
	return filepath.Clean(recorded) == filepath.Clean(path)
}

// removeByInBandMarkers is the no-manifest fallback.
//
// Two signals survive state loss. Hooks carry a `guardrail-` id and the
// opencode plugin is identifiable by basename -- the identification the merge
// path already had and the removal path never used, which is the defect that
// unregistered the operator's own plugins.
//
// Permission entries carry no signal at all, so the fallback regenerates what
// this binary would write and removes only entries whose current value matches
// it exactly. That is the most an honest removal can conclude without a
// record: an entry matching current output is one guardrail would have
// written, and one that does not is left alone rather than guessed at. It is
// strictly narrower than the manifest -- it cannot restore a prior value it
// never saw, and it cannot recognise output from an older release -- which is
// why the report says the removal was a fallback.
func removeByInBandMarkers(existing map[string]any, plane string) RemovalReport {
	report := RemovalReport{}
	switch plane {
	case "claude", "codex":
		report.Removed += removeGuardrailHookGroups(existing, plane)
	case "opencode":
		before, _ := toAnySlice(existing["plugin"])
		absorbGuardrailPluginEntries(existing)
		after, _ := toAnySlice(existing["plugin"])
		report.Removed += len(before) - len(after)
	case "antigravity":
		if _, ok := existing["guardrail"]; ok {
			delete(existing, "guardrail")
			report.Removed++
		}
	}
	report.Removed += removeGeneratedMatches(existing, plane)
	pruneEmpty(existing)
	return report
}

// removeGeneratedMatches deletes entries equal to what this binary generates.
//
// The generated fragment is walked with the same differ the manifest uses,
// against an empty document, so "everything guardrail would write" is
// expressed in exactly the same entry shape as "everything guardrail did
// write". One walker, two sources.
func removeGeneratedMatches(existing map[string]any, plane string) int {
	fragment, ok := fallbackFragment(plane)
	if !ok {
		return 0
	}
	removed := 0
	for _, entry := range ownershipEntries(map[string]any{}, fragment, nil) {
		if entry.Kind != "permission" {
			continue // hooks and plugins already went by their in-band signal
		}
		if entry.Key == "" {
			parent, ok := containerAt(existing, entry.Path[:len(entry.Path)-1])
			if !ok {
				continue
			}
			list, ok := toAnySlice(parent[entry.Path[len(entry.Path)-1]])
			if !ok {
				continue
			}
			want := jsonKey(entry.Value)
			kept := make([]any, 0, len(list))
			for _, v := range list {
				if jsonKey(v) == want {
					removed++
					continue
				}
				kept = append(kept, v)
			}
			parent[entry.Path[len(entry.Path)-1]] = kept
			continue
		}
		container, ok := containerAt(existing, entry.Path)
		if !ok {
			continue
		}
		if current, present := container[entry.Key]; present && jsonKey(current) == jsonKey(entry.Value) {
			delete(container, entry.Key)
			removed++
		}
	}
	return removed
}

// fallbackFragment is what this binary would write for the plane. The plugin
// path is derived the way gen-config defaults it, alongside the config file.
func fallbackFragment(plane string) (map[string]any, bool) {
	base, err := policy.LoadBase()
	if err != nil {
		return nil, false
	}
	switch plane {
	case "claude":
		return ClaudeConfig(base, "guardrail"), true
	case "opencode":
		return OpencodeConfig(base, "guardrail.js"), true
	}
	return nil, false
}

func removeGuardrailHookGroups(existing map[string]any, plane string) int {
	removed := 0
	hooks, _ := existing["hooks"].(map[string]any)
	for event, value := range hooks {
		groups, ok := value.([]any)
		if !ok {
			continue
		}
		kept := groups[:0]
		for _, group := range groups {
			if !ownedByGuardrail(group) || plane == "codex" && !codexOwnedGroup(group) {
				kept = append(kept, group)
				continue
			}
			removed++
		}
		if len(kept) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = kept
		}
	}
	if len(hooks) == 0 {
		delete(existing, "hooks")
	}
	return removed
}

// clearManifest drops the record once its entries are removed. A stale
// manifest would make a later disable try to remove entries that are already
// gone, and would make doctor report drift against a file guardrail no longer
// owns.
func clearManifest(plane string) error {
	path, err := manifestPath(plane)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func mergeInto(path, plane string, frag Fragment, reconcileOwnership bool) error {
	existing, err := ReadJSONObject(path)
	if os.IsNotExist(err) {
		existing = map[string]any{}
	} else if err != nil {
		if _, readErr := os.Stat(path); readErr != nil {
			return err
		}
		return fmt.Errorf("%s is not a JSON object; refusing to overwrite: %w", path, err)
	}
	// The manifest is the diff of this document across the merge, so the
	// pre-merge state has to survive the in-place mutation below.
	before := snapshot(existing)

	removeRetiredBashFloorRules(existing, plane)
	if plane == "" || plane == "opencode" {
		absorbGuardrailPluginEntries(existing)
	}

	if permission, ok := toStringAnyMap(frag["permission"]); ok {
		mergeOpencodePermission(existing, permission)
		withoutPermission := make(Fragment, len(frag)-1)
		for key, value := range frag {
			if key != "permission" {
				withoutPermission[key] = value
			}
		}
		deepMerge(existing, withoutPermission)
	} else {
		deepMerge(existing, frag)
	}

	recordOwnership(plane, path, before, existing, reconcileOwnership)

	out, err := json.MarshalIndent(existing, "", "  ")
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

var retiredBashFloorPatterns = []string{
	"rm -rf *",
	"rm -fr *",
	"rm -r -f *",
	"rm -f -r *",
	"find * -delete",
}

func removeRetiredBashFloorRules(existing map[string]any, plane string) {
	if plane == "claude" {
		if permissions, ok := toStringAnyMap(existing["permissions"]); ok {
			for _, tier := range []string{"deny", "ask"} {
				entries, ok := toAnySlice(permissions[tier])
				if !ok {
					continue
				}
				kept := entries[:0]
				for _, entry := range entries {
					if !retiredBashFloorRule(entry, true) {
						kept = append(kept, entry)
					}
				}
				permissions[tier] = kept
			}
		}
	}

	if plane == "opencode" {
		permission, ok := toStringAnyMap(existing["permission"])
		if !ok {
			return
		}
		bash, ok := toStringAnyMap(permission["bash"])
		if !ok {
			return
		}
		for _, pattern := range retiredBashFloorPatterns {
			delete(bash, pattern)
		}
	}
}

func retiredBashFloorRule(value any, wrapped bool) bool {
	rule, ok := value.(string)
	if !ok {
		return false
	}
	for _, pattern := range retiredBashFloorPatterns {
		if wrapped {
			pattern = "Bash(" + pattern + ")"
		}
		if rule == pattern {
			return true
		}
	}
	return false
}

// absorbGuardrailPluginEntries drops previously deployed guardrail plugin
// entries so a merge replaces them instead of appending (#145): the plugin
// file legitimately lives in more than one location (state root, config
// dir, repository .guardrail/), and opencode loads the first-listed entry —
// a stale earlier deployment would silently win over the fresh one. Foreign
// plugins are untouched; the incoming fragment's entry lands last.
func absorbGuardrailPluginEntries(existing map[string]any) {
	plugins, ok := toAnySlice(existing["plugin"])
	if !ok {
		return
	}
	kept := plugins[:0]
	for _, entry := range plugins {
		entryPath, _ := entry.(string)
		// Match the plugin file name regardless of host separator spelling:
		// a backslashed Windows path in a merged file must absorb on POSIX
		// CI hosts too, so normalize before Base.
		if entryPath != "" && strings.EqualFold(path.Base(strings.ReplaceAll(entryPath, "\\", "/")), "guardrail.js") {
			continue
		}
		kept = append(kept, entry)
	}
	if len(kept) == 0 {
		delete(existing, "plugin")
		return
	}
	existing["plugin"] = kept
}

type orderedPermissionRules map[string]any

func (rules orderedPermissionRules) MarshalJSON() ([]byte, error) {
	keys := make([]string, 0, len(rules))
	for key := range rules {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		iRank := permissionVerdictRank(rules[keys[i]])
		jRank := permissionVerdictRank(rules[keys[j]])
		if iRank != jRank {
			return iRank < jRank
		}
		return keys[i] < keys[j]
	})

	var out bytes.Buffer
	out.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			out.WriteByte(',')
		}
		encodedKey, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		encodedValue, err := json.Marshal(rules[key])
		if err != nil {
			return nil, err
		}
		out.Write(encodedKey)
		out.WriteByte(':')
		out.Write(encodedValue)
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

func permissionVerdictRank(value any) int {
	verdict, _ := value.(string)
	switch verdict {
	case "allow":
		return 1
	case "ask":
		return 2
	case "deny":
		return 3
	default:
		return 0
	}
}

func mergeOpencodePermission(existing map[string]any, generated map[string]any) {
	existingPermission, present := existing["permission"]
	permission, object := toStringAnyMap(existingPermission)
	inheritedFallback := ""
	if !object {
		if present {
			action, isString := existingPermission.(string)
			if !isString || action == "deny" {
				return
			}
			if permissionVerdictRank(action) > 0 {
				inheritedFallback = action
			}
			permission = map[string]any{"*": action}
		} else {
			permission = map[string]any{}
		}
	} else if action, recognized := permission["*"].(string); recognized && permissionVerdictRank(action) > 0 {
		inheritedFallback = action
	}

	for category, value := range generated {
		if category != "bash" && category != "read" && category != "edit" {
			deepMerge(permission, map[string]any{category: value})
			continue
		}
		generatedRules, ok := toStringAnyMap(value)
		if !ok {
			deepMerge(permission, map[string]any{category: value})
			continue
		}
		existingCategory, categoryPresent := permission[category]
		rules, categoryObject := toStringAnyMap(existingCategory)
		if !categoryObject {
			fallback := inheritedFallback
			if categoryPresent {
				action, isString := existingCategory.(string)
				if !isString || action == "deny" {
					continue
				}
				actionRank := permissionVerdictRank(action)
				if actionRank == 0 || actionRank > permissionVerdictRank(fallback) {
					fallback = action
				}
			}
			rules = map[string]any{}
			if fallback != "" {
				rules["*"] = fallback
			}
		} else if inheritedFallback != "" {
			existingFallback, present := rules["*"]
			existingRank := permissionVerdictRank(existingFallback)
			inheritedRank := permissionVerdictRank(inheritedFallback)
			if !present || existingRank > 0 && inheritedRank > existingRank {
				rules["*"] = inheritedFallback
			}
		}
		for pattern, generatedVerdict := range generatedRules {
			existingVerdict, present := rules[pattern]
			existingRank := permissionVerdictRank(existingVerdict)
			generatedRank := permissionVerdictRank(generatedVerdict)
			if !present || existingRank > 0 && generatedRank > existingRank {
				rules[pattern] = generatedVerdict
			}
		}
		permission[category] = rules
	}

	for _, category := range []string{"bash", "read", "edit"} {
		if rules, ok := toStringAnyMap(permission[category]); ok {
			permission[category] = orderedPermissionRules(rules)
		}
	}
	existing["permission"] = permission
}

func deepMerge(dst, src map[string]any) {
	for k, sv := range src {
		dv, present := dst[k]
		if !present {
			dst[k] = sv
			continue
		}
		dm, dok := toStringAnyMap(dv)
		sm, sok := toStringAnyMap(sv)
		if (k == "hooks" || k == "guardrail") && dok && sok {
			mergeHooks(dm, sm)
			continue
		}
		if dok && sok {
			deepMerge(dm, sm)
			continue
		}
		da, daok := toAnySlice(dv)
		sa, saok := toAnySlice(sv)
		if daok && saok {
			dst[k] = unionAppend(da, sa)
			continue
		}
		dst[k] = sv
	}
}

func toAnySlice(v any) ([]any, bool) {
	switch s := v.(type) {
	case []any:
		return s, true
	case []string:
		out := make([]any, len(s))
		for i, x := range s {
			out[i] = x
		}
		return out, true
	default:
		return nil, false
	}
}

// toStringAnyMap recognizes in-memory JSON-object shapes beyond the
// map[string]any that json.Unmarshal produces — fragments built in Go use
// typed leaves like map[string]string (OpencodeConfig's bash/read/edit), and
// those must merge recursively with an existing file's objects, not replace
// them.
func toStringAnyMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[string]string:
		out := make(map[string]any, len(m))
		for k, x := range m {
			out[k] = x
		}
		return out, true
	case orderedPermissionRules:
		return map[string]any(m), true
	default:
		return nil, false
	}
}

func mergeHooks(dst, src map[string]any) {
	for event, sv := range src {
		sGroups, ok := toAnySlice(sv)
		if !ok {
			dst[event] = sv // update non-array values (e.g. named wrapper's "enabled" bool)
			continue
		}
		dGroups, _ := toAnySlice(dst[event])

		out := make([]any, 0, len(dGroups)+len(sGroups))
		seen := map[string]bool{}
		for _, g := range dGroups {
			if ownedByGuardrail(g) {
				continue // drop; src replaces it
			}
			if unmarkedGuardrailGroup(g) {
				continue // absorb legacy pre-marker guardrail entries
			}
			out = append(out, g)
			seen[jsonKey(g)] = true
		}
		for _, g := range sGroups {
			if ownedByGuardrail(g) {
				out = append(out, g)
				continue
			}
			if k := jsonKey(g); !seen[k] {
				seen[k] = true
				out = append(out, g)
			}
		}
		dst[event] = out
	}
}

func ownedByGuardrail(group any) bool {
	m, ok := group.(map[string]any)
	if !ok {
		return false
	}
	id, _ := m["id"].(string)
	return strings.HasPrefix(id, "guardrail-")
}

func jsonKey(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func unionAppend(dst, src []any) []any {
	seen := map[string]bool{}
	for _, v := range dst {
		seen[jsonKey(v)] = true
	}
	out := append([]any{}, dst...)
	for _, v := range src {
		if k := jsonKey(v); !seen[k] {
			seen[k] = true
			out = append(out, v)
		}
	}
	return out
}

// unmarkedGuardrailGroup reports a hook group without a guardrail- marker id
// whose body invokes the guardrail hook command under any binary form —
// released binary, absolute path, Windows exe, or a test binary. These are
// legacy pre-marker entries (ADR-0004) that the marker merge absorbs instead
// of forking around.
func unmarkedGuardrailGroup(group any) bool {
	m, ok := group.(map[string]any)
	if !ok {
		return false
	}
	if id, _ := m["id"].(string); strings.HasPrefix(id, "guardrail-") {
		return false
	}
	raw, err := json.Marshal(m)
	return err == nil && guardrailHookCommand.MatchString(string(raw))
}

// guardrailHookCommand matches "<anything>guardrail<non-space-suffix> hook (claude|antigravity)"
// in any of its binary forms: bare name, absolute path, .exe, or .test.
var guardrailHookCommand = regexp.MustCompile(`guardrail\S* hook (?:claude|antigravity)`)

// CountUnmarkedGuardrailGroups counts legacy unmarked guardrail hook groups in
// a Claude settings document; doctor and lifecycle reconciliation use it.
func CountUnmarkedGuardrailGroups(doc map[string]any) int {
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		return 0
	}
	n := 0
	for _, ev := range hooks {
		groups, ok := ev.([]any)
		if !ok {
			continue
		}
		for _, g := range groups {
			if unmarkedGuardrailGroup(g) {
				n++
			}
		}
	}
	return n
}

// CountUnmarkedGuardrailDuplicates counts guardrail hook groups that have the
// command but no id, ONLY within events that also have a properly marked
// (guardrail- prefixed id) entry — true duplicates needing absorption.
// When Claude Code's serializer has stripped all ids (no marked entries
// anywhere), the hooks are owned, not drift; this returns 0.
func CountUnmarkedGuardrailDuplicates(doc map[string]any) int {
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		return 0
	}
	n := 0
	for _, ev := range hooks {
		groups, ok := ev.([]any)
		if !ok {
			continue
		}
		hasMarked := false
		for _, g := range groups {
			m, ok := g.(map[string]any)
			if !ok {
				continue
			}
			if id, _ := m["id"].(string); strings.HasPrefix(id, "guardrail-") {
				hasMarked = true
				break
			}
		}
		if !hasMarked {
			continue // id-stripped owned hooks, not duplicates
		}
		for _, g := range groups {
			if unmarkedGuardrailGroup(g) {
				n++
			}
		}
	}
	return n
}

// CountUnmarkedAntigravityGroups counts legacy unmarked guardrail hook groups in
// an Antigravity hooks.json document; doctor and lifecycle reconciliation use it.
func CountUnmarkedAntigravityGroups(doc map[string]any) int {
	n := 0
	checkGroupSlice := func(v any) {
		groups, ok := toAnySlice(v)
		if !ok {
			return
		}
		for _, g := range groups {
			if unmarkedGuardrailGroup(g) {
				n++
			}
		}
	}

	if guardrail, ok := doc["guardrail"].(map[string]any); ok {
		for _, ev := range guardrail {
			checkGroupSlice(ev)
		}
	}
	if hooks, ok := doc["hooks"].(map[string]any); ok {
		for _, ev := range hooks {
			checkGroupSlice(ev)
		}
	}
	return n
}

func codexOwnedGroup(group any) bool {
	m, _ := group.(map[string]any)
	id, _ := m["id"].(string)
	return strings.HasPrefix(id, "guardrail-codex-")
}
