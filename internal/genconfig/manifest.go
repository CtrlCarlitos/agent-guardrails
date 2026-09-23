package genconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"
)

// The ownership manifest (#278, ADR-0028 phase-1 precondition).
//
// Hook groups carry an `id: guardrail-…` marker and can be removed precisely.
// Permission entries cannot: they are bare strings and bare keys sharing a
// container with the operator's own, and nothing in the file says whose is
// whose. That produced three defects -- `plane disable claude` removed nothing,
// `plane disable opencode` removed everything including the operator's plugins,
// and drift was invisible -- so the record lives beside the file instead.
//
// The manifest is the *diff* of the target document across a merge: what the
// file gained, and what each changed key held before. That is what makes
// removal able to restore rather than delete, and it is one mechanism for
// every plane rather than a schema per config shape.

// manifestVersion is the on-disk format version. A manifest written by a newer
// binary is ignored rather than guessed at; removal then falls back.
const manifestVersion = 1

// ManifestEntry is one thing guardrail wrote.
//
// Key distinguishes the two containers a config can present. With a Key the
// container is an object and Value is what guardrail stored there, so removal
// restores Prior or deletes the key. Without one the container is an array and
// Value is an element guardrail appended, so removal drops that element and
// leaves every sibling alone.
type ManifestEntry struct {
	// Kind is for reporting, not mechanism: permission, hook, plugin, other.
	// It is what lets a hooks-only manifest read as a normal manifest once the
	// floor retires (ADR-0028) rather than as a degenerate one.
	Kind string `json:"kind"`
	// Path names the container, as JSON object keys from the document root.
	Path     []string `json:"path"`
	Key      string   `json:"key,omitempty"`
	Value    any      `json:"value"`
	Prior    any      `json:"prior,omitempty"`
	HadPrior bool     `json:"had_prior,omitempty"`
}

type Manifest struct {
	Version   int             `json:"version"`
	Plane     string          `json:"plane"`
	Target    string          `json:"target"`
	WrittenAt string          `json:"written_at"`
	Entries   []ManifestEntry `json:"entries"`
}

// ManifestDir is $XDG_STATE_HOME/guardrail/manifests (%LOCALAPPDATA% on
// Windows), following the coverage cache: this is guardrail's record of its
// own actions, not operator-owned configuration. Putting it in the operator
// config directory would imply they maintain it, and another file to keep in
// step is the problem rather than the fix.
func ManifestDir() (string, error) {
	if runtime.GOOS == "windows" {
		base := os.Getenv("LOCALAPPDATA")
		if base == "" || !filepath.IsAbs(base) {
			return "", fmt.Errorf("LOCALAPPDATA must be an absolute path")
		}
		return filepath.Join(base, "guardrail", "manifests"), nil
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "guardrail", "manifests"), nil
}

func manifestPath(plane string) (string, error) {
	dir, err := ManifestDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, plane+".json"), nil
}

// LoadManifest reads a plane's manifest. A missing, unreadable or
// newer-versioned manifest returns nil without an error: every installation
// that exists today has none, and state directories get cleared, so absence is
// an ordinary condition the caller degrades through rather than an failure.
func LoadManifest(plane string) (*Manifest, error) {
	path, err := manifestPath(plane)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, nil
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil || m.Version != manifestVersion {
		return nil, nil
	}
	return &m, nil
}

func saveManifest(m Manifest) error {
	path, err := manifestPath(m.Plane)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".guardrail-manifest-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// snapshot deep-copies a document so the pre-merge state survives the merge's
// in-place mutation. The diff needs both sides.
func snapshot(doc map[string]any) map[string]any {
	raw, err := json.Marshal(doc)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return map[string]any{}
	}
	return out
}

// recordOwnership accumulates the manifest for a merge that just happened. A
// failure here must not fail the merge: the settings file is already correct,
// and removal degrades through a missing manifest by design.
//
// Accumulates rather than replaces, because merging is idempotent and gets run
// repeatedly -- `plane enable` twice, a sync, a reinstall. The second merge
// changes nothing, so its diff is empty, and writing that diff would erase the
// record of everything the first merge wrote. The entries would still be in
// the settings file with nothing left that knows they are guardrail's, which
// is the exact condition the manifest exists to end.
func recordOwnership(plane, target string, before, after map[string]any) {
	if plane == "" {
		return
	}
	fresh := ownershipEntries(before, after, nil)
	if existing, _ := LoadManifest(plane); existing != nil && sameTarget(existing.Target, target) {
		fresh = mergeOwnership(existing.Entries, fresh)
	}
	_ = saveManifest(Manifest{
		Version:   manifestVersion,
		Plane:     plane,
		Target:    target,
		WrittenAt: time.Now().UTC().Format(time.RFC3339),
		Entries:   fresh,
	})
}

// entryIdentity names the slot an entry occupies: a key in an object, or a
// particular element of an array.
func entryIdentity(e ManifestEntry) string {
	if e.Key == "" {
		return joinPath(e.Path) + "\x00[]" + jsonKey(e.Value)
	}
	return joinPath(e.Path) + "\x00" + e.Key
}

// mergeOwnership folds a new merge's diff into the recorded one.
//
// Where both describe the same slot, the *recorded* Prior wins. On a second
// merge the value guardrail would see as "prior" is its own first write, and
// restoring that on removal would leave guardrail's entry behind under the
// name of the operator's. The first prior is the only one that was ever
// theirs.
func mergeOwnership(recorded, fresh []ManifestEntry) []ManifestEntry {
	index := make(map[string]int, len(recorded))
	out := append([]ManifestEntry{}, recorded...)
	for i, e := range out {
		index[entryIdentity(e)] = i
	}
	for _, e := range fresh {
		if i, seen := index[entryIdentity(e)]; seen {
			e.Prior, e.HadPrior = out[i].Prior, out[i].HadPrior
			out[i] = e
			continue
		}
		index[entryIdentity(e)] = len(out)
		out = append(out, e)
	}
	return out
}

// manifestKind labels an entry by the top-level key it sits under, so doctor
// can report "3 hook entries" rather than a path dump.
func manifestKind(path []string) string {
	if len(path) == 0 {
		return "other"
	}
	switch path[0] {
	case "permissions", "permission":
		return "permission"
	case "hooks", "guardrail":
		return "hook"
	case "plugin":
		return "plugin"
	}
	return "other"
}

// ownershipEntries diffs the document across a merge and returns what
// guardrail added or changed.
//
// The diff is the ownership record, and that has a property worth stating:
// an entry guardrail generated but did not actually change -- because the
// operator already had the same value, or a stricter one that won -- produces
// no diff, so guardrail does not claim it and removal leaves it alone. The
// alternative, deriving ownership from the generated fragment, would claim
// entries guardrail never wrote.
func ownershipEntries(before, after map[string]any, path []string) []ManifestEntry {
	var out []ManifestEntry
	keys := make([]string, 0, len(after))
	for k := range after {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		newValue := after[key]
		oldValue, had := before[key]
		here := append(append([]string{}, path...), key)

		// toStringAnyMap, not a bare type assertion: the merged document
		// holds orderedPermissionRules (a named map type with its own
		// MarshalJSON) wherever opencode's permission categories live. A bare
		// assertion misses those, and the diff then records the whole
		// category as one owned value -- which would make removal revert
		// every entry in it, including ones the operator added afterwards.
		// That is the defect this manifest exists to prevent, so the walker
		// must descend into those maps like any other.
		newMap, newIsMap := toStringAnyMap(newValue)
		oldMap, oldIsMap := toStringAnyMap(oldValue)
		if newIsMap && (!had || oldIsMap) {
			if !oldIsMap {
				oldMap = map[string]any{}
			}
			out = append(out, ownershipEntries(oldMap, newMap, here)...)
			continue
		}

		newList, newIsList := toAnySlice(newValue)
		oldList, oldIsList := toAnySlice(oldValue)
		if newIsList && (!had || oldIsList) {
			seen := map[string]bool{}
			for _, v := range oldList {
				seen[jsonKey(v)] = true
			}
			for _, v := range newList {
				if !seen[jsonKey(v)] {
					out = append(out, ManifestEntry{Kind: manifestKind(here), Path: here, Value: v})
				}
			}
			continue
		}

		if had && jsonKey(oldValue) == jsonKey(newValue) {
			continue // guardrail changed nothing here, so it owns nothing here
		}
		entry := ManifestEntry{Kind: manifestKind(path), Path: path, Key: key, Value: newValue}
		if had {
			entry.Prior, entry.HadPrior = oldValue, true
		}
		out = append(out, entry)
	}
	return out
}

// containerAt walks to the object holding the final path segment.
func containerAt(doc map[string]any, path []string) (map[string]any, bool) {
	cur := doc
	for _, segment := range path {
		next, ok := toStringAnyMap(cur[segment])
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// RemovalReport says what a removal actually did, because the interesting
// cases are the ones it declined to touch.
type RemovalReport struct {
	Removed  int
	Restored int
	// Edited are entries whose current value no longer matches what guardrail
	// wrote. They are left in place: the operator changed them since, they are
	// theirs now, and silently reverting an edit is the same class of harm as
	// deleting one.
	Edited []string
	// Fallback is set when no manifest was available and removal had to work
	// from the in-band markers alone.
	Fallback bool
}

// applyManifestRemoval undoes exactly what the manifest records.
func applyManifestRemoval(doc map[string]any, m *Manifest) RemovalReport {
	report := RemovalReport{}
	// Reverse order so nested containers empty from the inside out.
	for i := len(m.Entries) - 1; i >= 0; i-- {
		entry := m.Entries[i]
		if entry.Key == "" {
			parent, ok := containerAt(doc, entry.Path[:len(entry.Path)-1])
			if !ok {
				continue
			}
			list, ok := parent[entry.Path[len(entry.Path)-1]].([]any)
			if !ok {
				continue
			}
			want := jsonKey(entry.Value)
			kept := make([]any, 0, len(list))
			for _, v := range list {
				if jsonKey(v) == want {
					report.Removed++
					continue
				}
				kept = append(kept, v)
			}
			parent[entry.Path[len(entry.Path)-1]] = kept
			continue
		}
		container, ok := containerAt(doc, entry.Path)
		if !ok {
			continue
		}
		current, present := container[entry.Key]
		if !present {
			continue
		}
		if jsonKey(current) != jsonKey(entry.Value) {
			report.Edited = append(report.Edited, joinPath(append(append([]string{}, entry.Path...), entry.Key)))
			continue
		}
		if entry.HadPrior {
			container[entry.Key] = entry.Prior
			report.Restored++
			continue
		}
		delete(container, entry.Key)
		report.Removed++
	}
	pruneEmpty(doc)
	return report
}

func joinPath(path []string) string {
	out := ""
	for i, segment := range path {
		if i > 0 {
			out += "."
		}
		out += segment
	}
	return out
}

// pruneEmpty drops containers guardrail emptied. A container the operator also
// uses is not empty, so it survives; this only removes the ones that exist
// solely because guardrail created them.
func pruneEmpty(doc map[string]any) {
	for key, value := range doc {
		switch v := value.(type) {
		case map[string]any:
			pruneEmpty(v)
			if len(v) == 0 {
				delete(doc, key)
			}
		case []any:
			if len(v) == 0 {
				delete(doc, key)
			}
		}
	}
}
