package genconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MergeInto deep-merges frag into the JSON object stored at path, creating the
// file if absent. The written file's mode is CreateTemp's default 0600 —
// intentional, as settings files may carry secrets; callers wanting 0644 can
// chmod after.
func MergeInto(path string, frag Fragment) error {
	existing := map[string]any{}
	if raw, err := os.ReadFile(path); err == nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &existing); err != nil {
			return fmt.Errorf("%s is not a JSON object; refusing to overwrite: %w", path, err)
		}
		if existing == nil {
			return fmt.Errorf("%s is not a JSON object; refusing to overwrite: null", path)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}

	deepMerge(existing, frag)

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
	default:
		return nil, false
	}
}

func mergeHooks(dst, src map[string]any) {
	for event, sv := range src {
		sGroups, ok := toAnySlice(sv)
		if !ok {
			continue // non-array values (e.g. a named wrapper's "enabled" bool) are not groups
		}
		dGroups, _ := toAnySlice(dst[event])

		out := make([]any, 0, len(dGroups)+len(sGroups))
		seen := map[string]bool{}
		for _, g := range dGroups {
			if ownedByGuardrail(g) {
				continue // drop; src replaces it
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
