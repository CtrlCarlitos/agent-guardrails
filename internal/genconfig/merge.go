package genconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	permission, ok := toStringAnyMap(existing["permission"])
	if !ok {
		permission = map[string]any{}
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
		rules, ok := toStringAnyMap(permission[category])
		if !ok {
			rules = map[string]any{}
		}
		for pattern, generatedVerdict := range generatedRules {
			existingVerdict, present := rules[pattern]
			if !present || permissionVerdictRank(generatedVerdict) > permissionVerdictRank(existingVerdict) {
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
