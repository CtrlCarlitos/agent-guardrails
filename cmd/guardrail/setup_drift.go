package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// planeHandlerDrift reports whether the plane's registered Guardrail handlers
// differ from what enablePlaneIntegration would write for the running binary
// — the third reconcile trigger (#317): a binary swap that changes the hook
// command shape must not leave stale handlers behind. It only reads. A plane
// with no settings file is "not registered", which planeIntegrationRegistered
// owns, so it reports no drift; a registration whose wrapper or plugin file
// is missing is registered but stale, so it reports drift.
func planeHandlerDrift(plane string) (drifted bool, err error) {
	binary, err := installedExecutable()
	if err != nil {
		return false, err
	}
	if abs, err := filepath.Abs(binary); err == nil {
		binary = abs
	}
	path, err := planeConfigPath(plane)
	if err != nil {
		return false, err
	}
	doc, err := genconfig.ReadJSONObject(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}

	switch plane {
	case "claude":
		base, err := policy.LoadBase()
		if err != nil {
			return false, err
		}
		want := genconfig.ClaudeConfig(base, binary)
		owned := claimedBy("guardrail-", "hook claude")
		return !slices.Equal(ownedHookGroups(doc["hooks"], owned), ownedHookGroups(want["hooks"], owned)), nil
	case "antigravity":
		want := genconfig.AntigravityConfig(binary)
		owned := claimedBy("guardrail-", "hook antigravity")
		return !slices.Equal(ownedHookGroups(doc["guardrail"], owned), ownedHookGroups(want["guardrail"], owned)), nil
	case "codex":
		want := genconfig.CodexConfigFor(path, binary)
		owned := claimedBy("guardrail-codex-", "")
		if !slices.Equal(ownedHookGroups(doc["hooks"], owned), ownedHookGroups(want["hooks"], owned)) {
			return true, nil
		}
		return fileDiffers(filepath.Join(filepath.Dir(path), "guardrail-hook.cmd"), genconfig.CodexWrapperContent(binary))
	case "opencode":
		dir, err := planePluginDir()
		if err != nil {
			return false, err
		}
		pluginPath := filepath.Join(dir, "guardrail.js")
		if abs, err := filepath.Abs(pluginPath); err == nil {
			pluginPath = abs
		}
		registered := false
		plugins, _ := doc["plugin"].([]any)
		for _, entry := range plugins {
			s, ok := entry.(string)
			if !ok || filepath.Base(s) != "guardrail.js" {
				continue
			}
			if filepath.Clean(s) != pluginPath {
				return true, nil
			}
			registered = true
		}
		if !registered {
			return true, nil
		}
		return fileDiffers(pluginPath, genconfig.OpencodePluginFor(binary))
	default:
		return false, fmt.Errorf("unsupported plane %q", plane)
	}
}

// claimedBy returns the ownership rule for a hook group: its id carries
// idPrefix, or (when marker is non-empty) one of its commands contains marker.
// The marker fallback exists because Claude Code strips the undocumented id.
func claimedBy(idPrefix, marker string) func(group map[string]any) bool {
	return func(group map[string]any) bool {
		if id, _ := group["id"].(string); strings.HasPrefix(id, idPrefix) {
			return true
		}
		if marker == "" {
			return false
		}
		handlers, _ := group["hooks"].([]any)
		for _, raw := range handlers {
			h, _ := raw.(map[string]any)
			if command, _ := h["command"].(string); strings.Contains(command, marker) {
				return true
			}
		}
		return false
	}
}

// ownedHookGroups projects every owned hook group of an event → groups
// container to a sorted list of canonical JSON strings: the event name, the
// matcher, and each handler's type, command, commandWindows and timeout, in
// handler order. The group id is dropped (Claude Code strips it), as are any
// other keys a host may add. Non-array values in the container
// (antigravity's "enabled") are skipped. The container is round-tripped
// through JSON first so generated values (ints, typed slices) compare equal
// to the same values read back from disk.
func ownedHookGroups(container any, owned func(map[string]any) bool) []string {
	raw, err := json.Marshal(container)
	if err != nil {
		return nil
	}
	var events map[string]any
	if json.Unmarshal(raw, &events) != nil {
		return nil
	}
	var out []string
	for event, ev := range events {
		groups, _ := ev.([]any)
		for _, rawGroup := range groups {
			group, ok := rawGroup.(map[string]any)
			if !ok || !owned(group) {
				continue
			}
			projected := map[string]any{"event": event, "matcher": group["matcher"]}
			var handlers []any
			rawHandlers, _ := group["hooks"].([]any)
			for _, rawHandler := range rawHandlers {
				h, _ := rawHandler.(map[string]any)
				kept := map[string]any{}
				for _, field := range []string{"type", "command", "commandWindows", "timeout"} {
					if v, ok := h[field]; ok {
						kept[field] = v
					}
				}
				handlers = append(handlers, kept)
			}
			projected["hooks"] = handlers
			line, err := json.Marshal(projected)
			if err != nil {
				continue
			}
			out = append(out, string(line))
		}
	}
	slices.Sort(out)
	return out
}

// fileDiffers reports whether path is absent or its bytes differ from want.
func fileDiffers(path string, want []byte) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	return !bytes.Equal(raw, want), nil
}
