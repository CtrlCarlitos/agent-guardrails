package main

import (
	"bytes"
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
		return !slices.Equal(ownedHookCommands(doc["hooks"], owned, "command"), ownedHookCommands(want["hooks"], owned, "command")), nil
	case "antigravity":
		want := genconfig.AntigravityConfig(binary)
		owned := claimedBy("guardrail-", "hook antigravity")
		return !slices.Equal(ownedHookCommands(doc["guardrail"], owned, "command"), ownedHookCommands(want["guardrail"], owned, "command")), nil
	case "codex":
		want := genconfig.CodexConfigFor(path, binary)
		owned := claimedBy("guardrail-codex-", "")
		if !slices.Equal(ownedHookCommands(doc["hooks"], owned, "command", "commandWindows"), ownedHookCommands(want["hooks"], owned, "command", "commandWindows")) {
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

// ownedHookCommands collects, as a sorted multiset, the named command fields
// of every handler inside owned hook groups of an event → groups container.
// Non-array values in the container (antigravity's "enabled") are skipped.
func ownedHookCommands(container any, owned func(map[string]any) bool, fields ...string) []string {
	events, _ := container.(map[string]any)
	var out []string
	for _, ev := range events {
		groups, _ := ev.([]any)
		for _, raw := range groups {
			group, ok := raw.(map[string]any)
			if !ok || !owned(group) {
				continue
			}
			handlers, _ := group["hooks"].([]any)
			for _, rawHandler := range handlers {
				h, _ := rawHandler.(map[string]any)
				for _, field := range fields {
					if command, ok := h[field].(string); ok {
						out = append(out, field+"\x00"+command)
					}
				}
			}
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
