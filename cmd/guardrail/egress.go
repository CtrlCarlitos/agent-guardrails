package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/BurntSushi/toml"
	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func init() {
	approval.RegisterAction("web-host-grant", executeWebHostApproval)
	approval.RegisterAction("web-host-revoke", executeWebHostApproval)
}

func executeWebHostApproval(r approval.Request) error {
	if (r.Action != "web-host-grant" && r.Action != "web-host-revoke") || policy.ValidateWebHost(r.Host) != nil || !filepath.IsAbs(r.RepoRoot) || (r.Scope != approval.RepoScope && r.Scope != approval.GlobalScope) {
		return fmt.Errorf("invalid approved web-host action")
	}
	grant := r.Action == "web-host-grant"
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		return err
	}
	if r.Scope == approval.GlobalScope {
		op.GlobalWebHosts = updateHost(op.GlobalWebHosts, r.Host, grant)
		return writeOperatorConfig(op)
	}
	if err := os.MkdirAll(r.RepoRoot, 0o755); err != nil {
		return err
	}
	repo := filepath.Clean(r.RepoRoot)
	repoGrant := op.Repos[repo]
	repoGrant.WebHosts = updateHost(repoGrant.WebHosts, r.Host, grant)
	if op.Repos == nil {
		op.Repos = map[string]policy.RepoGrant{}
	}
	op.Repos[repo] = repoGrant
	if err := writeOperatorConfig(op); err != nil {
		return err
	}
	return writeOverlayWebHost(filepath.Join(repo, "guardrail.toml"), r.Host, grant)
}

func updateHost(hosts []string, host string, grant bool) []string {
	if grant {
		if !slices.Contains(hosts, host) {
			return append(hosts, host)
		}
		return hosts
	}
	return slices.DeleteFunc(hosts, func(existing string) bool { return existing == host })
}

func writeOperatorConfig(op *policy.OperatorConfig) error {
	if op == nil {
		return fmt.Errorf("operator config unavailable")
	}
	raw := map[string]any{"web_hosts": map[string]any{"global": op.GlobalWebHosts}}
	for root, grant := range op.Repos {
		raw[root] = grant
	}
	var out bytes.Buffer
	if err := toml.NewEncoder(&out).Encode(raw); err != nil {
		return err
	}
	path := policy.OperatorConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writePrivateFile(path, out.Bytes(), 0o600)
}

func writeOverlayWebHost(path, host string, grant bool) error {
	raw := map[string]any{}
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if _, err := toml.Decode(string(content), &raw); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	slots, ok := raw["slots"].(map[string]any)
	if !ok {
		slots = map[string]any{}
		raw["slots"] = slots
	}
	hosts := []string{}
	if existing, ok := slots["web_hosts"].([]any); ok {
		for _, entry := range existing {
			if value, ok := entry.(string); ok {
				hosts = append(hosts, value)
			}
		}
	}
	slots["web_hosts"] = updateHost(hosts, host, grant)
	var out bytes.Buffer
	if err := toml.NewEncoder(&out).Encode(raw); err != nil {
		return err
	}
	return writePrivateFile(path, out.Bytes(), mode)
}

func writePrivateFile(path string, content []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".guardrail-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
