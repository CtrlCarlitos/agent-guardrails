package engine

import (
	"net/url"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/bmatcuk/doublestar/v4"
)

var netTools = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "socat": true,
	"scp": true, "rsync": true, "ftp": true, "telnet": true,
}

var fetchTools = map[string]bool{"curl": true, "wget": true}
var interpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true,
	"python": true, "python3": true, "perl": true, "ruby": true, "node": true,
}

func checkDownloadPipeShell(simples []Simple) *policy.Verdict {
	for i := 0; i+1 < len(simples); i++ {
		if len(simples[i].Argv) == 0 || len(simples[i+1].Argv) == 0 {
			continue
		}
		if fetchTools[simples[i].Argv[0]] && interpreters[simples[i+1].Argv[0]] {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P6.download-pipe-shell",
				Reason: "downloaded content piped straight into an interpreter"}
		}
	}
	return nil
}

func checkEgress(s Simple, pol *policy.Policy) *policy.Verdict {
	if !netTools[s.Argv[0]] {
		return nil
	}
	host := extractHost(s.Argv, s.Argv[0])
	if host == "" {
		return nil
	}
	if isLocalHost(host) || hostAllowed(host, pol.Slots.EgressAllowlist) {
		return nil
	}
	return &policy.Verdict{Decision: policy.Deny, RuleID: "P6.egress",
		Reason: "network access to a non-allowlisted host: " + host}
}

func extractHost(argv []string, tool string) string {
	args := nonFlagArgs(argv)
	switch tool {
	case "curl", "wget":
		for _, a := range args {
			if u, err := url.Parse(a); err == nil && u.Host != "" {
				return stripPort(u.Host)
			}
		}
	case "scp", "rsync":
		for _, a := range args {
			if i := strings.Index(a, "@"); i >= 0 {
				rest := a[i+1:]
				if j := strings.Index(rest, ":"); j >= 0 {
					return rest[:j]
				}
			}
		}
	case "nc", "ncat", "telnet":
		if len(args) > 0 {
			return args[0]
		}
	case "ftp":
		if len(args) > 0 {
			return args[0]
		}
	}
	return ""
}

func stripPort(hostport string) string {
	if i := strings.LastIndex(hostport, ":"); i >= 0 {
		return hostport[:i]
	}
	return hostport
}

func isLocalHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	}
	return false
}

func hostAllowed(host string, allowlist []string) bool {
	for _, a := range allowlist {
		if host == a {
			return true
		}
		if ok, _ := doublestar.Match(a, host); ok {
			return true
		}
	}
	return false
}
