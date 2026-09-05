package engine

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/bmatcuk/doublestar/v4"
)

var netTools = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "socat": true,
	"scp": true, "rsync": true, "ftp": true, "telnet": true, "ssh": true, "sftp": true,
}

var fetchTools = map[string]bool{"curl": true, "wget": true}
var interpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true,
	"python": true, "python3": true, "perl": true, "ruby": true, "node": true,
}

func checkDownloadPipeShell(simples []Simple) *policy.Verdict {
	for i, fetch := range simples {
		if !fetchTools[head(fetch.Argv)] {
			continue
		}
		for _, interpreter := range simples[i+1:] {
			if !interpreters[head(interpreter.Argv)] || !laterPipelineStage(fetch, interpreter) {
				continue
			}
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P6.download-pipe-shell",
				Reason: "downloaded content reaches an interpreter later in the same pipeline"}
		}
	}
	return nil
}

func laterPipelineStage(earlier, later Simple) bool {
	for _, left := range earlier.pipelines {
		for _, right := range later.pipelines {
			if left.id == right.id && left.stage < right.stage {
				return true
			}
		}
	}
	return false
}

func checkPackageInstall(s Simple) *policy.Verdict {
	command := head(s.Argv)
	joined := strings.Join(s.Argv, " ")

	isPip := command == "pip" || command == "pip3"
	if isPip && strings.Contains(joined, "install") {
		if hasAnyFlag(s.Argv, "", "--index-url", "--extra-index-url") || strings.Contains(joined, "git+http") {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P6.registry-redirect",
				Reason: "pip install bypassing the normal index/lockfile review path"}
		}
		return &policy.Verdict{Decision: policy.Ask, RuleID: "P6.package-install",
			Reason: "new Python dependency — runs install scripts with your privileges"}
	}

	if command == "npm" && hasAnyFlag(s.Argv, "", "--registry") {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P6.registry-redirect",
			Reason: "npm install with a redirected registry"}
	}

	switch command {
	case "npm", "yarn", "pnpm":
		for _, a := range nonFlagArgs(s.Argv) {
			if a == "install" || a == "i" || a == "ci" || a == "add" {
				return &policy.Verdict{Decision: policy.Ask, RuleID: "P6.package-install",
					Reason: "new JS dependency — runs postinstall scripts with your privileges"}
			}
		}
	case "gem":
		if len(s.Argv) > 1 && s.Argv[1] == "install" {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P6.package-install", Reason: "new Ruby gem install"}
		}
	case "cargo":
		if len(s.Argv) > 1 && s.Argv[1] == "install" {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P6.package-install", Reason: "new Rust crate install"}
		}
	case "go":
		if len(s.Argv) > 1 && (s.Argv[1] == "install" || s.Argv[1] == "get") {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P6.package-install", Reason: "new Go module fetched and built"}
		}
	case "apt", "apt-get", "brew":
		if len(s.Argv) > 1 && s.Argv[1] == "install" {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P6.package-install", Reason: "new system package install"}
		}
	}
	return nil
}

func checkEgress(s Simple, pol *policy.Policy) *policy.Verdict {
	command := head(s.Argv)
	if !netTools[command] {
		return nil
	}
	host, networkTarget, err := extractHost(s.Argv, command)
	if err != nil {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P6.egress",
			Reason: "network target could not be resolved safely: " + err.Error()}
	}
	if !networkTarget {
		return nil
	}
	if isLocalHost(host) || hostAllowed(host, pol.Slots.EgressAllowlist) {
		return nil
	}
	return &policy.Verdict{Decision: policy.Deny, RuleID: "P6.egress",
		Reason: "network access to a non-allowlisted host: " + host}
}

type networkOptionSpec struct {
	shortFlags         string
	shortValues        string
	longFlags          map[string]bool
	longValues         map[string]bool
	longTargetValues   map[string]bool
	stopAtFirstOperand bool
}

func networkOptionNames(names ...string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, name := range names {
		out[name] = true
	}
	return out
}

var curlOptions = networkOptionSpec{
	shortFlags:  "#046aBfFGghIiJklLMnNOPpqRsSVZ",
	shortValues: "AbcCdDeEFHKmoPQrTtuUwXxYyz",
	longFlags: networkOptionNames(
		"--anyauth", "--basic", "--compressed", "--create-dirs", "--digest", "--disable",
		"--fail", "--fail-early", "--fail-with-body", "--get", "--globoff", "--head",
		"--http0.9", "--http1.0", "--http1.1", "--http2", "--http2-prior-knowledge",
		"--include", "--insecure", "--ipv4", "--ipv6", "--location", "--location-trusted",
		"--cert-status", "--netrc", "--netrc-optional", "--no-buffer", "--no-keepalive",
		"--no-progress-meter", "--ntlm", "--parallel", "--path-as-is", "--progress-bar",
		"--proxytunnel", "--remote-header-name", "--remote-name", "--remote-name-all",
		"--retry-all-errors", "--retry-connrefused", "--show-error", "--silent", "--ssl",
		"--ssl-reqd", "--tcp-fastopen", "--tcp-nodelay", "--tlsv1", "--trace-time",
		"--use-ascii", "--verbose", "--version",
	),
	longValues: networkOptionNames(
		"--abstract-unix-socket", "--alt-svc", "--aws-sigv4", "--cacert", "--capath",
		"--cert", "--cert-type", "--ciphers", "--config", "--connect-timeout",
		"--connect-to", "--cookie", "--cookie-jar", "--create-file-mode", "--crlfile",
		"--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode",
		"--delegation", "--dns-interface", "--dns-ipv4-addr", "--dns-ipv6-addr", "--dns-servers",
		"--dump-header", "--egd-file", "--engine", "--expect100-timeout", "--form",
		"--form-string", "--ftp-account", "--ftp-alternative-to-user", "--ftp-method",
		"--ftp-port", "--happy-eyeballs-timeout-ms", "--header", "--hostpubmd5", "--interface",
		"--key", "--key-type", "--krb", "--libcurl", "--limit-rate", "--local-port",
		"--max-filesize", "--max-redirs", "--max-time", "--netrc-file", "--oauth2-bearer", "--output",
		"--output-dir", "--pass", "--pinnedpubkey", "--preproxy", "--proto", "--proto-default",
		"--proto-redir", "--proxy", "--proxy-cacert", "--proxy-capath", "--proxy-cert",
		"--proxy-cert-type", "--proxy-ciphers", "--proxy-crlfile", "--proxy-header", "--proxy-key",
		"--proxy-key-type", "--proxy-pass", "--proxy-service-name", "--proxy-ssl-allow-beast",
		"--proxy-tls13-ciphers", "--proxy-tlsauthtype", "--proxy-tlspassword", "--proxy-tlsuser",
		"--proxy-user", "--pubkey", "--quote", "--range", "--referer", "--request",
		"--request-target", "--resolve", "--retry", "--retry-delay", "--retry-max-time",
		"--service-name", "--socks4", "--socks4a", "--socks5", "--socks5-hostname",
		"--speed-limit", "--speed-time", "--stderr", "--telnet-option", "--tftp-blksize",
		"--time-cond", "--tls-max", "--tls13-ciphers", "--trace", "--trace-ascii",
		"--unix-socket", "--upload-file", "--user", "--user-agent", "--write-out",
	),
	longTargetValues: networkOptionNames("--url"),
}

var wgetOptions = networkOptionSpec{
	shortFlags:  "bcEFHhLNnpqrSv",
	shortValues: "aABCDeIiloOPQtTUwX",
	longFlags: networkOptionNames(
		"--adjust-extension", "--auth-no-challenge", "--background", "--backup-converted",
		"--continue", "--convert-links", "--content-disposition", "--debug", "--delete-after",
		"--directories", "--force-directories", "--force-html", "--help",
		"--html-extension", "--http-keep-alive", "--ignore-case", "--ignore-length", "--inet4-only",
		"--inet6-only", "--mirror", "--no-cache", "--no-check-certificate", "--no-clobber",
		"--no-config", "--no-directories", "--no-glob", "--no-host-directories", "--no-http-keep-alive",
		"--no-iri", "--no-netrc", "--no-parent", "--no-proxy", "--no-remove-listing",
		"--no-use-server-timestamps", "--page-requisites", "--passive-ftp", "--quiet", "--random-wait",
		"--recursive", "--relative", "--server-response",
		"--show-progress", "--spider", "--timestamping", "--trust-server-names", "--verbose", "--version",
	),
	longValues: networkOptionNames(
		"--accept", "--accept-regex", "--base", "--bind-address", "--ca-certificate", "--ca-directory",
		"--certificate", "--certificate-type", "--config", "--connect-timeout", "--cut-dirs",
		"--directory-prefix", "--dns-timeout", "--domains", "--exclude-directories", "--exclude-domains",
		"--ftp-user", "--header", "--http-password", "--http-user", "--input-file", "--level", "--limit-rate",
		"--load-cookies", "--local-encoding", "--max-redirect", "--no", "--output-document",
		"--output-file", "--password", "--post-data", "--post-file", "--private-key",
		"--private-key-type", "--progress", "--protocol-directories", "--proxy-password", "--proxy-user",
		"--quota", "--read-timeout", "--referer", "--reject", "--reject-regex", "--remote-encoding",
		"--restrict-file-names", "--save-cookies",
		"--secure-protocol", "--timeout", "--tries", "--user", "--user-agent", "--wait", "--waitretry",
	),
}

var sshOptions = networkOptionSpec{
	shortFlags:         "46AaCfGgKkMNnqstTVvXxYy",
	shortValues:        "BbcDEeFIiJLlmOoPpQRSWw",
	stopAtFirstOperand: true,
}

var sftpOptions = networkOptionSpec{
	shortFlags:         "46AaCfNpqrv",
	shortValues:        "BbcDFiJloPRS",
	stopAtFirstOperand: true,
}

func networkOperands(argv []string, tool string, spec networkOptionSpec) ([]string, error) {
	var operands []string
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || arg == "-" || !strings.HasPrefix(arg, "-") {
			operands = append(operands, arg)
			if spec.stopAtFirstOperand {
				options = false
			}
			continue
		}
		if strings.HasPrefix(arg, "--") {
			name, _, attached := strings.Cut(arg, "=")
			switch {
			case spec.longFlags[name] && !attached:
			case spec.longValues[name] || spec.longTargetValues[name]:
				value := ""
				if !attached {
					if i+1 >= len(argv) {
						return nil, needsValue(tool, arg)
					}
					i++
					value = argv[i]
				} else {
					_, value, _ = strings.Cut(arg, "=")
				}
				if spec.longTargetValues[name] {
					operands = append(operands, value)
				}
			default:
				return nil, unknownOpt(tool, arg)
			}
			continue
		}
		short := strings.TrimPrefix(arg, "-")
		for j := 0; j < len(short); j++ {
			option := short[j]
			switch {
			case strings.ContainsRune(spec.shortFlags, rune(option)):
				continue
			case strings.ContainsRune(spec.shortValues, rune(option)):
				if j+1 == len(short) {
					if i+1 >= len(argv) {
						return nil, needsValue(tool, "-"+string(option))
					}
					i++
				}
				j = len(short)
			default:
				return nil, unknownOpt(tool, "-"+string(option))
			}
		}
	}
	return operands, nil
}

func extractHost(argv []string, tool string) (string, bool, error) {
	switch tool {
	case "curl", "wget":
		spec := curlOptions
		if tool == "wget" {
			spec = wgetOptions
		}
		args, err := networkOperands(argv, tool, spec)
		if err != nil {
			return "", true, err
		}
		var host string
		for _, a := range args {
			candidate, err := hostFromURLCandidate(a)
			if err != nil {
				return "", true, err
			}
			if host != "" && host != candidate {
				return "", true, fmt.Errorf("multiple different hosts are ambiguous")
			}
			host = candidate
		}
		if host == "" {
			return "", true, fmt.Errorf("missing host")
		}
		return host, true, nil
	case "scp", "rsync":
		args := nonFlagArgs(argv)
		for _, a := range args {
			if i := strings.Index(a, "@"); i >= 0 {
				rest := a[i+1:]
				if j := strings.Index(rest, ":"); j >= 0 {
					return rest[:j], true, nil
				}
				continue
			}
			if j := strings.Index(a, "::"); j > 0 && len(a[:j]) > 1 && !strings.Contains(a[:j], "/") {
				return a[:j], true, nil
			}
			if j := strings.Index(a, ":"); j > 0 && len(a[:j]) > 1 && !strings.Contains(a[:j], "/") {
				return a[:j], true, nil
			}
		}
		return "", false, nil
	case "ssh", "sftp":
		spec := sshOptions
		if tool == "sftp" {
			spec = sftpOptions
		}
		args, err := networkOperands(argv, tool, spec)
		if err != nil {
			return "", true, err
		}
		if len(args) == 0 {
			return "", true, fmt.Errorf("missing host")
		}
		host, err := hostFromURLCandidate(args[0])
		return host, true, err
	case "nc", "ncat", "telnet":
		args := nonFlagArgs(argv)
		if len(args) > 0 {
			return stripPort(args[0]), true, nil
		}
	case "ftp":
		args := nonFlagArgs(argv)
		if len(args) > 0 {
			return stripPort(args[0]), true, nil
		}
	}
	return "", true, fmt.Errorf("missing or unrecognized host")
}

func hostFromURLCandidate(candidate string) (string, error) {
	if ip := net.ParseIP(strings.Trim(candidate, "[]")); ip != nil {
		return strings.ToLower(ip.String()), nil
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return "", fmt.Errorf("malformed target %q", candidate)
	}
	if parsed.Hostname() == "" {
		parsed, err = url.Parse("//" + candidate)
	}
	if err != nil || parsed.Hostname() == "" {
		return "", fmt.Errorf("target %q has no resolvable host", candidate)
	}
	return strings.ToLower(strings.TrimSuffix(parsed.Hostname(), ".")), nil
}

func stripPort(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.Trim(host, "[]")
	}
	if strings.Count(hostport, ":") == 1 {
		if i := strings.LastIndex(hostport, ":"); i >= 0 {
			return hostport[:i]
		}
	}
	return strings.Trim(hostport, "[]")
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
