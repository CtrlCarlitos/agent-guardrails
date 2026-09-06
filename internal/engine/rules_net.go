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
	hosts, networkTarget, err := extractHosts(s.Argv, command)
	if err != nil {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P6.egress",
			Reason: "network target could not be resolved safely: " + err.Error()}
	}
	if !networkTarget {
		return nil
	}
	for _, host := range hosts {
		if isLocalHost(host) || hostAllowed(host, pol.Slots.EgressAllowlist) {
			continue
		}
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P6.egress",
			Reason: "network access to a non-allowlisted host: " + host}
	}
	return nil
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

type parsedNetworkArgs struct {
	operands           []string
	connectionHosts    []string
	hostOverrides      []string
	remoteCommands     []string
	localCommands      []string
	permitLocalCommand bool
}

func parseNetworkArgs(argv []string, tool string, spec networkOptionSpec) (parsedNetworkArgs, error) {
	var parsed parsedNetworkArgs
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || arg == "-" || !strings.HasPrefix(arg, "-") {
			parsed.operands = append(parsed.operands, arg)
			if spec.stopAtFirstOperand {
				options = false
			}
			continue
		}
		if strings.HasPrefix(arg, "--") {
			name, value, attached := strings.Cut(arg, "=")
			if !attached && (spec.longValues[name] || spec.longTargetValues[name]) {
				if i+1 >= len(argv) {
					return parsed, needsValue(tool, arg)
				}
				i++
				value = argv[i]
			}
			switch {
			case spec.longFlags[name] && !attached:
			case spec.longValues[name] || spec.longTargetValues[name]:
				if err := addNetworkOptionTarget(&parsed, tool, name, value); err != nil {
					return parsed, err
				}
				if spec.longTargetValues[name] {
					parsed.operands = append(parsed.operands, value)
				}
			default:
				return parsed, unknownOpt(tool, arg)
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
				value := ""
				if j+1 < len(short) {
					value = short[j+1:]
				} else {
					if i+1 >= len(argv) {
						return parsed, needsValue(tool, "-"+string(option))
					}
					i++
					value = argv[i]
				}
				if err := addNetworkOptionTarget(&parsed, tool, "-"+string(option), value); err != nil {
					return parsed, err
				}
				j = len(short)
			default:
				return parsed, unknownOpt(tool, "-"+string(option))
			}
		}
	}
	return parsed, nil
}

func sshCommandSources(argv []string) ([]string, error) {
	if head(argv) != "ssh" {
		return nil, nil
	}
	parsed, err := parseNetworkArgs(argv, "ssh", sshOptions)
	if err != nil {
		return nil, err
	}
	sources := append([]string(nil), parsed.remoteCommands...)
	if parsed.permitLocalCommand {
		sources = append(sources, parsed.localCommands...)
	}
	if len(parsed.operands) > 1 {
		sources = append(sources, strings.Join(parsed.operands[1:], " "))
	}
	return sources, nil
}

func addNetworkOptionTarget(parsed *parsedNetworkArgs, tool, option, value string) error {
	if tool == "curl" {
		switch option {
		case "--config", "-K", "--alt-svc":
			return fmt.Errorf("%s loads opaque network configuration", option)
		case "--proxy", "--preproxy", "--socks4", "--socks4a", "--socks5", "--socks5-hostname", "-x":
			host, err := hostFromURLCandidate(value)
			if err != nil {
				return err
			}
			parsed.connectionHosts = append(parsed.connectionHosts, host)
		case "--connect-to":
			fields, ok := colonFields(value, 4)
			if !ok {
				return fmt.Errorf("malformed --connect-to target %q", value)
			}
			if fields[2] != "" {
				host, err := hostFromURLCandidate(fields[2])
				if err != nil {
					return err
				}
				parsed.connectionHosts = append(parsed.connectionHosts, host)
			}
		case "--resolve":
			fields, ok := colonFields(value, 3)
			if !ok || fields[2] == "" {
				return fmt.Errorf("malformed --resolve target %q", value)
			}
			for _, address := range strings.Split(fields[2], ",") {
				host, err := hostFromURLCandidate(address)
				if err != nil {
					return err
				}
				parsed.connectionHosts = append(parsed.connectionHosts, host)
			}
		case "--dns-servers":
			for _, server := range strings.Split(value, ",") {
				host, err := hostFromURLCandidate(server)
				if err != nil {
					return err
				}
				parsed.connectionHosts = append(parsed.connectionHosts, host)
			}
		}
		return nil
	}
	if tool == "wget" {
		if option == "--config" || option == "--execute" || option == "-e" {
			return fmt.Errorf("%s loads opaque network configuration", option)
		}
		return nil
	}
	if tool != "ssh" && tool != "sftp" {
		return nil
	}
	switch option {
	case "-F":
		return fmt.Errorf("-F loads opaque SSH configuration")
	case "-S":
		if tool == "sftp" {
			return fmt.Errorf("sftp -S executes an opaque transport program")
		}
	case "-J":
		return addProxyJumpTargets(parsed, value)
	case "-o":
		return addSSHSettingTarget(parsed, value)
	case "-W":
		host, err := hostFromURLCandidate(value)
		if err != nil {
			return err
		}
		parsed.connectionHosts = append(parsed.connectionHosts, host)
	case "-L", "-R":
		if tool != "ssh" {
			return nil
		}
		host, err := sshForwardHost(value)
		if err != nil {
			return err
		}
		if host != "" {
			parsed.connectionHosts = append(parsed.connectionHosts, host)
		}
	case "-D":
		return fmt.Errorf("ssh -D creates a dynamic connection target")
	}
	return nil
}

func sshForwardHost(value string) (string, error) {
	if fields, ok := colonFields(value, 4); ok {
		return hostFromURLCandidate(fields[2])
	}
	if fields, ok := colonFields(value, 3); ok {
		return hostFromURLCandidate(fields[1])
	}
	if strings.Contains(value, "/") {
		return "", nil
	}
	return "", fmt.Errorf("SSH forwarding target %q could not be resolved safely", value)
}

func addProxyJumpTargets(parsed *parsedNetworkArgs, value string) error {
	if strings.EqualFold(value, "none") {
		return nil
	}
	for _, target := range strings.Split(value, ",") {
		host, err := hostFromURLCandidate(target)
		if err != nil {
			return err
		}
		parsed.connectionHosts = append(parsed.connectionHosts, host)
	}
	return nil
}

var inertSSHSettings = networkOptionNames(
	"addressfamily", "batchmode", "bindaddress", "bindinterface", "certificatefile",
	"checkhostip", "ciphers", "compression", "connectionattempts", "connecttimeout",
	"controlmaster", "controlpath", "controlpersist", "enableescapecommandline", "escapechar",
	"exitonforwardfailure", "fingerprinthash", "forwardagent", "forwardx11", "forwardx11timeout",
	"forwardx11trusted", "gatewayports", "globalknownhostsfile", "gssapiauthentication",
	"gssapidelegatecredentials", "hashknownhosts", "hostkeyalgorithms", "hostkeyalias",
	"identitiesonly", "identityagent", "identityfile", "ipqos", "kbdinteractiveauthentication",
	"kbdinteractivedevices", "loglevel", "logverbose", "macs",
	"nohostauthenticationforlocalhost", "numberofpasswordprompts", "passwordauthentication",
	"pkcs11provider", "port", "preferredauthentications", "proxyusefdpass",
	"pubkeyacceptedalgorithms", "pubkeyauthentication", "rekeylimit", "requesttty",
	"requiredrsasize", "sendenv", "serveralivecountmax", "serveraliveinterval", "sessiontype",
	"setenv", "stdinnull", "streamlocalbindmask", "streamlocalbindunlink", "stricthostkeychecking",
	"syslogfacility", "tcpkeepalive", "tunnel", "tunneldevice", "updatehostkeys", "user",
	"userknownhostsfile", "verifyhostkeydns", "visualhostkey", "xauthlocation",
)

func addSSHSettingTarget(parsed *parsedNetworkArgs, value string) error {
	key, setting, found := strings.Cut(value, "=")
	if !found {
		fields := strings.Fields(value)
		if len(fields) < 2 {
			return fmt.Errorf("malformed SSH setting %q", value)
		}
		key, setting = fields[0], strings.Join(fields[1:], " ")
	}
	key = strings.ToLower(strings.TrimSpace(key))
	setting = strings.TrimSpace(setting)
	switch key {
	case "hostname":
		host, err := hostFromURLCandidate(setting)
		if err != nil {
			return err
		}
		parsed.hostOverrides = append(parsed.hostOverrides, host)
		return nil
	case "proxyjump":
		return addProxyJumpTargets(parsed, setting)
	case "remotecommand":
		if setting == "" {
			return fmt.Errorf("SSH setting remotecommand requires a command")
		}
		parsed.remoteCommands = append(parsed.remoteCommands, setting)
		return nil
	case "localcommand":
		if setting == "" {
			return fmt.Errorf("SSH setting localcommand requires a command")
		}
		if !strings.EqualFold(setting, "none") {
			parsed.localCommands = append(parsed.localCommands, setting)
		}
		return nil
	case "permitlocalcommand":
		switch {
		case strings.EqualFold(setting, "yes"):
			parsed.permitLocalCommand = true
			return nil
		case strings.EqualFold(setting, "no"):
			return nil
		default:
			return fmt.Errorf("SSH setting permitlocalcommand requires yes or no")
		}
	case "proxycommand", "canonicaldomains", "canonicalizehostname", "include",
		"localforward", "remoteforward", "dynamicforward", "permitremoteopen":
		return fmt.Errorf("SSH setting %s has an opaque connection target", key)
	default:
		if inertSSHSettings[key] {
			return nil
		}
		return fmt.Errorf("unknown SSH setting %s could alter the connection target", key)
	}
}

func colonFields(value string, count int) ([]string, bool) {
	var fields []string
	start, brackets := 0, 0
	for i, r := range value {
		switch r {
		case '[':
			brackets++
		case ']':
			if brackets > 0 {
				brackets--
			}
		case ':':
			if brackets == 0 && len(fields) < count-1 {
				fields = append(fields, strings.Trim(value[start:i], "[]"))
				start = i + 1
			}
		}
	}
	fields = append(fields, strings.Trim(value[start:], "[]"))
	return fields, len(fields) == count
}

func extractHosts(argv []string, tool string) ([]string, bool, error) {
	switch tool {
	case "curl", "wget":
		spec := curlOptions
		if tool == "wget" {
			spec = wgetOptions
		}
		args, err := parseNetworkArgs(argv, tool, spec)
		if err != nil {
			return nil, true, err
		}
		hosts := append([]string(nil), args.connectionHosts...)
		for _, a := range args.operands {
			candidate, err := hostFromURLCandidate(a)
			if err != nil {
				return nil, true, err
			}
			hosts = append(hosts, candidate)
		}
		if len(hosts) == 0 {
			return nil, true, fmt.Errorf("missing host")
		}
		return hosts, true, nil
	case "scp", "rsync":
		args := nonFlagArgs(argv)
		for _, a := range args {
			if i := strings.Index(a, "@"); i >= 0 {
				rest := a[i+1:]
				if j := strings.Index(rest, ":"); j >= 0 {
					return []string{rest[:j]}, true, nil
				}
				continue
			}
			if j := strings.Index(a, "::"); j > 0 && len(a[:j]) > 1 && !strings.Contains(a[:j], "/") {
				return []string{a[:j]}, true, nil
			}
			if j := strings.Index(a, ":"); j > 0 && len(a[:j]) > 1 && !strings.Contains(a[:j], "/") {
				return []string{a[:j]}, true, nil
			}
		}
		return nil, false, nil
	case "ssh", "sftp":
		spec := sshOptions
		if tool == "sftp" {
			spec = sftpOptions
		}
		args, err := parseNetworkArgs(argv, tool, spec)
		if err != nil {
			return nil, true, err
		}
		if len(args.operands) == 0 {
			return nil, true, fmt.Errorf("missing host")
		}
		hosts := append([]string(nil), args.connectionHosts...)
		if len(args.hostOverrides) == 0 {
			host, err := hostFromURLCandidate(args.operands[0])
			if err != nil {
				return nil, true, err
			}
			hosts = append(hosts, host)
		} else {
			hosts = append(hosts, args.hostOverrides...)
		}
		return hosts, true, nil
	case "nc", "ncat", "telnet":
		args := nonFlagArgs(argv)
		if len(args) > 0 {
			return []string{stripPort(args[0])}, true, nil
		}
	case "ftp":
		args := nonFlagArgs(argv)
		if len(args) > 0 {
			return []string{stripPort(args[0])}, true, nil
		}
	}
	return nil, true, fmt.Errorf("missing or unrecognized host")
}

func hostFromURLCandidate(candidate string) (string, error) {
	if ip := net.ParseIP(strings.Trim(candidate, "[]")); ip != nil {
		return strings.ToLower(ip.String()), nil
	}
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Hostname() == "" {
		if strings.Contains(candidate, "://") {
			return "", fmt.Errorf("malformed target %q", candidate)
		}
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
