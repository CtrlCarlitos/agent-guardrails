package engine

import (
	"fmt"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// PowerShell reaches the Engine through the same command capability as bash:
// the Claude contract maps the PowerShell tool onto the Bash analyser, and a
// bash tool on a Windows host can spawn `powershell -Command` regardless.
//
// The families that read path operands — P4's secret tier, P5's containment —
// already cover cmdlets, because they key on the operand and not on the
// command name; `Get-Content …\.ssh\id_ed25519` denied before any of this
// existed. The families that key on a command name do not. So a cmdlet is
// projected onto the POSIX command it stands for and handed to the rule that
// already owns that command, rather than given a rule of its own: one
// decision for `rm -rf` and `Remove-Item -Recurse -Force`, one waiver, one
// place for the containment logic to live.

// psParams describes a cmdlet's parameters by full lowercase name, because
// PowerShell binds any unambiguous prefix of one: `-rec` and `-R` are both
// `-Recurse`.
type psParams struct {
	switches []string // present or absent; consume no following token
	values   []string // consume the following token as their argument
	paths    []string // the subset of values whose argument is a path operand
}

var removeItemParams = psParams{
	switches: []string{"recurse", "force", "whatif", "confirm", "usetransaction"},
	values:   []string{"path", "literalpath", "filter", "include", "exclude", "credential", "stream"},
	paths:    []string{"path", "literalpath"},
}

// webRequestParams covers Invoke-WebRequest and Invoke-RestMethod, which share
// a parameter set. Only `-Uri` names a destination; everything else that takes
// a value is listed so its argument is consumed rather than read as one.
var webRequestParams = psParams{
	switches: []string{
		"usebasicparsing", "usedefaultcredentials", "disablekeepalive", "passthru",
		"resume", "skipcertificatecheck", "skiphttperrorcheck", "nonproxy",
		"allowunencryptedauthentication", "preserveauthorizationonredirect",
		"skipheadervalidation", "allowinsecureredirect", "nopagination",
	},
	values: []string{
		"uri", "outfile", "infile", "method", "headers", "body", "contenttype",
		"proxy", "proxycredential", "credential", "useragent", "timeoutsec",
		"maximumredirection", "maximumretrycount", "retryintervalsec",
		"sessionvariable", "websession", "transferencoding", "certificate",
		"certificatethumbprint", "form", "authentication", "token",
		"statuscodevariable", "responseheadersvariable", "operationtimeoutseconds",
	},
}

var executionPolicyParams = psParams{
	switches: []string{"force", "whatif", "confirm"},
	values:   []string{"executionpolicy", "scope"},
}

// psBinding is one cmdlet invocation with its parameters resolved.
type psBinding struct {
	present  map[string]bool // every full name some argument bound to
	operands []string        // positional operands plus the arguments of path parameters
	values   map[string]string
}

func (b psBinding) has(name string) bool { return b.present[name] }

// bindPS resolves argv against a parameter table. An argument that matches
// several full names is recorded against all of them and consumes nothing:
// PowerShell would reject such a command as ambiguous, and leaving the next
// token in the operand list is the reading that denies rather than allows.
func bindPS(argv []string, spec psParams) psBinding {
	binding := psBinding{present: map[string]bool{}, values: map[string]string{}}
	pathParam := map[string]bool{}
	for _, name := range spec.paths {
		pathParam[name] = true
	}
	for index := 1; index < len(argv); index++ {
		arg := argv[index]
		name, inline, hasInline := psParameter(arg)
		if name == "" {
			binding.operands = append(binding.operands, arg)
			continue
		}
		switches := psMatches(name, spec.switches)
		values := psMatches(name, spec.values)
		for _, matched := range append(append([]string(nil), switches...), values...) {
			binding.present[matched] = true
		}
		if len(values) != 1 || len(switches) > 0 {
			// Unknown, switch, or ambiguous: nothing follows that belongs to it.
			if hasInline {
				binding.operands = append(binding.operands, inline)
			}
			continue
		}
		argument := inline
		if !hasInline {
			if index+1 >= len(argv) {
				continue
			}
			index++
			argument = argv[index]
		}
		binding.values[values[0]] = argument
		if pathParam[values[0]] {
			binding.operands = append(binding.operands, argument)
		}
	}
	return binding
}

// psParameter splits `-Name`, `-Name:Value` and `--Name` into a lowercase name
// and an inline argument. A bare `-` or a negative number is not a parameter.
func psParameter(arg string) (name, inline string, hasInline bool) {
	trimmed := strings.TrimPrefix(arg, "-")
	trimmed = strings.TrimPrefix(trimmed, "-")
	if trimmed == arg || trimmed == "" {
		return "", "", false
	}
	if head, rest, found := strings.Cut(trimmed, ":"); found {
		return strings.ToLower(head), rest, true
	}
	return strings.ToLower(trimmed), "", false
}

func psMatches(name string, full []string) []string {
	var matched []string
	for _, candidate := range full {
		if strings.HasPrefix(candidate, name) {
			matched = append(matched, candidate)
		}
	}
	return matched
}

// removeItemAliases are PowerShell's shipped aliases for Remove-Item. `rm` is
// absent on purpose: the bash family already owns that name and reads its
// flags correctly. `rmdir` is present but gated below, because POSIX has a
// command by that name with narrower semantics.
var removeItemAliases = map[string]bool{
	"remove-item": true, "ri": true, "rd": true, "del": true, "erase": true, "rmdir": true,
}

// psDiskDestroyers destroy a filesystem or a partition table the way mkfs
// does. checkDiskDestroyers consumes this: the family lives in one place.
var psDiskDestroyers = map[string]bool{
	"format-volume": true, "clear-disk": true, "remove-partition": true,
	"initialize-disk": true, "clear-partition": true,
}

// psWebRequestHosts reads the destinations of an Invoke-WebRequest family
// call: `-Uri`, and the first positional operand, which is what `-Uri` binds
// to when it is not named.
func psWebRequestHosts(argv []string) ([]string, bool, error) {
	binding := bindPS(argv, webRequestParams)
	targets := append([]string(nil), binding.operands...)
	if named, ok := binding.values["uri"]; ok {
		targets = append(targets, named)
	}
	if len(targets) == 0 {
		return nil, true, fmt.Errorf("missing host")
	}
	var hosts []string
	for _, target := range targets {
		host, err := hostFromURLCandidate(target)
		if err != nil {
			return nil, true, err
		}
		hosts = append(hosts, host)
	}
	return hosts, true, nil
}

// psDynamicEval evaluates PowerShell source at runtime. Reading that source
// with a POSIX shell parser would be a guess, so the analyser does not make
// one: it declares the command unreadable and asks. ADR-0012's boundary —
// model the minimum, fail closed at everything unmodelled.
var psDynamicEval = map[string]bool{"invoke-expression": true, "iex": true}

func checkPowerShell(s Simple, tc ToolCall, pol *policy.Policy) *policy.Verdict {
	command := head(s.Argv)
	switch {
	case psDynamicEval[command]:
		return ask("P6.dynamic-eval",
			command+" evaluates source at runtime, so the command that runs is not the command shown")
	case command == "set-executionpolicy":
		return checkPSExecutionPolicy(s)
	case removeItemAliases[command]:
		return checkPSRemoveItem(s, tc, pol)
	}
	return nil
}

func checkPSRemoveItem(s Simple, tc ToolCall, pol *policy.Policy) *policy.Verdict {
	binding := bindPS(s.Argv, removeItemParams)
	if head(s.Argv) == "rmdir" && !psCmdletShaped(s.Argv, removeItemParams) {
		return nil // POSIX rmdir removes one empty directory; P1.rmdir owns it.
	}
	if binding.has("whatif") {
		return nil // PowerShell's dry run removes nothing.
	}
	if !binding.has("recurse") && !binding.has("force") {
		return nil // Matches rm: one of the two is what makes it dangerous.
	}
	argv := []string{"rm", psRmFlags(binding)}
	argv = append(argv, binding.operands...)
	return checkRmRf(commandDerivedFromAt(s, argv, -1), tc, pol)
}

func psRmFlags(binding psBinding) string {
	flags := "-"
	if binding.has("recurse") {
		flags += "r"
	}
	if binding.has("force") {
		flags += "f"
	}
	return flags
}

// psCmdletShaped reports whether argv carries a parameter spelled the way a
// cmdlet parameter is spelled rather than the way a POSIX flag is. Three
// characters is the threshold: `-rec`, `-force` and `-lit` are cmdlet
// parameters; `-p`, `-r` and `-f` are flags that a POSIX command of the same
// name may define for itself.
func psCmdletShaped(argv []string, spec psParams) bool {
	for _, arg := range argv[1:] {
		name, _, _ := psParameter(arg)
		if len(name) < 3 {
			continue
		}
		if len(psMatches(name, spec.switches)) > 0 || len(psMatches(name, spec.values)) > 0 {
			return true
		}
	}
	return false
}

// psWideningPolicies turn script-signing enforcement off for a scope. The
// narrowing values (Restricted, AllSigned, RemoteSigned) are not the risk.
var psWideningPolicies = map[string]bool{"bypass": true, "unrestricted": true}

func checkPSExecutionPolicy(s Simple) *policy.Verdict {
	binding := bindPS(s.Argv, executionPolicyParams)
	candidates := append([]string(nil), binding.operands...)
	if named, ok := binding.values["executionpolicy"]; ok {
		candidates = append(candidates, named)
	}
	for _, candidate := range candidates {
		if psWideningPolicies[strings.ToLower(candidate)] {
			return ask("P1.execution-policy",
				"Set-ExecutionPolicy "+candidate+" turns off script-signing enforcement for this host")
		}
	}
	return nil
}
