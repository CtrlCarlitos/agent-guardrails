package engine

import (
	"regexp"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// P4.credential-print (#436). Everything a command prints enters the session
// and is sent to the model provider, so a command whose output is a
// credential may run only when that output never reaches the session: the
// operator's decision of 2026-09-28, which reverses #289's choice to leave
// `gh auth token` allowed.
//
// The rule has two halves. credentialExposure recognises the commands whose
// output is a credential or a dump of the environment that holds them; the
// Simple's stdoutFate (stdout_fate.go) says where that output goes. Only a
// contained fate allows: `GH_TOKEN=$(gh auth token) tool`, `tool --token
// "$(gh auth token)"`, `docker login --password-stdin <<< "$(gh auth token)"`,
// `gh auth token | docker login --password-stdin`.
//
// This judges the shape of the command. A consuming program that prints its
// own arguments or environment still leaks the value; the rule narrows the
// channel, it does not close it.

const credentialPrintRule = "P4.credential-print"

func checkCredentialPrint(s Simple) *policy.Verdict {
	what, kind := credentialExposure(s)
	if kind == exposureNone || s.stdoutFate == stdoutContained && !writesOutputFile(s) {
		return nil
	}
	switch kind {
	case exposureEnvironment:
		return ask(credentialPrintRule, what+" prints environment variables, secrets included, into the session, and everything a command prints is sent to the model provider. Read the one non-secret variable you need (printenv HOME), or hand a secret to the program that needs it without printing it: NAME=\"$NAME\" program.")
	case exposureVariable:
		return ask(credentialPrintRule, what+" prints a secret-looking variable into the session, and everything a command prints is sent to the model provider. Pass it to the program that needs it as an argument or environment value instead (program --token \"$NAME\"), or pipe it into a --password-stdin login.")
	}
	return ask(credentialPrintRule, what+" prints a credential, and everything a command prints enters the session and is sent to the model provider. Hand the value straight to the command that needs it instead: NAME=$("+what+") program, program --token \"$("+what+")\", or "+what+" | program --password-stdin. Not through echo, printf, cat, tee, a variable of its own, a file, or a pipe into anything but a credential consumer.")
}

// writesOutputFile reports a write redirect other than a discard. The
// Simple's Redirects do not say which descriptor they carry, so `2>err.log`
// counts too: the conservative reading.
func writesOutputFile(s Simple) bool {
	for _, target := range s.Redirects {
		if !discardTarget(target) {
			return true
		}
	}
	return false
}

type exposureKind uint8

const (
	exposureNone exposureKind = iota
	exposureCredential
	exposureEnvironment
	exposureVariable
)

// credentialExposure names the command when its output is a credential.
func credentialExposure(s Simple) (string, exposureKind) {
	argv := credentialedTarget(s.Argv)
	if len(argv) == 0 {
		return "", exposureNone
	}
	if what := credentialPrinter(argv); what != "" {
		return what, exposureCredential
	}
	if what := environmentDump(argv); what != "" {
		return what, exposureEnvironment
	}
	if what := secretVariableEcho(s); what != "" {
		return what, exposureVariable
	}
	return "", exposureNone
}

// credentialOperands are the words after the binary that are neither flags
// nor the values of the flags credentialedVerb already knows take one.
func credentialOperands(argv []string) []string {
	var operands []string
	skip := false
	for _, arg := range argv[1:] {
		if skip {
			skip = false
			continue
		}
		if strings.HasPrefix(arg, "-") {
			name, _, inline := strings.Cut(arg, "=")
			skip = !inline && credentialedValueFlags[name]
			continue
		}
		operands = append(operands, arg)
	}
	return operands
}

func operandsStartWith(operands []string, want ...string) bool {
	if len(operands) < len(want) {
		return false
	}
	for index, word := range want {
		if !strings.EqualFold(operands[index], word) {
			return false
		}
	}
	return true
}

func hasFlag(argv []string, names ...string) bool {
	for _, arg := range argv[1:] {
		name, _, _ := strings.Cut(arg, "=")
		for _, want := range names {
			if strings.EqualFold(name, want) {
				return true
			}
		}
	}
	return false
}

// credentialPrinter is the set of commands whose standard output is a
// credential. Each entry is there because its documented output is the secret
// itself, not metadata about it; the read twins that print only names,
// accounts or configuration stay out.
func credentialPrinter(argv []string) string {
	command := head(argv)
	operands := credentialOperands(argv)
	switch command {
	case "gh":
		switch {
		case operandsStartWith(operands, "auth", "token"):
			// The OAuth token of the active account.
			return "gh auth token"
		case operandsStartWith(operands, "auth", "status") && hasFlag(argv, "-t", "--show-token"):
			// status prints the account; -t adds the token itself.
			return "gh auth status --show-token"
		case operandsStartWith(operands, "auth", "git-credential", "get"):
			// The git credential-helper protocol: prints password=<token>.
			return "gh auth git-credential get"
		}
	case "glab":
		if operandsStartWith(operands, "auth", "status") && hasFlag(argv, "-t", "--show-token") {
			// GitLab's twin of gh auth status --show-token.
			return "glab auth status --show-token"
		}
	case "git":
		index := gitSubcommandIndex(argv)
		if index < 0 || index+1 >= len(argv) {
			break
		}
		sub, operand := strings.ToLower(argv[index]), strings.ToLower(argv[index+1])
		if sub == "credential" && operand == "fill" {
			// Asks the configured helpers and prints password=<secret>.
			return "git credential fill"
		}
		if strings.HasPrefix(sub, "credential-") && operand == "get" {
			// A helper run directly (credential-manager, -store, -cache,
			// -wincred, -osxkeychain, -libsecret) prints the stored secret.
			return "git " + sub + " get"
		}
	case "security":
		// macOS keychain: -w prints the password, -g prints it to stderr.
		// Without either, find-*-password prints only the item's attributes.
		if len(operands) > 0 && (strings.EqualFold(operands[0], "find-generic-password") || strings.EqualFold(operands[0], "find-internet-password")) && shortFlagSet(argv, 'w', 'g') {
			return "security " + operands[0] + " -w"
		}
		if operandsStartWith(operands, "dump-keychain") && shortFlagSet(argv, 'd') {
			// -d decrypts every item and prints it.
			return "security dump-keychain -d"
		}
	case "secret-tool":
		// libsecret: lookup prints the secret; search prints "secret = …"
		// for every match.
		if operandsStartWith(operands, "lookup") || operandsStartWith(operands, "search") {
			return "secret-tool " + operands[0]
		}
	case "az":
		if operandsStartWith(operands, "account", "get-access-token") {
			// A bearer token for the signed-in account.
			return "az account get-access-token"
		}
		if operandsStartWith(operands, "acr", "login") && hasFlag(argv, "--expose-token") {
			// Prints the registry access token instead of logging docker in.
			return "az acr login --expose-token"
		}
	case "aws":
		switch {
		case operandsStartWith(operands, "configure", "get") && len(operands) >= 3 && awsSecretConfigKey(operands[2]):
			// `aws configure get region` prints configuration; the key and
			// token settings print the credential.
			return "aws configure get " + operands[2]
		case operandsStartWith(operands, "configure", "export-credentials"):
			return "aws configure export-credentials"
		case operandsStartWith(operands, "sts", "get-session-token"),
			operandsStartWith(operands, "sts", "get-federation-token"),
			operandsStartWith(operands, "sts", "assume-role"),
			operandsStartWith(operands, "sts", "assume-role-with-web-identity"),
			operandsStartWith(operands, "sts", "assume-role-with-saml"):
			// All return a Credentials block with a secret access key.
			return "aws sts " + operands[1]
		case operandsStartWith(operands, "ecr", "get-login-password"),
			operandsStartWith(operands, "ecr-public", "get-login-password"),
			operandsStartWith(operands, "ecr", "get-authorization-token"),
			operandsStartWith(operands, "codeartifact", "get-authorization-token"):
			return "aws " + operands[0] + " " + operands[1]
		case operandsStartWith(operands, "secretsmanager", "get-secret-value"):
			return "aws secretsmanager get-secret-value"
		case (operandsStartWith(operands, "ssm", "get-parameter") || operandsStartWith(operands, "ssm", "get-parameters")) && hasFlag(argv, "--with-decryption"):
			// Decrypted SecureString parameters.
			return "aws ssm " + operands[1] + " --with-decryption"
		}
	case "gcloud":
		switch {
		case operandsStartWith(operands, "auth", "print-access-token"),
			operandsStartWith(operands, "auth", "print-identity-token"):
			return "gcloud auth " + operands[1]
		case operandsStartWith(operands, "auth", "application-default", "print-access-token"):
			return "gcloud auth application-default print-access-token"
		case operandsStartWith(operands, "config", "config-helper"):
			// Prints a credential block including the access token.
			return "gcloud config config-helper"
		case operandsStartWith(operands, "secrets", "versions", "access"):
			return "gcloud secrets versions access"
		}
	case "kubectl":
		if operandsStartWith(operands, "config", "view") && hasFlag(argv, "--raw") {
			// Without --raw the client keys and tokens are redacted.
			return "kubectl config view --raw"
		}
		if operandsStartWith(operands, "create", "token") {
			// Mints and prints a service-account token.
			return "kubectl create token"
		}
	case "npm", "pnpm", "yarn":
		if operandsStartWith(operands, "config", "get") && len(operands) >= 3 && npmAuthConfigKey(operands[2]) {
			return command + " config get " + operands[2]
		}
	case "op":
		// 1Password: read prints the referenced field; item get prints
		// concealed fields only with --reveal.
		if operandsStartWith(operands, "read") {
			return "op read"
		}
		if operandsStartWith(operands, "item", "get") && hasFlag(argv, "--reveal") {
			return "op item get --reveal"
		}
	case "vault":
		switch {
		case operandsStartWith(operands, "kv", "get"):
			// Prints the secret's data.
			return "vault kv get"
		case operandsStartWith(operands, "read"):
			// Secrets engines answer reads with the secret or a freshly
			// minted credential (database/creds, aws/creds, secret/…).
			return "vault read"
		case operandsStartWith(operands, "print", "token"):
			return "vault print token"
		case operandsStartWith(operands, "token", "create"):
			return "vault token create"
		}
	case "heroku":
		if operandsStartWith(operands, "auth:token") {
			return "heroku auth:token"
		}
	case "fly", "flyctl":
		if operandsStartWith(operands, "auth", "token") {
			return command + " auth token"
		}
	case "pass", "gopass":
		if operandsStartWith(operands, "show") {
			return command + " show"
		}
	case "get-secret":
		// PowerShell SecretManagement: a SecureString unless -AsPlainText.
		if hasFlag(argv, "-asplaintext") {
			return "Get-Secret -AsPlainText"
		}
	case "convertfrom-securestring":
		if hasFlag(argv, "-asplaintext") {
			return "ConvertFrom-SecureString -AsPlainText"
		}
	}
	if strings.HasPrefix(command, "docker-credential-") && len(operands) > 0 {
		// Docker's credential helpers: get prints the secret, list prints
		// every registry and the account stored for it.
		if op := strings.ToLower(operands[0]); op == "get" || op == "list" {
			return command + " " + op
		}
	}
	if strings.HasPrefix(command, "git-credential-") && operandsStartWith(operands, "get") {
		return command + " get"
	}
	return ""
}

// shortFlagSet reports a single-dash flag cluster containing any of letters.
func shortFlagSet(argv []string, letters ...byte) bool {
	for _, arg := range argv[1:] {
		if len(arg) < 2 || arg[0] != '-' || arg[1] == '-' {
			continue
		}
		for _, letter := range letters {
			if strings.IndexByte(arg[1:], letter) >= 0 && isASCIILetters(arg[1:]) {
				return true
			}
		}
	}
	return false
}

func isASCIILetters(value string) bool {
	for index := 0; index < len(value); index++ {
		if !isASCIILetterByte(value[index]) {
			return false
		}
	}
	return value != ""
}

func awsSecretConfigKey(key string) bool {
	lower := strings.ToLower(key)
	return strings.Contains(lower, "secret") || strings.Contains(lower, "token") ||
		strings.Contains(lower, "access_key") || strings.Contains(lower, "password")
}

func npmAuthConfigKey(key string) bool {
	lower := strings.ToLower(key)
	return strings.Contains(lower, "_auth") || strings.Contains(lower, "token") ||
		strings.Contains(lower, "password")
}

// secretVariableName is the operator's list: a name containing TOKEN, SECRET,
// PASSWORD, PASSWD, API_KEY, PRIVATE_KEY or CREDENTIAL, in any case.
func secretVariableName(name string) bool {
	upper := strings.ToUpper(name)
	for _, marker := range []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "PRIVATE_KEY", "CREDENTIAL"} {
		if strings.Contains(upper, marker) {
			return true
		}
	}
	return false
}

// environmentDump names the commands that print environment variables: bare
// `env` (stripAndUnwrap keeps it when no command follows), `printenv` with no
// name or a secret-looking one, bare `set`, and PowerShell's env: drive.
func environmentDump(argv []string) string {
	command := head(argv)
	switch command {
	case "env":
		// stripAndUnwrap keeps `env` only when no command follows, but a
		// find callback reaches here unwrapped: `-exec env cat {} +` runs cat.
		if rest, err := consumeEnv(argv[1:]); err == nil && len(rest) == 0 {
			return "env"
		}
	case "printenv":
		names := nonFlagArgs(argv)
		if len(names) == 0 {
			return "printenv"
		}
		for _, name := range names {
			if secretVariableName(name) {
				return "printenv " + name
			}
		}
	case "set":
		if len(argv) == 1 {
			return "set"
		}
	case "get-childitem", "gci", "dir", "ls", "get-item", "gi", "get-content", "gc", "cat", "type", "get-itemproperty", "gp":
		for _, arg := range argv[1:] {
			value := arg
			if name, inline, ok := strings.Cut(arg, ":"); ok && strings.HasPrefix(name, "-") {
				// -Path:env:NAME
				value = inline
			}
			lower := strings.ToLower(value)
			if !strings.HasPrefix(lower, "env:") {
				continue
			}
			name := strings.Trim(value[len("env:"):], `\/`)
			if name == "" || strings.ContainsAny(name, "*?[") || secretVariableName(name) {
				return argv[0] + " " + arg
			}
		}
	}
	return ""
}

var variableReference = regexp.MustCompile(`\$\{?(?i:env:)?([A-Za-z_][A-Za-z0-9_]*)`)

// echoCommands print their arguments.
var echoCommands = map[string]bool{
	"echo": true, "printf": true, "print": true, "write-output": true,
	"write": true, "write-host": true, "write-information": true,
}

// secretVariableEcho names `echo $GITHUB_TOKEN`, `printf '%s' "$NPM_API_KEY"`
// and PowerShell's `Write-Output $env:GITHUB_TOKEN` or a bare
// `$env:GITHUB_TOKEN`, which PowerShell prints. The same reference as an
// argument of a program that does not print it is the intended use.
//
// A single-quoted `'$GITHUB_TOKEN'` is literal text, not a reference, and a
// word the tokenizer resolved holds its value; neither is read.
func secretVariableEcho(s Simple) string {
	argv := s.Argv
	if len(argv) == 0 || s.literalArgs[0] || s.resolvedArgs[0] {
		return ""
	}
	if match := variableReference.FindStringSubmatch(argv[0]); match != nil && strings.HasPrefix(argv[0], "$") && secretVariableName(match[1]) {
		return argv[0]
	}
	if !echoCommands[head(argv)] {
		return ""
	}
	for index, arg := range argv {
		if index == 0 || s.literalArgs[index] || s.resolvedArgs[index] {
			continue
		}
		for _, match := range variableReference.FindAllStringSubmatch(arg, -1) {
			if secretVariableName(match[1]) {
				return argv[0] + " " + match[0]
			}
		}
	}
	return ""
}
