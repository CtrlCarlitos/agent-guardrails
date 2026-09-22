package engine

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Credentialed CLIs act with authority the agent never reads: the token lives
// in a keychain, a kubeconfig, or an environment the command inherits. Their
// effects are public, irreversible, or billed, and none of them touch the
// working tree, so nothing else in the Engine sees them (#235).
//
// Same projection shape as the PowerShell and cmd.exe work: classify the
// subcommand, hand the verdict to the family that owns the risk. The rule ids
// are per family rather than one blob, so an operator running a Kubernetes dev
// loop does not have to waive `npm publish` to do it, and so the per-rule
// verdict profile stays readable.
//
// The read twins matter as much as the mutations. Every binary below has one,
// and they are how somebody inspects the system they are about to change --
// gating those would train the operator to click through the prompts that
// matter.

// credentialedDryRun reports a flag that makes the CLI guarantee no side
// effect, in which case the gate has nothing to protect.
func credentialedDryRun(argv []string) bool {
	for _, arg := range argv {
		name, _, _ := strings.Cut(arg, "=")
		if name == "--dry-run" || name == "-dry-run" || name == "--dryrun" {
			return true
		}
	}
	return false
}

// localKubeContexts are the context-name prefixes that mean a cluster on this
// machine. Anything else -- including an unstated context -- is treated as
// possibly production, because the safe reading of "I cannot tell" is not
// "it is fine".
var localKubeContexts = []string{"kind-", "minikube", "docker-desktop", "k3d-", "rancher-desktop"}

func kubeContextIsLocal(argv []string) bool {
	for i, arg := range argv {
		name, inline, found := strings.Cut(arg, "=")
		if name != "--context" {
			continue
		}
		value := inline
		if !found && i+1 < len(argv) {
			value = argv[i+1]
		}
		for _, prefix := range localKubeContexts {
			if value == strings.TrimSuffix(prefix, "-") || strings.HasPrefix(value, prefix) {
				return true
			}
		}
		return false
	}
	return false
}

var (
	publishVerbs = map[string]map[string]bool{
		"npm":   {"publish": true},
		"pnpm":  {"publish": true},
		"yarn":  {"publish": true},
		"cargo": {"publish": true},
		"twine": {"upload": true},
		"gem":   {"push": true},
	}
	registryPushVerbs = map[string]map[string]bool{
		"docker": {"push": true},
		"podman": {"push": true},
		"oras":   {"push": true},
	}
	clusterMutateVerbs = map[string]map[string]bool{
		"kubectl": {
			"delete": true, "apply": true, "scale": true, "patch": true,
			"replace": true, "drain": true, "rollout": true, "create": true,
			"edit": true, "cordon": true, "uncordon": true, "taint": true,
		},
		"helm": {"install": true, "upgrade": true, "uninstall": true, "rollback": true, "delete": true},
	}
	deployVerbs = map[string]map[string]bool{
		"wrangler": {"deploy": true, "publish": true},
		"firebase": {"deploy": true},
		"netlify":  {"deploy": true},
		"supabase": {"db": true},
	}
	// Verb-allowlisted CLIs: enumerating every mutating operation across aws,
	// gcloud and az is not tractable, so the read operations are the list and
	// anything else asks. Unknown means ask, which is the direction a billing
	// mistake should fail in.
	cloudCLIs = map[string]bool{
		"aws": true, "gcloud": true, "az": true, "doctl": true, "flyctl": true, "fly": true,
	}
	cloudReadVerbs = map[string]bool{
		"ls": true, "list": true, "show": true, "describe": true, "get": true,
		"status": true, "version": true, "help": true, "config": true, "whoami": true,
	}
	// terraform and pulumi name their mutations explicitly, so those are
	// enumerable rather than allowlisted.
	infraMutateVerbs = map[string]map[string]bool{
		"terraform": {"apply": true, "destroy": true, "import": true, "taint": true, "untaint": true},
		"pulumi":    {"up": true, "destroy": true, "refresh": true, "import": true},
	}
	// Wrappers that run a fetched binary. The wrapped command is the one that
	// matters, so the classifier looks past them.
	credentialedWrappers = map[string]bool{"npx": true}
)

func checkCredentialedCLI(s Simple) *policy.Verdict {
	argv := credentialedTarget(s.Argv)
	if len(argv) == 0 {
		return nil
	}
	command := head(argv)
	if credentialedDryRun(argv) {
		return nil
	}
	verb := credentialedVerb(argv)

	switch {
	case publishVerbs[command][verb]:
		return ask("P6.publish", command+" "+verb+" publishes a package that consumers can pull and that cannot reliably be unpublished")
	case registryPushVerbs[command][verb]:
		return ask("P6.publish", command+" "+verb+" publishes an image consumers pull by tag")
	case command == "docker" && verb == "buildx" && hasBareFlag(argv, "--push"):
		return ask("P6.publish", "docker buildx build --push publishes an image consumers pull by tag")
	case clusterMutateVerbs[command][verb]:
		if kubeContextIsLocal(argv) {
			return nil
		}
		return ask("P6.cluster-mutate", command+" "+verb+" changes cluster state, and the context is not a local cluster")
	case infraMutateVerbs[command][verb]:
		return ask("P6.cloud-mutate", command+" "+verb+" changes provisioned infrastructure and is metered")
	case deployVerbs[command][verb]:
		return ask("P6.deploy", command+" "+verb+" puts a change in front of the public")
	case command == "vercel":
		if hasBareFlag(argv, "--prod") {
			return ask("P6.deploy", "vercel --prod deploys to production")
		}
	case cloudCLIs[command]:
		if verb == "" || cloudReadVerbs[verb] || cloudReadOperation(argv) {
			return nil
		}
		return ask("P6.cloud-mutate", command+" "+verb+" is not a known read operation on a metered cloud account")
	}
	return nil
}

// credentialedTarget looks past a fetch-and-run wrapper or a package-manager
// passthrough to the command that actually carries the authority.
//
// Two shapes, both of which hid a real mutation in the first draft:
// `npx vercel --prod` and `pnpm dlx wrangler deploy` fetch the binary first,
// and `yarn npm publish` hands the rest straight to npm.
func credentialedTarget(argv []string) []string {
	for len(argv) > 1 {
		switch {
		case credentialedWrappers[head(argv)]:
			// `npx <cli> …` — the wrapper is one word.
			argv = argv[1:]
		case len(argv) > 2 && credentialedRunners[head(argv)][argv[1]]:
			// `pnpm dlx <cli> …` — the second word names no tool, so both go.
			argv = argv[2:]
		case credentialedForwarders[head(argv)][argv[1]]:
			// `yarn npm publish` — the second word *is* the tool, so only the
			// forwarder goes. Stripping both here left argv as ["publish"],
			// which classified as a binary named "publish" and allowed.
			argv = argv[1:]
		default:
			return argv
		}
	}
	return argv
}

// credentialedRunners fetch and execute another binary; the word after them is
// the binary, not a subcommand of theirs.
var credentialedRunners = map[string]map[string]bool{
	"pnpm": {"dlx": true, "exec": true},
	"yarn": {"dlx": true},
	"npm":  {"exec": true},
}

// credentialedForwarders hand the rest of the line to a named tool.
var credentialedForwarders = map[string]map[string]bool{
	"yarn": {"npm": true},
}

// credentialedValueFlags take a separate value, which must not be mistaken for
// the verb. `kubectl --context prod-eu delete pod x` read as verb "prod-eu"
// in the first draft, which silently allowed every mutation carrying an
// explicit context -- the exact commands most likely to touch production.
var credentialedValueFlags = map[string]bool{
	"--context": true, "--namespace": true, "-n": true, "--kubeconfig": true,
	"--cluster": true, "--user": true, "--profile": true, "--region": true,
	"-f": true, "--filename": true, "-o": true, "--output": true,
	"--project": true, "--resource-group": true, "-g": true, "--subscription": true,
}

// credentialedVerb is the first operand after the binary that is neither a
// flag nor a flag's value.
func credentialedVerb(argv []string) string {
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
		return arg
	}
	return ""
}

// cloudReadOperation covers the aws/gcloud/az convention where the read verb
// is the *second* operand: `aws ec2 describe-instances`, `gcloud compute
// instances list`. A `describe-`/`list-`/`get-` prefix is the same signal.
func cloudReadOperation(argv []string) bool {
	var operands []string
	for _, arg := range argv[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		operands = append(operands, arg)
	}
	for _, operand := range operands {
		base, _, _ := strings.Cut(operand, ":")
		if cloudReadVerbs[base] {
			return true
		}
		for _, prefix := range []string{"describe-", "list-", "get-", "search-", "check-"} {
			if strings.HasPrefix(operand, prefix) {
				return true
			}
		}
	}
	return false
}

func hasBareFlag(argv []string, flag string) bool {
	for _, arg := range argv {
		name, _, _ := strings.Cut(arg, "=")
		if name == flag {
			return true
		}
	}
	return false
}
