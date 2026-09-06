package engine

import (
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/CtrlCarlitos/agent-guardrails/internal/pathutil"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/bmatcuk/doublestar/v4"
)

var pathReaders = map[string]bool{
	"cat": true, "head": true, "tail": true, "grep": true, "egrep": true, "fgrep": true,
	"sed": true, "awk": true, "less": true, "more": true, "bat": true, "xxd": true,
	"od": true, "strings": true,
}

func isFileTool(tool string) bool {
	switch strings.ToLower(tool) {
	case "read", "edit", "write", "multiedit":
		return true
	}
	return false
}

// isWriteToolCall reports whether tc is a file-tool call that mutates.
// Bash calls are excluded here on purpose: their write intent is carried by
// redirect targets (and, after the writeCandidates work, by argv), not by the
// tool name.
func isWriteToolCall(tool string) bool {
	switch strings.ToLower(tool) {
	case "edit", "write", "multiedit":
		return true
	}
	return false
}

func checkPaths(tc ToolCall, pol *policy.Policy) *policy.Verdict {
	candidates := privatePathCandidates(tc)
	for _, c := range candidates {
		c = strings.TrimPrefix(c, "~/")
		c = strings.TrimPrefix(c, "~")
		if v := checkSecretPath(c, pol); v != nil {
			return v
		}
		if resolved, ok := resolveExistingPath(c, tc.CWD); ok {
			if v := checkSecretPath(resolved, pol); v != nil {
				return v
			}
		}
		if v := checkSymlinkEscape(c, tc); v != nil {
			return v
		}
	}
	if v := checkGitProtectedPaths(tc); v != nil {
		return v
	}
	if v := checkSelfConfig(tc); v != nil {
		return v
	}
	if v := checkCIInfraLockfile(tc); v != nil {
		return v
	}
	if v := checkOutOfRepoWrite(tc); v != nil {
		return v
	}
	return nil
}

func privatePathCandidates(tc ToolCall) []string {
	var candidates []string
	if isFileTool(tc.Tool) {
		candidates = append(candidates, tc.Paths...)
	}
	if tc.IsBash() {
		simples, err := Normalize(tc.Command, tc.CWD)
		if err == nil {
			for _, s := range simples {
				if pathReaders[head(s.Argv)] {
					candidates = append(candidates, nonFlagArgs(s.Argv)...)
				}
				candidates = append(candidates, s.Redirects...)
				candidates = append(candidates, s.ReadRedirects...)
			}
		}
	}
	return candidates
}

func checkSecretPath(candidate string, pol *policy.Policy) *policy.Verdict {
	if matchesAnyGlob(candidate, pol.Slots.SecretAllow) || !matchesAnyGlob(candidate, pol.Slots.SecretGlobs) {
		return nil
	}
	if pol.Waived["P4.secret-path"] {
		return nil
	}
	return &policy.Verdict{Decision: policy.Deny, RuleID: "P4.secret-path",
		Reason: "access to a credential/secret path: " + candidate}
}

func resolveExistingPath(candidate, cwd string) (string, bool) {
	resolved, err := pathutil.ResolveThroughExistingAncestor(resolvePath(candidate, cwd))
	if err != nil {
		return "", false
	}
	return filepath.ToSlash(resolved), true
}

type destinationCommandSpec struct {
	targetDirectory    bool
	allOperands        bool
	allOperandsShort   string
	allOperandsLong    string
	shortFlags         string
	shortValues        string
	shortWritePaths    string
	longFlags          string
	longValues         string
	longOptionalValues string
	longWritePaths     string
}

var mutatingDestinationCommands = map[string]destinationCommandSpec{
	"cp": {
		targetDirectory:    true,
		shortFlags:         "abdfHilLnPpRrsTuvxZ",
		shortValues:        "S",
		longFlags:          "archive attributes-only backup copy-contents debug force interactive link dereference keep-directory-symlink no-clobber no-dereference parents preserve recursive reflink remove-destination strip-trailing-slashes symbolic-link no-target-directory update verbose one-file-system context help version",
		longValues:         "no-preserve sparse suffix",
		longOptionalValues: "backup preserve reflink update context",
	},
	"mv": {
		targetDirectory:    true,
		shortFlags:         "bfinTuvZ",
		shortValues:        "S",
		longFlags:          "backup debug exchange force interactive no-clobber no-copy strip-trailing-slashes no-target-directory update verbose context help version",
		longValues:         "suffix",
		longOptionalValues: "backup update context",
	},
	"install": {
		targetDirectory:    true,
		allOperandsShort:   "d",
		allOperandsLong:    "directory",
		shortFlags:         "bcCdDpsTvZ",
		shortValues:        "gmoS",
		longFlags:          "backup compare directory debug preserve-timestamps strip no-target-directory verbose preserve-context context help version",
		longValues:         "group mode owner strip-program suffix",
		longOptionalValues: "backup context",
	},
	"ln": {
		targetDirectory:    true,
		shortFlags:         "bdFfiLnPrsTv",
		shortValues:        "S",
		longFlags:          "backup directory force interactive logical no-dereference physical relative symbolic no-target-directory verbose help version",
		longValues:         "suffix",
		longOptionalValues: "backup",
	},
	// rsync's -t means --times, not --target-directory.
	"rsync": {
		shortFlags:      "vqcarRbudlLkKHpEogDtUNOJsnWxzCF0s8hPimynIAX46VS",
		shortValues:     "BefT@M",
		shortWritePaths: "T",
		longFlags:       "verbose quiet no-motd checksum archive recursive relative no-implied-dirs backup update inplace append append-verify dirs old-dirs old-d mkpath links copy-links copy-unsafe-links safe-links munge-links copy-dirlinks keep-dirlinks hard-links perms executability acls xattrs owner group devices copy-devices write-devices specials times atimes open-noatime crtimes omit-dir-times omit-link-times super fake-super sparse preallocate dry-run whole-file existing ignore-existing remove-source-files del delete delete-before delete-during delete-delay delete-after delete-excluded ignore-missing-args delete-missing-args ignore-errors force partial delay-updates prune-empty-dirs numeric-ids ignore-times size-only fuzzy compress cvs-exclude from0 old-args secluded-args trust-sender blocking-io stats 8-bit-output human-readable progress itemize-changes list-only fsync ipv4 ipv6 version help",
		longValues:      "info debug stderr backup-dir suffix chmod checksum-choice cc block-size rsh rsync-path max-delete max-size min-size max-alloc partial-dir usermap groupmap chown timeout contimeout modify-window temp-dir compare-dest copy-dest link-dest compress-choice zc compress-level zl skip-compress filter exclude exclude-from include include-from files-from copy-as address port sockopts outbuf remote-option out-format log-file log-file-format password-file early-input bwlimit stop-after stop-at write-batch only-write-batch read-batch protocol iconv checksum-seed",
		longWritePaths:  "backup-dir partial-dir temp-dir log-file write-batch only-write-batch",
	},
	"tee": {
		allOperands:        true,
		shortFlags:         "aip",
		longFlags:          "append ignore-interrupts help version",
		longOptionalValues: "output-error",
	},
}

var mutatingAllArgs = map[string]bool{
	"rm": true, "truncate": true, "chmod": true, "chown": true,
	"mkdir": true, "touch": true, "shred": true,
}

type destinationArgs struct {
	operands           []string
	optionWritePaths   []string
	targetDirectory    string
	targetDirectorySet bool
	ambiguous          bool
	allOperands        bool
}

type destinationOptionKind uint8

const (
	destinationFlag destinationOptionKind = iota
	destinationValue
	destinationOptionalValue
	destinationWritePath
	destinationTargetDirectory
)

func resolveDestinationLongOption(name string, spec destinationCommandSpec) (string, destinationOptionKind, bool) {
	options := make(map[string]destinationOptionKind)
	for _, option := range strings.Fields(spec.longFlags) {
		options[option] = destinationFlag
	}
	for _, option := range strings.Fields(spec.longValues) {
		options[option] = destinationValue
	}
	for _, option := range strings.Fields(spec.longOptionalValues) {
		options[option] = destinationOptionalValue
	}
	for _, option := range strings.Fields(spec.longWritePaths) {
		options[option] = destinationWritePath
	}
	if spec.targetDirectory {
		options["target-directory"] = destinationTargetDirectory
	}
	if kind, ok := options[name]; ok {
		return name, kind, true
	}
	matched := ""
	var kind destinationOptionKind
	for option, candidateKind := range options {
		if !strings.HasPrefix(option, name) {
			continue
		}
		if matched != "" {
			return "", 0, false
		}
		matched, kind = option, candidateKind
	}
	return matched, kind, matched != ""
}

func parseDestinationArgs(argv []string, spec destinationCommandSpec) destinationArgs {
	var parsed destinationArgs
	options := true
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if options && a == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(a, "--") {
			name, value, attached := strings.Cut(strings.TrimPrefix(a, "--"), "=")
			resolved, kind, ok := resolveDestinationLongOption(name, spec)
			if !ok {
				parsed.ambiguous = true
				continue
			}
			if resolved == spec.allOperandsLong {
				parsed.allOperands = true
			}
			if kind == destinationTargetDirectory {
				parsed.targetDirectorySet = true
				if attached {
					parsed.targetDirectory = value
				} else if i+1 < len(argv) {
					i++
					parsed.targetDirectory = argv[i]
				} else {
					parsed.ambiguous = true
				}
				continue
			}
			if attached {
				if kind == destinationWritePath {
					parsed.optionWritePaths = append(parsed.optionWritePaths, value)
				} else if kind == destinationFlag {
					parsed.ambiguous = true
				}
				continue
			}
			if kind == destinationValue || kind == destinationWritePath {
				if i+1 < len(argv) {
					i++
					if kind == destinationWritePath {
						parsed.optionWritePaths = append(parsed.optionWritePaths, argv[i])
					}
				} else {
					parsed.ambiguous = true
				}
				continue
			}
			continue
		}
		if options && strings.HasPrefix(a, "-") && len(a) > 1 {
			short := strings.TrimPrefix(a, "-")
			for j := 0; j < len(short); j++ {
				option := short[j]
				if strings.ContainsRune(spec.allOperandsShort, rune(option)) {
					parsed.allOperands = true
				}
				if spec.targetDirectory && option == 't' {
					parsed.targetDirectorySet = true
					if j+1 < len(short) {
						parsed.targetDirectory = short[j+1:]
					} else if i+1 < len(argv) {
						i++
						parsed.targetDirectory = argv[i]
					} else {
						parsed.ambiguous = true
					}
					break
				}
				if strings.ContainsRune(spec.shortValues, rune(option)) {
					value := ""
					if j+1 < len(short) {
						value = short[j+1:]
					} else if i+1 < len(argv) {
						i++
						value = argv[i]
					} else {
						parsed.ambiguous = true
					}
					if strings.ContainsRune(spec.shortWritePaths, rune(option)) && value != "" {
						parsed.optionWritePaths = append(parsed.optionWritePaths, value)
					}
					break
				}
				if !strings.ContainsRune(spec.shortFlags, rune(option)) {
					parsed.ambiguous = true
				}
			}
			continue
		}
		parsed.operands = append(parsed.operands, a)
	}
	return parsed
}

func destinationTargets(argv []string, spec destinationCommandSpec) []string {
	parsed := parseDestinationArgs(argv, spec)
	out := parsed.optionWritePaths
	if parsed.targetDirectorySet {
		if parsed.targetDirectory == "" {
			return append(out, parsed.operands...)
		}
		out = append(out, parsed.targetDirectory)
		for _, source := range parsed.operands {
			out = append(out, path.Join(parsed.targetDirectory, path.Base(source)))
		}
		if parsed.ambiguous {
			out = append(out, parsed.operands...)
		}
		return out
	}
	if spec.allOperands || parsed.allOperands {
		return append(out, parsed.operands...)
	}
	if len(parsed.operands) == 0 {
		return out
	}
	if parsed.ambiguous {
		return append(out, parsed.operands...)
	}
	return append(out, parsed.operands[len(parsed.operands)-1])
}

func moveSourceTargets(argv []string) []string {
	parsed := parseDestinationArgs(argv, mutatingDestinationCommands["mv"])
	if parsed.targetDirectorySet || parsed.ambiguous {
		return parsed.operands
	}
	if len(parsed.operands) < 2 {
		return nil
	}
	return parsed.operands[:len(parsed.operands)-1]
}

func writeTargets(s Simple) []string {
	if len(s.Argv) == 0 {
		return nil
	}
	command := head(s.Argv)
	args := nonFlagArgs(s.Argv)

	if command == "dd" {
		var out []string
		for _, a := range s.Argv[1:] {
			if strings.HasPrefix(a, "of=") {
				out = append(out, strings.TrimPrefix(a, "of="))
			}
		}
		return out
	}
	// sed -i edits in place; without -i it is a reader.
	if command == "sed" {
		if !hasAnyFlag(s.Argv, "i", "--in-place") {
			return nil
		}
		if len(args) > 1 {
			return args[1:] // args[0] is the script
		}
		return nil
	}
	if spec, ok := mutatingDestinationCommands[command]; ok {
		return destinationTargets(s.Argv, spec)
	}
	if mutatingAllArgs[command] {
		return args
	}
	return nil
}

func writeCandidates(tc ToolCall) []string {
	var out []string
	if isFileTool(tc.Tool) {
		out = append(out, tc.Paths...)
	}
	if tc.IsBash() {
		if simples, err := Normalize(tc.Command, tc.CWD); err == nil {
			for _, s := range simples {
				out = append(out, s.Redirects...)
				out = append(out, writeTargets(s)...)
			}
		}
	}
	return out
}

func checkGitProtectedPaths(tc ToolCall) *policy.Verdict {
	if isFileTool(tc.Tool) && !isWriteToolCall(tc.Tool) {
		return nil
	}
	for _, c := range writeCandidates(tc) {
		if matchesAnyGlob(strings.TrimPrefix(c, "./"), gitProtectedGlobs) {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P2.git-protected-path",
				Reason: "write to a protected git-internal path: " + c}
		}
	}
	return nil
}

var selfConfigGlobs = []string{
	"**/.claude/**", "CLAUDE.md", "AGENTS.md", ".mcp.json", ".envrc",
	"**/.bashrc", "**/.zshrc", "**/.profile", "**/.bash_profile",
	// Guardrail's own machinery: the agent must not configure, disable, or
	// replace the thing supervising it (CR-14).
	"guardrail.toml", "**/guardrail.toml",
	"**/.guardrail/**",
	// The operator's authorization must not be writable by the agent it governs.
	"**/.config/guardrail/**", "**/guardrail/waivers.toml",
	"opencode.json", "**/opencode.json",
	"**/.agents/hooks.json",
	"**/.gemini/config/hooks.json",
	"**/.local/bin/guardrail", "**/bin/guardrail",
}

func checkSelfConfig(tc ToolCall) *policy.Verdict {
	if isFileTool(tc.Tool) && !isWriteToolCall(tc.Tool) {
		return nil
	}
	for _, c := range writeCandidates(tc) {
		protected := matchesAnyGlob(strings.TrimPrefix(c, "./"), selfConfigGlobs)
		if resolved, ok := resolveExistingPath(c, tc.CWD); ok {
			protected = protected || matchesAnyGlob(resolved, selfConfigGlobs)
		}
		if protected {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P5.self-config",
				Reason: "write to the agent's own guardrail/shell config: " + c}
		}
	}
	if tc.IsBash() {
		if simples, err := Normalize(tc.Command, tc.CWD); err == nil {
			for _, s := range simples {
				if !isOpaqueExecutor(head(s.Argv)) {
					continue
				}
				for _, arg := range s.Argv[1:] {
					if containsOperatorConfigPath(arg) {
						return &policy.Verdict{Decision: policy.Deny, RuleID: "P5.self-config",
							Reason: "opaque command names the Operator config: " + head(s.Argv)}
					}
				}
			}
		}
	}
	return nil
}

func containsOperatorConfigPath(arg string) bool {
	for _, candidate := range visiblePathCandidates(arg) {
		if matchesOperatorConfigPath(candidate) {
			return true
		}
	}
	return false
}

func visiblePathCandidates(arg string) []string {
	var candidates []string
	var unquoted strings.Builder
	for i := 0; i < len(arg); {
		if arg[i] != '\'' && arg[i] != '"' && arg[i] != '`' {
			unquoted.WriteByte(arg[i])
			i++
			continue
		}
		literal, next, ok := quotedLiteral(arg, i)
		if !ok {
			unquoted.WriteString(arg[i:])
			break
		}
		candidates = append(candidates, literal)
		unquoted.WriteByte(' ')
		i = next
	}
	tokens := strings.FieldsFunc(unquoted.String(), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune(`/\._-$~:%@+`, r)
	})
	return append(candidates, tokens...)
}

func quotedLiteral(source string, start int) (string, int, bool) {
	quote := source[start]
	var literal strings.Builder
	for i := start + 1; i < len(source); i++ {
		if source[i] == quote {
			return literal.String(), i + 1, true
		}
		if source[i] == '\\' && i+1 < len(source) && (source[i+1] == quote || source[i+1] == '\\') {
			i++
		}
		literal.WriteByte(source[i])
	}
	return "", start, false
}

func matchesOperatorConfigPath(candidate string) bool {
	normalized := strings.ReplaceAll(candidate, `\`, "/")
	parsed, err := url.Parse(normalized)
	if err != nil {
		return matchesNormalizedOperatorConfigPath(normalized)
	}
	if parsed.Scheme != "" && !isWindowsDrivePath(normalized) {
		if !strings.EqualFold(parsed.Scheme, "file") {
			return false
		}
		if parsed.Host != "" && !strings.EqualFold(parsed.Host, "localhost") {
			return false
		}
		decoded, err := url.PathUnescape(parsed.EscapedPath())
		if err != nil {
			return matchesNormalizedOperatorConfigPath(normalized)
		}
		normalized = decoded
	}
	return matchesNormalizedOperatorConfigPath(normalized)
}

func isWindowsDrivePath(candidate string) bool {
	return len(candidate) >= 2 && isASCIILetter(candidate[0]) && candidate[1] == ':'
}

func isASCIILetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func matchesNormalizedOperatorConfigPath(candidate string) bool {
	cleaned := strings.ToLower(path.Clean(strings.ReplaceAll(candidate, `\`, "/")))
	return strings.Contains(cleaned, "/.config/guardrail/") || strings.Contains(cleaned, "/guardrail/waivers.toml")
}

func isOpaqueExecutor(executable string) bool {
	name := strings.ToLower(path.Base(strings.ReplaceAll(executable, `\`, "/")))
	name = strings.TrimSuffix(name, ".exe")
	for _, base := range []string{"python", "node", "perl", "ruby", "php", "lua", "awk", "powershell", "pwsh"} {
		if name == base || strings.HasPrefix(name, base) && isVersionSuffix(name[len(base):]) {
			return true
		}
	}
	return false
}

func isVersionSuffix(suffix string) bool {
	suffix = strings.TrimPrefix(suffix, "-")
	if suffix == "" {
		return false
	}
	hasDigit := false
	for _, r := range suffix {
		if r >= '0' && r <= '9' {
			hasDigit = true
			continue
		}
		if r != '.' {
			return false
		}
	}
	return hasDigit
}

var ciInfraLockGlobs = []string{
	"**/.github/workflows/**", ".gitlab-ci.yml", "**/.circleci/**", "Jenkinsfile",
	"**/.buildkite/**", ".pre-commit-config.yaml", "azure-pipelines.yml",
	"Dockerfile", "docker-compose*.yml", "*.tf", "Makefile", "justfile", "Taskfile.yml",
	"setup.py", "conftest.py", "noxfile.py",
	"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock",
	"poetry.lock", "uv.lock", "go.sum", "Gemfile.lock", "mix.lock", "composer.lock",
}

func checkCIInfraLockfile(tc ToolCall) *policy.Verdict {
	if !isFileTool(tc.Tool) && !tc.IsBash() {
		return nil
	}
	// only Write/Edit — reading these is fine
	if isFileTool(tc.Tool) && !isWriteToolCall(tc.Tool) {
		return nil
	}
	for _, c := range writeCandidates(tc) {
		if matchesAnyGlob(strings.TrimPrefix(c, "./"), ciInfraLockGlobs) {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P5.ci-infra-lockfile",
				Reason: "edit of a CI/infra/lockfile — this code runs later with more privilege: " + c}
		}
	}
	return nil
}

func checkOutOfRepoWrite(tc ToolCall) *policy.Verdict {
	if tc.RepoRoot == "" {
		return nil
	}
	if !strings.EqualFold(tc.Tool, "edit") && !strings.EqualFold(tc.Tool, "write") && !strings.EqualFold(tc.Tool, "multiedit") {
		return nil
	}
	for _, p := range tc.Paths {
		abs := resolvePath(p, tc.CWD)
		if !withinSafe(abs, tc.RepoRoot, nil) {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P5.out-of-repo",
				Reason: "write target is outside the repo/worktree root: " + p}
		}
	}
	return nil
}

func matchesAnyGlob(p string, globs []string) bool {
	p = path.Clean(filepath.ToSlash(strings.TrimPrefix(p, "./")))
	base := path.Base(p)
	for _, g := range globs {
		if ok, _ := doublestar.Match(g, p); ok {
			return true
		}
		if ok, _ := doublestar.Match(g, base); ok {
			return true
		}
	}
	return false
}

func checkSymlinkEscape(cand string, tc ToolCall) *policy.Verdict {
	if tc.RepoRoot == "" || filepath.IsAbs(cand) && !strings.HasPrefix(filepath.Clean(cand), filepath.Clean(tc.RepoRoot)) {
		// only guard paths that claim to be inside the repo
		if !strings.HasPrefix(filepath.Clean(cand), filepath.Clean(tc.RepoRoot)) {
			return nil
		}
	}
	abs := cand
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(tc.CWD, cand)
	}
	if !strings.HasPrefix(filepath.Clean(abs), filepath.Clean(tc.RepoRoot)+string(filepath.Separator)) {
		return nil
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil // nonexistent target: nothing to resolve yet
	}
	root := filepath.Clean(tc.RepoRoot) + string(filepath.Separator)
	if !strings.HasPrefix(filepath.Clean(resolved)+string(filepath.Separator), root) {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P4.symlink-escape",
			Reason: "a path inside the repo resolves outside it via symlink: " + cand}
	}
	return nil
}
