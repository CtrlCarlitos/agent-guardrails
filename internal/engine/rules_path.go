package engine

import (
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"unicode"

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
	var candidates []string
	if isFileTool(tc.Tool) {
		candidates = append(candidates, tc.Paths...)
	}
	if tc.IsBash() {
		simples, err := Normalize(tc.Command)
		if err == nil {
			for _, s := range simples {
				if pathReaders[head(s.Argv)] {
					candidates = append(candidates, nonFlagArgs(s.Argv)...)
				}
			}
		}
	}
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
	resolved, err := filepath.EvalSymlinks(resolvePath(candidate, cwd))
	if err != nil {
		return "", false
	}
	return filepath.ToSlash(resolved), true
}

type destinationCommandSpec struct {
	targetDirectory bool
	shortFlags      string
	shortValues     string
	shortWritePaths string
	longFlags       string
	longValues      string
	longWritePaths  string
}

var mutatingDestinationCommands = map[string]destinationCommandSpec{
	"cp": {
		targetDirectory: true,
		shortFlags:      "abdfHilLnPpRrsTuvxZ",
		shortValues:     "S",
		longFlags:       "archive attributes-only backup copy-contents debug force interactive link dereference no-clobber no-dereference parents preserve recursive reflink remove-destination strip-trailing-slashes symbolic-link no-target-directory update verbose one-file-system context help version",
		longValues:      "no-preserve sparse suffix",
	},
	"mv": {
		targetDirectory: true,
		shortFlags:      "bfinTuvZ",
		shortValues:     "S",
		longFlags:       "backup debug force interactive no-clobber no-copy strip-trailing-slashes no-target-directory update verbose context help version",
		longValues:      "suffix",
	},
	"install": {
		targetDirectory: true,
		shortFlags:      "bcCdDpsTvZ",
		shortValues:     "gmoS",
		longFlags:       "backup compare directory debug preserve-timestamps strip no-target-directory verbose preserve-context context help version",
		longValues:      "group mode owner strip-program suffix",
	},
	"ln": {
		targetDirectory: true,
		shortFlags:      "bdFfiLnPrsTv",
		shortValues:     "S",
		longFlags:       "backup directory force interactive logical no-dereference physical relative symbolic no-target-directory verbose help version",
		longValues:      "suffix",
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
}

var mutatingAllArgs = map[string]bool{
	"rm": true, "truncate": true, "chmod": true, "chown": true,
	"mkdir": true, "tee": true, "touch": true, "shred": true,
}

func listedOption(options, option string) bool {
	return strings.Contains(" "+options+" ", " "+option+" ")
}

func destinationTargets(argv []string, spec destinationCommandSpec) []string {
	var operands []string
	var optionWritePaths []string
	var targetDirectory string
	targetDirectorySet := false
	ambiguous := false
	options := true
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if options && a == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(a, "--") {
			name, value, attached := strings.Cut(strings.TrimPrefix(a, "--"), "=")
			if spec.targetDirectory && name == "target-directory" {
				targetDirectorySet = true
				if attached {
					targetDirectory = value
				} else if i+1 < len(argv) {
					i++
					targetDirectory = argv[i]
				} else {
					ambiguous = true
				}
				continue
			}
			if attached {
				if listedOption(spec.longWritePaths, name) {
					optionWritePaths = append(optionWritePaths, value)
				}
				continue
			}
			if listedOption(spec.longValues, name) {
				if i+1 < len(argv) {
					i++
					if listedOption(spec.longWritePaths, name) {
						optionWritePaths = append(optionWritePaths, argv[i])
					}
				} else {
					ambiguous = true
				}
				continue
			}
			if !listedOption(spec.longFlags, name) && !strings.HasPrefix(name, "no-") {
				ambiguous = true
			}
			continue
		}
		if options && strings.HasPrefix(a, "-") && len(a) > 1 {
			short := strings.TrimPrefix(a, "-")
			for j := 0; j < len(short); j++ {
				option := short[j]
				if spec.targetDirectory && option == 't' {
					targetDirectorySet = true
					if j+1 < len(short) {
						targetDirectory = short[j+1:]
					} else if i+1 < len(argv) {
						i++
						targetDirectory = argv[i]
					} else {
						ambiguous = true
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
						ambiguous = true
					}
					if strings.ContainsRune(spec.shortWritePaths, rune(option)) && value != "" {
						optionWritePaths = append(optionWritePaths, value)
					}
					break
				}
				if !strings.ContainsRune(spec.shortFlags, rune(option)) {
					ambiguous = true
				}
			}
			continue
		}
		operands = append(operands, a)
	}

	out := optionWritePaths
	if targetDirectorySet {
		if targetDirectory == "" {
			return append(out, operands...)
		}
		out = append(out, targetDirectory)
		for _, source := range operands {
			out = append(out, path.Join(targetDirectory, path.Base(source)))
		}
		if ambiguous {
			out = append(out, operands...)
		}
		return out
	}
	if len(operands) == 0 {
		return out
	}
	if ambiguous {
		return append(out, operands...)
	}
	return append(out, operands[len(operands)-1])
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
		if simples, err := Normalize(tc.Command); err == nil {
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
		if simples, err := Normalize(tc.Command); err == nil {
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
