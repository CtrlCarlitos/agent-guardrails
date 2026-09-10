package engine

import "strings"

type operandRole uint8

const (
	operandNonPath operandRole = iota
	operandPath
	operandUncertain
)

type parsedOperand struct {
	value       string
	role        operandRole
	writeTarget bool
	sourceArg   int
}

type operandParseResult struct {
	operands          []parsedOperand
	uncertaintyReason string
}

var pathOperandCommands = map[string]bool{
	"cat": true, "head": true, "tail": true, "grep": true, "egrep": true, "fgrep": true,
	"sed": true, "awk": true, "less": true, "more": true, "bat": true, "xxd": true,
	"od": true, "strings": true, "wc": true, "diff": true, "cmp": true, "file": true,
	"nl": true, "tac": true, "rev": true, "cut": true, "sort": true, "uniq": true,
	"tee": true, "base32": true, "base64": true, "md5sum": true, "sha1sum": true,
	"sha256sum": true, "cp": true, "mv": true, "install": true, "rsync": true,
	"scp": true, "tar": true, "zip": true, "gzip": true, "openssl": true, "gpg": true,
	"dd": true, "jq": true, "yq": true, "unlink": true, "rmdir": true,
}

func parseOperandRoles(argv []string) operandParseResult {
	if len(argv) == 0 {
		return operandParseResult{}
	}
	command := head(argv)
	if command == "grep" || command == "egrep" || command == "fgrep" {
		operands, _ := parsePatternCommandOperands(argv, grepOperandOptions)
		return operandParseResult{operands: operands}
	}
	if command == "sed" {
		operands, _ := parsePatternCommandOperands(argv, sedOperandOptions)
		return operandParseResult{operands: operands}
	}
	if command == "jq" {
		return parseJQOperands(argv)
	}
	if command == "yq" {
		return parseYQOperands(argv)
	}
	if command == "awk" {
		return operandParseResult{operands: parseAWKOperands(argv)}
	}
	if command == "tar" {
		return operandParseResult{operands: parseTarOperands(argv)}
	}
	if command == "dd" {
		return operandParseResult{operands: parseDDOperands(argv)}
	}
	return operandParseResult{operands: parseGenericOperands(argv, pathOperandCommands[command])}
}

func parseOperandRolesWithSources(argv []string) operandParseResult {
	parsed := parseOperandRoles(argv)
	start := 1
	for index := range parsed.operands {
		source := operandSourceArg(argv, parsed.operands[index].value, start)
		parsed.operands[index].sourceArg = source
		if source >= start {
			start = source + 1
		}
	}
	return parsed
}

func operandSourceArg(argv []string, value string, start int) int {
	for pass := 0; pass < 2; pass++ {
		from := start
		if pass == 1 {
			from = 1
		}
		for index := from; index < len(argv); index++ {
			arg := argv[index]
			if arg == value || strings.HasSuffix(arg, "="+value) || len(value) > 0 && strings.HasSuffix(arg, value) {
				return index
			}
		}
	}
	return -1
}

func parseDDOperands(argv []string) []parsedOperand {
	var out []parsedOperand
	for _, arg := range argv[1:] {
		name, value, assignment := strings.Cut(arg, "=")
		if !assignment {
			out = append(out, parsedOperand{value: arg, role: operandUncertain})
			continue
		}
		role := operandNonPath
		switch name {
		case "if":
			role = operandPath
		case "of", "iflag", "oflag", "ibs", "obs", "bs", "cbs", "skip", "iseek", "seek", "oseek", "count", "status", "conv":
		default:
			role = operandUncertain
		}
		out = append(out, parsedOperand{value: value, role: role})
	}
	return out
}

func parseTarOperands(argv []string) []parsedOperand {
	var out []parsedOperand
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			name, attachedValue, attached := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
			kind := optionFlag
			known := true
			switch name {
			case "exclude":
				kind = optionNonPath
			case "exclude-from", "files-from", "file", "directory", "listed-incremental", "add-file",
				"exclude-ignore", "exclude-ignore-recursive", "exclude-tag", "exclude-tag-all", "exclude-tag-under",
				"group-map", "owner-map", "volno-file", "index-file":
				kind = optionPath
			case "gzip", "gunzip", "ungzip", "bzip2", "xz", "auto-compress", "verbose", "create", "catenate",
				"concatenate", "delete", "diff", "compare", "append", "test-label", "list", "update", "extract",
				"get", "incremental", "sparse", "exclude-backups", "exclude-caches", "exclude-caches-all",
				"exclude-caches-under", "exclude-vcs", "exclude-vcs-ignores", "no-null", "no-recursion", "no-unquote",
				"no-verbatim-files-from", "null", "recursion", "unquote", "verbatim-files-from":
			case "blocking-factor", "format", "tape-length", "info-script", "new-volume-script", "use-compress-program",
				"starting-file", "newer", "after-date", "label", "suffix":
				kind = optionNonPath
			default:
				known = false
			}
			if !known {
				i = appendUnknownOptionValue(argv, i, attachedValue, attached, &out)
				continue
			}
			if kind == optionFlag {
				continue
			}
			i = appendOptionValues(argv, i, attachedValue, attached, []operandRole{roleForOption(kind)}, &out)
			continue
		}
		oldStyle := options && i == 1 && !strings.HasPrefix(arg, "-") && isTarOptionCluster(arg)
		if options && strings.HasPrefix(arg, "-") && arg != "-" || oldStyle {
			short := strings.TrimPrefix(arg, "-")
			for j := 0; j < len(short); j++ {
				kind := optionFlag
				switch short[j] {
				case 'X', 'T', 'f', 'C', 'g':
					kind = optionPath
				case 'b', 'H', 'L', 'F', 'I', 'K', 'N', 'V':
					kind = optionNonPath
				case 'A', 'c', 'd', 'r', 't', 'u', 'x', 'z', 'j', 'J', 'a', 'v', 'G', 'n', 'S', 'B', 'i', 'M', 'Z', 'h', 'P', 'O', 'm', 'p', 's', 'U', 'W', 'l', 'w', 'o':
				default:
					value := short[j+1:]
					i = appendUnknownOptionValue(argv, i, value, value != "", &out)
					j = len(short)
					continue
				}
				if kind == optionFlag {
					continue
				}
				value := short[j+1:]
				if value == "" && i+1 < len(argv) {
					i++
					value = argv[i]
				}
				if value != "" {
					out = append(out, parsedOperand{value: value, role: roleForOption(kind)})
				}
				break
			}
			continue
		}
		out = append(out, parsedOperand{value: arg, role: operandPath})
	}
	return out
}

func isTarOptionCluster(value string) bool {
	if value == "" {
		return false
	}
	for _, option := range value {
		if !strings.ContainsRune("AcdrtuxzjJavGnSBiMZhPOmpsUWlwoXTFICKNLVbgH", option) {
			return false
		}
	}
	return true
}

func parseAWKOperands(argv []string) []parsedOperand {
	var out []parsedOperand
	var positional []int
	options := true
	explicitProgram := false
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			name, attachedValue, attached := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
			kind := optionFlag
			known := true
			switch name {
			case "file", "exec", "include", "load":
				kind = optionPath
				explicitProgram = explicitProgram || name == "file" || name == "exec"
			case "source":
				kind = optionProgram
				explicitProgram = true
			case "field-separator", "assign":
				kind = optionNonPath
			case "dump-variables", "debug", "lint", "pretty-print", "profile":
				kind = optionOptionalNonPath
			case "characters-as-bytes", "traditional", "copyright", "gen-pot", "help", "trace", "bignum",
				"use-lc-numeric", "non-decimal-data", "optimize", "posix", "re-interval", "no-optimize",
				"sandbox", "lint-old", "version":
			default:
				known = false
			}
			if !known {
				i = appendUnknownOptionValue(argv, i, attachedValue, attached, &out)
				continue
			}
			if kind == optionFlag || kind == optionOptionalNonPath && !attached {
				continue
			}
			i = appendOptionValues(argv, i, attachedValue, attached, []operandRole{roleForOption(kind)}, &out)
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			short := strings.TrimPrefix(arg, "-")
			for j := 0; j < len(short); j++ {
				kind := optionFlag
				switch short[j] {
				case 'f', 'E', 'i', 'l':
					kind = optionPath
					explicitProgram = explicitProgram || short[j] == 'f' || short[j] == 'E'
				case 'e':
					kind = optionProgram
					explicitProgram = true
				case 'F', 'v':
					kind = optionNonPath
				case 'd', 'D', 'L', 'o', 'p':
					kind = optionOptionalNonPath
				case 'b', 'c', 'C', 'g', 'h', 'I', 'M', 'N', 'O', 'P', 'r', 's', 'S', 't', 'V':
				default:
					value := short[j+1:]
					i = appendUnknownOptionValue(argv, i, value, value != "", &out)
					j = len(short)
					continue
				}
				if kind == optionFlag {
					continue
				}
				value := short[j+1:]
				if kind == optionOptionalNonPath {
					if value != "" {
						out = append(out, parsedOperand{value: value, role: operandNonPath})
					}
					break
				}
				if value == "" && i+1 < len(argv) {
					i++
					value = argv[i]
				}
				if value != "" {
					out = append(out, parsedOperand{value: value, role: roleForOption(kind)})
				}
				break
			}
			continue
		}
		role := operandPath
		if isAWKAssignment(arg) {
			role = operandNonPath
		} else {
			positional = append(positional, len(out))
		}
		out = append(out, parsedOperand{value: arg, role: role})
	}
	if !explicitProgram && len(positional) > 0 {
		out[positional[0]].role = operandNonPath
	}
	return out
}

func isAWKAssignment(value string) bool {
	name, _, ok := strings.Cut(value, "=")
	if !ok || name == "" {
		return false
	}
	for index, r := range name {
		if index == 0 && (r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			continue
		}
		if index > 0 && (r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

// Mike Farah yq v4 defines -f as --front-matter (extract|process), while
// --from-file and --split-exp-file read paths. Keep this separate from jq:
// https://github.com/mikefarah/yq/blob/v4.47.2/cmd/root.go
// Its first positional is selected as expression or file using os.Stat, so the
// role cannot be known before execution and must remain uncertain:
// https://github.com/mikefarah/yq/blob/v4.47.2/cmd/utils.go
func parseYQOperands(argv []string) operandParseResult {
	var out []parsedOperand
	var positional []int
	options := true
	expressionSet := false
	uncertaintyReason := ""
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if i == 1 && (arg == "e" || arg == "eval" || arg == "ea" || arg == "eval-all") {
			continue
		}
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			name, attachedValue, attached := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
			switch name {
			case "front-matter", "split-exp":
				i = appendOptionValues(argv, i, attachedValue, attached, []operandRole{operandNonPath}, &out)
			case "expression":
				expressionSet = true
				i = appendOptionValues(argv, i, attachedValue, attached, []operandRole{operandNonPath}, &out)
			case "from-file":
				expressionSet = true
				i = appendOptionValues(argv, i, attachedValue, attached, []operandRole{operandPath}, &out)
			case "split-exp-file":
				i = appendOptionValues(argv, i, attachedValue, attached, []operandRole{operandPath}, &out)
			case "output-format", "input-format", "indent", "xml-attribute-prefix", "xml-content-name",
				"xml-proc-inst-prefix", "xml-directive-name", "csv-separator", "lua-prefix", "lua-suffix",
				"properties-separator":
				i = appendOptionValues(argv, i, attachedValue, attached, []operandRole{operandNonPath}, &out)
			case "verbose", "debug-node-info", "tojson", "xml-strict-mode", "xml-keep-namespace", "xml-raw-token",
				"xml-skip-proc-inst", "xml-skip-directives", "csv-auto-parse", "tsv-auto-parse", "lua-unquoted",
				"lua-globals", "properties-array-brackets", "string-interpolation", "null-input", "no-doc",
				"version", "inplace", "unwrapScalar", "nul-output", "prettyPrint", "exit-status", "colors",
				"no-colors", "header-preprocess", "yaml-fix-merge-anchor-to-spec":
			default:
				uncertaintyReason = "yq operand roles are ambiguous because an option is unknown"
				i = appendUnknownOptionValue(argv, i, attachedValue, attached, &out)
			}
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			short := strings.TrimPrefix(arg, "-")
			for j := 0; j < len(short); j++ {
				kind := optionFlag
				switch short[j] {
				case 'f', 's', 'o', 'p', 'I':
					kind = optionNonPath
				case 'v', 'j', 'n', 'N', 'V', 'i', 'r', '0', 'P', 'e', 'C', 'M':
				default:
					uncertaintyReason = "yq operand roles are ambiguous because an option is unknown"
					value := short[j+1:]
					i = appendUnknownOptionValue(argv, i, value, value != "", &out)
					j = len(short)
					continue
				}
				if kind == optionFlag {
					continue
				}
				value := short[j+1:]
				if value == "" && i+1 < len(argv) {
					i++
					value = argv[i]
				}
				if value != "" {
					out = append(out, parsedOperand{value: value, role: operandNonPath})
				}
				j = len(short)
			}
			continue
		}
		positional = append(positional, len(out))
		out = append(out, parsedOperand{value: arg, role: operandPath})
	}
	if !expressionSet && len(positional) > 0 {
		out[positional[0]].role = operandUncertain
	}
	return operandParseResult{operands: out, uncertaintyReason: uncertaintyReason}
}

func parseJQOperands(argv []string) operandParseResult {
	var out []parsedOperand
	var positional []int
	options := true
	filterFromFile := false
	nullInput := false
	literalTailAt := -1
	runTests := false
	uncertaintyReason := ""
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if runTests {
			if arg == "--skip" || arg == "--take" {
				if i+1 < len(argv) {
					i++
				}
				continue
			}
			out = append(out, parsedOperand{value: arg, role: operandPath})
			continue
		}
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			name, attachedValue, attached := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
			switch name {
			case "from-file":
				filterFromFile = true
				if !attached && optionInterposesValue(argv, i) {
					uncertaintyReason = "jq operand roles are ambiguous because a filter-file value is interposed by an option"
					continue
				}
				i = appendOptionValues(argv, i, attachedValue, attached, []operandRole{operandPath}, &out)
			case "arg", "argjson":
				i = appendOptionValues(argv, i, attachedValue, attached, []operandRole{operandNonPath, operandNonPath}, &out)
			case "rawfile", "slurpfile":
				i = appendOptionValues(argv, i, attachedValue, attached, []operandRole{operandNonPath, operandPath}, &out)
			case "indent":
				i = appendOptionValues(argv, i, attachedValue, attached, []operandRole{operandNonPath}, &out)
			case "null-input":
				nullInput = true
			case "args", "jsonargs":
				if literalTailAt < 0 {
					literalTailAt = len(positional)
				}
			case "run-tests":
				if attached {
					uncertaintyReason = "jq operand roles are ambiguous because an option is unknown"
					i = appendUnknownOptionValue(argv, i, attachedValue, true, &out)
				} else {
					runTests = true
				}
			case "raw-input", "slurp", "compact-output", "raw-output", "raw-output0", "join-output",
				"ascii-output", "sort-keys", "color-output", "monochrome-output", "tab", "unbuffered",
				"stream", "stream-errors", "seq", "exit-status", "version", "build-configuration", "help":
			default:
				uncertaintyReason = "jq operand roles are ambiguous because an option is unknown"
				i = appendUnknownOptionValue(argv, i, attachedValue, attached, &out)
			}
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			short := strings.TrimPrefix(arg, "-")
			for j := 0; j < len(short); j++ {
				switch short[j] {
				case 'f', 'L':
					if short[j] == 'f' {
						filterFromFile = true
					}
					value := short[j+1:]
					if short[j] == 'f' && value == "" && optionInterposesValue(argv, i) {
						uncertaintyReason = "jq operand roles are ambiguous because a filter-file value is interposed by an option"
						j = len(short)
						continue
					}
					if value == "" && i+1 < len(argv) {
						i++
						value = argv[i]
					}
					if value != "" {
						out = append(out, parsedOperand{value: value, role: operandPath})
					}
					j = len(short)
				case 'n':
					nullInput = true
				case 'R', 's', 'c', 'r', 'j', 'a', 'S', 'C', 'M', 'e', 'V', 'h':
				default:
					uncertaintyReason = "jq operand roles are ambiguous because an option is unknown"
					value := short[j+1:]
					i = appendUnknownOptionValue(argv, i, value, value != "", &out)
					j = len(short)
				}
			}
			continue
		}
		positional = append(positional, len(out))
		out = append(out, parsedOperand{value: arg, role: operandPath})
	}
	dataStart := 0
	if !filterFromFile && len(positional) > 0 {
		out[positional[0]].role = operandNonPath
		dataStart = 1
	}
	for position, index := range positional[dataStart:] {
		if nullInput || literalTailAt >= 0 && position+dataStart >= literalTailAt {
			out[index].role = operandNonPath
		}
	}
	return operandParseResult{operands: out, uncertaintyReason: uncertaintyReason}
}

func optionInterposesValue(argv []string, index int) bool {
	return index+1 < len(argv) && strings.HasPrefix(argv[index+1], "-") && argv[index+1] != "-"
}

func appendOptionValues(argv []string, index int, attachedValue string, attached bool, roles []operandRole, out *[]parsedOperand) int {
	for valueIndex, role := range roles {
		value := ""
		if valueIndex == 0 && attached {
			value = attachedValue
		} else if index+1 < len(argv) {
			index++
			value = argv[index]
		}
		if value != "" {
			*out = append(*out, parsedOperand{value: value, role: role})
		}
	}
	return index
}

func appendUnknownOptionValue(argv []string, index int, attachedValue string, attached bool, out *[]parsedOperand) int {
	if attached {
		*out = append(*out, parsedOperand{value: attachedValue, role: operandUncertain})
		return index
	}
	if index+1 < len(argv) && (!strings.HasPrefix(argv[index+1], "-") || argv[index+1] == "-") {
		index++
		*out = append(*out, parsedOperand{value: argv[index], role: operandUncertain})
	}
	return index
}

type operandOptionKind uint8

const (
	optionFlag operandOptionKind = iota
	optionNonPath
	optionPath
	optionProgram
	optionOptionalNonPath
)

type operandOption struct {
	short           byte
	long            string
	kind            operandOptionKind
	suppliesProgram bool
}

type patternCommandOptions struct {
	options       []operandOption
	shortFlags    string
	inPlaceOption string
}

var grepOperandOptions = patternCommandOptions{shortFlags: "EFGPiwxzsvVbnHhoqaIrRLlcTZU", options: []operandOption{
	{short: 'e', long: "regexp", kind: optionProgram},
	{short: 'f', long: "file", kind: optionPath, suppliesProgram: true},
	{short: 'A', long: "after-context", kind: optionNonPath},
	{short: 'B', long: "before-context", kind: optionNonPath},
	{short: 'C', long: "context", kind: optionNonPath},
	{short: 'm', long: "max-count", kind: optionNonPath},
	{short: 'd', long: "directories", kind: optionNonPath},
	{short: 'D', long: "devices", kind: optionNonPath},
	{long: "label", kind: optionNonPath},
	{long: "binary-files", kind: optionNonPath},
	{long: "include", kind: optionNonPath},
	{long: "exclude", kind: optionNonPath},
	{long: "exclude-from", kind: optionPath},
	{long: "exclude-dir", kind: optionNonPath},
	{long: "group-separator", kind: optionNonPath},
	{long: "color", kind: optionOptionalNonPath},
	{long: "colour", kind: optionOptionalNonPath},
	{long: "extended-regexp", kind: optionFlag}, {long: "fixed-strings", kind: optionFlag},
	{long: "basic-regexp", kind: optionFlag}, {long: "perl-regexp", kind: optionFlag},
	{long: "ignore-case", kind: optionFlag}, {long: "no-ignore-case", kind: optionFlag},
	{long: "word-regexp", kind: optionFlag}, {long: "line-regexp", kind: optionFlag},
	{long: "null-data", kind: optionFlag}, {long: "no-messages", kind: optionFlag},
	{long: "invert-match", kind: optionFlag}, {long: "version", kind: optionFlag},
	{long: "help", kind: optionFlag}, {long: "byte-offset", kind: optionFlag},
	{long: "line-number", kind: optionFlag}, {long: "line-buffered", kind: optionFlag},
	{long: "with-filename", kind: optionFlag}, {long: "no-filename", kind: optionFlag},
	{long: "only-matching", kind: optionFlag}, {long: "quiet", kind: optionFlag},
	{long: "silent", kind: optionFlag}, {long: "text", kind: optionFlag},
	{long: "recursive", kind: optionFlag}, {long: "dereference-recursive", kind: optionFlag},
	{long: "files-without-match", kind: optionFlag}, {long: "files-with-matches", kind: optionFlag},
	{long: "count", kind: optionFlag}, {long: "initial-tab", kind: optionFlag},
	{long: "null", kind: optionFlag}, {long: "no-group-separator", kind: optionFlag},
	{long: "binary", kind: optionFlag},
}}

var sedOperandOptions = patternCommandOptions{
	inPlaceOption: "in-place",
	shortFlags:    "nErsuz",
	options: []operandOption{
		{short: 'e', long: "expression", kind: optionProgram},
		{short: 'f', long: "file", kind: optionPath, suppliesProgram: true},
		{short: 'i', long: "in-place", kind: optionOptionalNonPath},
		{short: 'l', long: "line-length", kind: optionNonPath},
		{long: "quiet", kind: optionFlag}, {long: "silent", kind: optionFlag},
		{long: "debug", kind: optionFlag}, {long: "follow-symlinks", kind: optionFlag},
		{long: "posix", kind: optionFlag}, {long: "regexp-extended", kind: optionFlag},
		{long: "separate", kind: optionFlag}, {long: "sandbox", kind: optionFlag},
		{long: "unbuffered", kind: optionFlag}, {long: "null-data", kind: optionFlag},
		{long: "help", kind: optionFlag}, {long: "version", kind: optionFlag},
	},
}

func parsePatternCommandOperands(argv []string, spec patternCommandOptions) ([]parsedOperand, bool) {
	var out []parsedOperand
	var positional []int
	options := true
	explicitProgram := false
	inPlace := false
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			name, value, attached := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
			option, ok := resolveOperandLongOption(name, spec.options)
			if !ok {
				i = appendUnknownOptionValue(argv, i, value, attached, &out)
				continue
			}
			if option.long == spec.inPlaceOption {
				inPlace = true
			}
			if option.kind == optionProgram || option.suppliesProgram {
				explicitProgram = true
			}
			if option.kind == optionFlag || option.kind == optionOptionalNonPath && !attached {
				continue
			}
			if !attached {
				if i+1 >= len(argv) {
					continue
				}
				i++
				value = argv[i]
			}
			out = append(out, parsedOperand{value: value, role: roleForOption(option.kind)})
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			short := strings.TrimPrefix(arg, "-")
			if allDigits(short) {
				continue
			}
			for j := 0; j < len(short); j++ {
				option, ok := operandShortOption(short[j], spec)
				if !ok {
					value := short[j+1:]
					i = appendUnknownOptionValue(argv, i, value, value != "", &out)
					break
				}
				if option.long == spec.inPlaceOption {
					inPlace = true
				}
				if option.kind == optionProgram || option.suppliesProgram {
					explicitProgram = true
				}
				if option.kind == optionFlag {
					continue
				}
				value := short[j+1:]
				if option.kind == optionOptionalNonPath {
					if value != "" {
						out = append(out, parsedOperand{value: value, role: operandNonPath})
					}
					break
				}
				if value == "" && i+1 < len(argv) {
					i++
					value = argv[i]
				}
				if value != "" {
					out = append(out, parsedOperand{value: value, role: roleForOption(option.kind)})
				}
				break
			}
			continue
		}
		positional = append(positional, len(out))
		out = append(out, parsedOperand{value: arg, role: operandPath})
	}
	if !explicitProgram && len(positional) > 0 {
		out[positional[0]].role = operandNonPath
	}
	if inPlace {
		for _, index := range positional {
			if out[index].role != operandNonPath {
				out[index].writeTarget = true
			}
		}
	}
	return out, inPlace
}

func roleForOption(kind operandOptionKind) operandRole {
	if kind == optionPath {
		return operandPath
	}
	return operandNonPath
}

func operandShortOption(name byte, spec patternCommandOptions) (operandOption, bool) {
	for _, option := range spec.options {
		if option.short == name && name != 0 {
			return option, true
		}
	}
	if strings.ContainsRune(spec.shortFlags, rune(name)) {
		return operandOption{short: name, kind: optionFlag}, true
	}
	return operandOption{}, false
}

func resolveOperandLongOption(name string, options []operandOption) (operandOption, bool) {
	for _, option := range options {
		if option.long == name {
			return option, true
		}
	}
	var match operandOption
	found := false
	for _, option := range options {
		if option.long == "" || !strings.HasPrefix(option.long, name) {
			continue
		}
		if found {
			return operandOption{}, false
		}
		match, found = option, true
	}
	return match, found
}

func parseGenericOperands(argv []string, scanBare bool) []parsedOperand {
	var out []parsedOperand
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			_, value, attached := strings.Cut(arg, "=")
			i = appendUnknownOptionValue(argv, i, value, attached, &out)
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			if len(arg) > 2 {
				i = appendUnknownOptionValue(argv, i, arg[2:], true, &out)
			} else {
				i = appendUnknownOptionValue(argv, i, "", false, &out)
			}
			continue
		}
		role := operandNonPath
		if scanBare || looksLikePathOperand(arg) {
			role = operandPath
		}
		out = append(out, parsedOperand{value: arg, role: role})
	}
	return out
}

func looksLikePathOperand(value string) bool {
	return strings.HasPrefix(value, "~") || strings.ContainsAny(value, `/\`) || isWindowsDrivePath(value)
}
