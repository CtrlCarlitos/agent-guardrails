package engine

import "strings"

type findActionKind uint8

const (
	findReadAction findActionKind = iota
	findWriteAction
	findCallbackAction
	findDeleteAction
	findUnsupportedAction
)

type findRoot struct {
	value     string
	sourceArg int
}

type findOutput struct {
	value string
}

type findReadPath struct {
	value string
}

type findCallbackTerminator uint8

const (
	findCallbackSemicolon findCallbackTerminator = iota
	findCallbackBatch
)

type findCallback struct {
	argv       []string
	sourceArg  int
	execDir    bool
	terminator findCallbackTerminator
}

type findAction struct {
	kind     findActionKind
	index    int
	end      int
	callback int
}

type findActionParseResult struct {
	roots                      []findRoot
	outputs                    []findOutput
	readPaths                  []findReadPath
	callbacks                  []findCallback
	actions                    []findAction
	expressionStart            int
	uncertaintyReason          string
	traversalUncertain         bool
	hasLeadingOptions          bool
	exactScopedDeletionManaged bool
	exactScopedDeletion        bool
	exactDeletionExecutableArg int
	scopedDeletionRoot         string
}

func parseFindActions(argv []string) findActionParseResult {
	var parsed findActionParseResult
	if len(argv) == 0 || head(argv) != "find" {
		return parsed
	}

	i := 1
	for i < len(argv) {
		switch {
		case argv[i] == "-P":
			parsed.hasLeadingOptions = true
			i++
		case argv[i] == "-H" || argv[i] == "-L":
			parsed.hasLeadingOptions = true
			parsed.traversalUncertain = true
			i++
		case argv[i] == "-D":
			parsed.hasLeadingOptions = true
			if i+1 >= len(argv) {
				parsed.noteUncertainty("find leading option is missing its value")
				i++
				continue
			}
			i += 2
		case len(argv[i]) == 3 && strings.HasPrefix(argv[i], "-O") && argv[i][2] >= '0' && argv[i][2] <= '3':
			parsed.hasLeadingOptions = true
			i++
		default:
			goto roots
		}
	}

roots:
	for i < len(argv) && !isFindExpressionToken(argv[i]) {
		parsed.roots = append(parsed.roots, findRoot{value: argv[i], sourceArg: i})
		i++
	}
	parsed.expressionStart = i
	expression := newFindExpressionValidator()

	for i < len(argv) {
		arg := argv[i]
		predicate, knownPredicate := describeFindPredicate(arg)
		switch {
		case isFindOperator(arg):
			expression.operator(arg)
			i++
		case knownPredicate:
			expression.operand()
			if arg == "-follow" {
				parsed.traversalUncertain = true
			}
			if i+predicate.arity >= len(argv) {
				parsed.noteUncertainty("find predicate is missing its value")
				i++
				continue
			}
			if predicate.operandRole == findPredicateReadPath {
				parsed.readPaths = append(parsed.readPaths, findReadPath{value: argv[i+1]})
			}
			i += predicate.arity + 1
		case arg == "-print" || arg == "-print0" || arg == "-ls" || arg == "-prune" || arg == "-quit":
			expression.operand()
			parsed.actions = append(parsed.actions, findAction{kind: findReadAction, index: i, end: i + 1})
			i++
		case arg == "-printf":
			expression.operand()
			end, ok := findActionArguments(argv, i, 1)
			if !ok {
				parsed.noteUncertainty("find -printf is missing its format")
				i++
				continue
			}
			parsed.actions = append(parsed.actions, findAction{kind: findReadAction, index: i, end: end})
			i = end
		case arg == "-fprint" || arg == "-fprint0" || arg == "-fls":
			expression.operand()
			end, ok := findActionArguments(argv, i, 1)
			if !ok {
				parsed.noteUncertainty("find file-output action is missing its destination")
				i++
				continue
			}
			parsed.outputs = append(parsed.outputs, findOutput{value: argv[i+1]})
			parsed.actions = append(parsed.actions, findAction{kind: findWriteAction, index: i, end: end})
			i = end
		case arg == "-fprintf":
			expression.operand()
			end, ok := findActionArguments(argv, i, 2)
			if !ok {
				parsed.noteUncertainty("find -fprintf is missing its destination or format")
				i++
				continue
			}
			parsed.outputs = append(parsed.outputs, findOutput{value: argv[i+1]})
			parsed.actions = append(parsed.actions, findAction{kind: findWriteAction, index: i, end: end})
			i = end
		case arg == "-delete":
			expression.operand()
			parsed.exactScopedDeletionManaged = true
			parsed.actions = append(parsed.actions, findAction{kind: findDeleteAction, index: i, end: i + 1})
			i++
		case arg == "-exec" || arg == "-execdir" || arg == "-ok" || arg == "-okdir":
			expression.operand()
			callback, end, ok := parseFindCallback(argv, i)
			if !ok {
				parsed.noteUncertainty("find callback is empty or unterminated")
				i++
				continue
			}
			callback.execDir = arg == "-execdir" || arg == "-okdir"
			if callback.terminator == findCallbackBatch && !validFindBatchCallback(callback.argv) {
				parsed.noteUncertainty("find batch callback requires exactly one final placeholder")
			}
			if arg == "-ok" || arg == "-okdir" {
				parsed.noteUncertainty("find callback requires unsupported execution semantics")
			}
			callbackIndex := len(parsed.callbacks)
			parsed.callbacks = append(parsed.callbacks, callback)
			kind := findCallbackAction
			if arg == "-ok" || arg == "-okdir" {
				kind = findUnsupportedAction
			}
			parsed.actions = append(parsed.actions, findAction{kind: kind, index: i, end: end, callback: callbackIndex})
			if callback.argv[0] == "rm" {
				parsed.exactScopedDeletionManaged = true
			}
			i = end
		default:
			expression.operand()
			parsed.noteUncertainty("find expression contains unknown grammar")
			i++
		}
	}
	if !expression.valid() {
		parsed.noteUncertainty("find expression structure is invalid")
	}

	parsed.classifyExactScopedDeletion(argv)
	return parsed
}

func (parsed *findActionParseResult) noteUncertainty(reason string) {
	if parsed.uncertaintyReason == "" {
		parsed.uncertaintyReason = reason
	}
}

func findActionArguments(argv []string, action, count int) (int, bool) {
	end := action + count + 1
	if end > len(argv) {
		return action + 1, false
	}
	return end, true
}

func parseFindCallback(argv []string, action int) (findCallback, int, bool) {
	for end := action + 1; end < len(argv); end++ {
		if argv[end] != ";" && argv[end] != `\;` && argv[end] != "+" {
			continue
		}
		if end == action+1 {
			return findCallback{}, end + 1, false
		}
		terminator := findCallbackSemicolon
		if argv[end] == "+" {
			terminator = findCallbackBatch
		}
		return findCallback{argv: append([]string(nil), argv[action+1:end]...), sourceArg: action + 1, terminator: terminator}, end + 1, true
	}
	return findCallback{}, action + 1, false
}

func validFindBatchCallback(argv []string) bool {
	placeholders := 0
	for _, arg := range argv {
		if arg == "{}" {
			placeholders++
		}
	}
	return placeholders == 1 && argv[len(argv)-1] == "{}"
}

func (parsed *findActionParseResult) classifyExactScopedDeletion(argv []string) {
	if !parsed.exactScopedDeletionManaged || parsed.uncertaintyReason != "" || parsed.traversalUncertain || parsed.hasLeadingOptions || len(parsed.roots) != 1 || len(parsed.actions) != 1 {
		return
	}
	action := parsed.actions[0]
	if action.end != len(argv) || !knownFindTests(argv[parsed.expressionStart:action.index]) {
		return
	}
	if action.kind == findDeleteAction {
		parsed.exactScopedDeletion = true
		parsed.scopedDeletionRoot = parsed.roots[0].value
		return
	}
	if action.kind != findCallbackAction {
		return
	}
	callback := parsed.callbacks[action.callback]
	if callback.argv[0] != "rm" || len(callback.argv) < 2 || callback.sourceArg >= len(argv) || argv[callback.sourceArg] != "rm" {
		return
	}
	for _, arg := range callback.argv[1:] {
		if knownFindRmOption(arg) {
			continue
		}
		if arg != "{}" {
			return
		}
	}
	if callback.argv[len(callback.argv)-1] != "{}" {
		return
	}
	parsed.exactScopedDeletion = true
	parsed.exactDeletionExecutableArg = callback.sourceArg
	parsed.scopedDeletionRoot = parsed.roots[0].value
}

func (parsed *findActionParseResult) applySourceProvenance(outer Simple) {
	if !parsed.exactScopedDeletion || parsed.exactDeletionExecutableArg == 0 {
		return
	}
	if outer.resolvedArgs[parsed.exactDeletionExecutableArg] || outer.wordUnresolved(parsed.exactDeletionExecutableArg) {
		parsed.exactScopedDeletion = false
	}
}

func isFindExpressionToken(value string) bool {
	return strings.HasPrefix(value, "-") || isFindOperator(value)
}

func isFindOperator(value string) bool {
	switch value {
	case "!", "(", ")", `\(`, `\)`, ",", "-a", "-and", "-o", "-or", "-not":
		return true
	default:
		return false
	}
}

type findPredicateOperandRole uint8

const (
	findPredicateInert findPredicateOperandRole = iota
	findPredicateReadPath
)

type findPredicateDescriptor struct {
	arity       int
	operandRole findPredicateOperandRole
}

func describeFindPredicate(value string) (findPredicateDescriptor, bool) {
	if strings.Contains(" -true -false -empty -readable -writable -executable -nouser -nogroup -xdev -mount -depth -daystart -ignore_readdir_race -noignore_readdir_race -follow ", " "+value+" ") {
		return findPredicateDescriptor{}, true
	}
	if strings.Contains(" -amin -anewer -atime -cmin -cnewer -context -ctime -fstype -gid -group -ilname -iname -inum -ipath -iregex -links -lname -maxdepth -mindepth -mmin -mtime -name -newer -path -perm -regex -regextype -samefile -size -type -uid -used -user -wholename -xattrname -xtype ", " "+value+" ") {
		role := findPredicateInert
		switch value {
		case "-newer", "-anewer", "-cnewer", "-samefile":
			role = findPredicateReadPath
		}
		return findPredicateDescriptor{arity: 1, operandRole: role}, true
	}
	if len(value) == 8 && strings.HasPrefix(value, "-newer") && strings.ContainsRune("aBcm", rune(value[6])) && strings.ContainsRune("aBcmt", rune(value[7])) {
		role := findPredicateInert
		if value[7] != 't' {
			role = findPredicateReadPath
		}
		return findPredicateDescriptor{arity: 1, operandRole: role}, true
	}
	return findPredicateDescriptor{}, false
}

type findExpressionFrame struct {
	hasOperand   bool
	needsOperand bool
}

type findExpressionValidator struct {
	frames   []findExpressionFrame
	sawToken bool
	invalid  bool
}

func newFindExpressionValidator() *findExpressionValidator {
	return &findExpressionValidator{frames: []findExpressionFrame{{needsOperand: true}}}
}

func (validator *findExpressionValidator) operator(value string) {
	validator.sawToken = true
	frame := &validator.frames[len(validator.frames)-1]
	switch value {
	case "!", "-not":
		frame.needsOperand = true
	case "(", `\(`:
		validator.frames = append(validator.frames, findExpressionFrame{needsOperand: true})
	case ")", `\)`:
		if len(validator.frames) == 1 || !frame.hasOperand || frame.needsOperand {
			validator.invalid = true
			return
		}
		validator.frames = validator.frames[:len(validator.frames)-1]
		parent := &validator.frames[len(validator.frames)-1]
		parent.hasOperand = true
		parent.needsOperand = false
	default:
		if !frame.hasOperand || frame.needsOperand {
			validator.invalid = true
			return
		}
		frame.needsOperand = true
	}
}

func (validator *findExpressionValidator) operand() {
	validator.sawToken = true
	frame := &validator.frames[len(validator.frames)-1]
	frame.hasOperand = true
	frame.needsOperand = false
}

func (validator *findExpressionValidator) valid() bool {
	if validator.invalid || len(validator.frames) != 1 {
		return false
	}
	frame := validator.frames[0]
	return !validator.sawToken || frame.hasOperand && !frame.needsOperand
}

func adaptFindCallbacks(parsed *findActionParseResult, outer Simple, tc ToolCall) []Simple {
	var callbacks []Simple
	for _, callback := range parsed.callbacks {
		// NF-9 owns direct rm callbacks; evaluating them again could strengthen an approved Ask into a Deny.
		if callback.argv[0] == "rm" {
			continue
		}
		argv := append([]string(nil), callback.argv...)
		for index, arg := range argv {
			if arg == "{}" {
				if len(parsed.roots) != 1 || outer.cwdUnknown || parsed.traversalUncertain || outer.wordUnresolved(parsed.roots[0].sourceArg) {
					parsed.noteUncertainty("find callback placeholder cannot be rooted soundly")
					continue
				}
				// Adapt the placeholder into path evidence without interpreting callback argv as shell source.
				argv[index] = resolvePath(parsed.roots[0].value, simpleCwd(outer, tc))
				continue
			}
			if strings.Contains(arg, "{}") {
				parsed.noteUncertainty("find callback contains a transforming placeholder")
			}
		}
		callbackSimple := commandDerivedFromAt(outer, argv, callback.sourceArg)
		if callback.execDir {
			callbackSimple.Unresolved = true
			callbackSimple.cwdUnknown = true
		}
		callbacks = append(callbacks, callbackSimple)
	}
	return callbacks
}

func findRootCandidates(parsed findActionParseResult, outer Simple, tc ToolCall) []pathCandidate {
	var candidates []pathCandidate
	for _, root := range parsed.roots {
		if looksLikePathOperand(root.value) {
			candidates = append(candidates, pathCandidate{path: root.value, cwd: outer.Cwd, cwdUnknown: outer.cwdUnknown, repoRoot: tc.RepoRoot})
		}
	}
	return candidates
}

func findOutputCandidates(parsed findActionParseResult, outer Simple, tc ToolCall) []pathCandidate {
	candidates := make([]pathCandidate, 0, len(parsed.outputs))
	for _, output := range parsed.outputs {
		candidates = append(candidates, pathCandidate{path: output.value, cwd: outer.Cwd, cwdUnknown: outer.cwdUnknown, repoRoot: tc.RepoRoot})
	}
	return candidates
}

func findReadPathCandidates(parsed findActionParseResult, outer Simple, tc ToolCall) []pathCandidate {
	candidates := make([]pathCandidate, 0, len(parsed.readPaths))
	for _, input := range parsed.readPaths {
		candidates = append(candidates, pathCandidate{path: input.value, cwd: outer.Cwd, cwdUnknown: outer.cwdUnknown, repoRoot: tc.RepoRoot})
	}
	return candidates
}
