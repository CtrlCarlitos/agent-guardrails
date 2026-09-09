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

type findCallback struct {
	argv    []string
	execDir bool
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
	callbacks                  []findCallback
	actions                    []findAction
	expressionStart            int
	uncertaintyReason          string
	traversalUncertain         bool
	hasLeadingOptions          bool
	exactScopedDeletionManaged bool
	exactScopedDeletion        bool
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

	for i < len(argv) {
		arg := argv[i]
		switch {
		case isFindOperator(arg):
			i++
		case knownFindNoValue(arg):
			if arg == "-follow" {
				parsed.traversalUncertain = true
			}
			i++
		case knownFindOneValue(arg):
			if i+1 >= len(argv) {
				parsed.noteUncertainty("find predicate is missing its value")
				i++
				continue
			}
			i += 2
		case arg == "-print" || arg == "-print0" || arg == "-ls" || arg == "-prune" || arg == "-quit":
			parsed.actions = append(parsed.actions, findAction{kind: findReadAction, index: i, end: i + 1})
			i++
		case arg == "-printf":
			end, ok := findActionArguments(argv, i, 1)
			if !ok {
				parsed.noteUncertainty("find -printf is missing its format")
				i++
				continue
			}
			parsed.actions = append(parsed.actions, findAction{kind: findReadAction, index: i, end: end})
			i = end
		case arg == "-fprint" || arg == "-fprint0" || arg == "-fls":
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
			parsed.exactScopedDeletionManaged = true
			parsed.actions = append(parsed.actions, findAction{kind: findDeleteAction, index: i, end: i + 1})
			i++
		case arg == "-exec" || arg == "-execdir" || arg == "-ok" || arg == "-okdir":
			callback, end, ok := parseFindCallback(argv, i)
			if !ok {
				parsed.noteUncertainty("find callback is empty or unterminated")
				i++
				continue
			}
			callback.execDir = arg == "-execdir" || arg == "-okdir"
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
			parsed.noteUncertainty("find expression contains unknown grammar")
			i++
		}
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
		return findCallback{argv: append([]string(nil), argv[action+1:end]...)}, end + 1, true
	}
	return findCallback{}, action + 1, false
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
	if callback.argv[0] != "rm" || len(callback.argv) < 2 {
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
	parsed.scopedDeletionRoot = parsed.roots[0].value
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

func isFindKnownGrammarToken(value string) bool {
	return isFindOperator(value) || knownFindNoValue(value) || knownFindOneValue(value) || strings.Contains(" -print -print0 -printf -fprintf -fprint -fprint0 -ls -fls -prune -quit -delete -exec -execdir -ok -okdir ", " "+value+" ")
}

func knownFindNoValue(value string) bool {
	return strings.Contains(" -true -false -empty -readable -writable -executable -nouser -nogroup -xdev -mount -depth -daystart -ignore_readdir_race -noignore_readdir_race -follow ", " "+value+" ")
}

func knownFindOneValue(value string) bool {
	if strings.Contains(" -amin -anewer -atime -cmin -cnewer -context -ctime -fstype -gid -group -ilname -iname -inum -ipath -iregex -links -lname -maxdepth -mindepth -mmin -mtime -name -newer -path -perm -regex -regextype -samefile -size -type -uid -used -user -wholename -xattrname -xtype ", " "+value+" ") {
		return true
	}
	return len(value) == 8 && strings.HasPrefix(value, "-newer") && strings.ContainsRune("aBcm", rune(value[6])) && strings.ContainsRune("aBcmt", rune(value[7]))
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
		callbackSimple := Simple{
			Argv: argv, Cwd: outer.Cwd, Unresolved: outer.Unresolved, cwdUnknown: outer.cwdUnknown,
			pipelines: append([]pipelinePosition(nil), outer.pipelines...),
		}
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
