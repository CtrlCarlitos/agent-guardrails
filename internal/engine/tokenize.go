package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/pattern"
	"mvdan.cc/sh/v3/syntax"
)

type Simple struct {
	Argv          []string
	Redirects     []string
	ReadRedirects []string
	Cwd           string
	Unresolved    bool
	pipelines     []pipelinePosition
	cwdUnknown    bool
	origin        *syntax.Stmt
	shellState    cwdState
}

type pipelinePosition struct {
	id    int
	stage int
}

type normalizeContext struct {
	nextPipelineID int
}

func splitSimples(src string) ([]Simple, error) {
	return splitSimplesWithContext(src, &normalizeContext{})
}

func splitSimplesWithContext(src string, ctx *normalizeContext) ([]Simple, error) {
	f, err := syntax.NewParser().Parse(strings.NewReader(src), "")
	if err != nil {
		return nil, err
	}
	pipelines := pipelinePositions(f, ctx, shadowedStaticCommandNames(f))
	return extractSimples(src, f, pipelines, nil), nil
}

func extractSimples(src string, f *syntax.File, pipelines map[*syntax.Stmt][]pipelinePosition, states map[*syntax.Stmt]cwdState) []Simple {
	var out []Simple
	syntax.Walk(f, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		state, tracked := states[stmt]
		if states != nil && !tracked {
			return false
		}
		var args []*syntax.Word
		if stmt.Cmd != nil {
			ce, ok := stmt.Cmd.(*syntax.CallExpr)
			if !ok {
				if len(stmt.Redirs) == 0 {
					return true
				}
			} else {
				args = ce.Args
			}
		}
		if len(args) == 0 && len(stmt.Redirs) == 0 {
			return true
		}
		s := Simple{pipelines: pipelines[stmt]}
		if tracked {
			s.Cwd = state.cwd
			s.Unresolved = state.unknown
			s.cwdUnknown = state.unknown
			s.origin = stmt
			s.shellState = state
		}
		for _, w := range args {
			raw := src[w.Pos().Offset():w.End().Offset()]
			if lit, ok := literalText(raw); ok {
				s.Argv = append(s.Argv, lit)
			} else {
				s.Argv = append(s.Argv, raw)
				s.Unresolved = true
			}
		}
		for _, r := range stmt.Redirs {
			if r.Word == nil {
				continue
			}
			read, write := false, false
			switch r.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
				write = true
			case syntax.RdrIn:
				read = true
			case syntax.RdrInOut:
				read, write = true, true
			case syntax.DplOut:
				if r.N != nil {
					continue
				}
				write = true
			default:
				continue
			}
			raw := src[r.Word.Pos().Offset():r.Word.End().Offset()]
			target, literal := literalText(raw)
			if !literal {
				target = raw
				s.Unresolved = true
			}
			if r.Op == syntax.DplOut && literal && (target == "-" || allDigits(target)) {
				continue
			}
			if write {
				s.Redirects = append(s.Redirects, target)
			}
			if read {
				s.ReadRedirects = append(s.ReadRedirects, target)
			}
		}
		out = append(out, s)
		return true
	})
	return out
}

func pipelinePositions(f *syntax.File, ctx *normalizeContext, shadowedConstants map[string]bool) map[*syntax.Stmt][]pipelinePosition {
	pipeStatements := make(map[*syntax.Stmt]bool)
	childPipes := make(map[*syntax.Stmt]bool)
	syntax.Walk(f, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		binary, ok := stmt.Cmd.(*syntax.BinaryCmd)
		if !ok || binary.Op != syntax.Pipe && binary.Op != syntax.PipeAll {
			return true
		}
		pipeStatements[stmt] = true
		for _, child := range []*syntax.Stmt{binary.X, binary.Y} {
			if nested, ok := child.Cmd.(*syntax.BinaryCmd); ok && (nested.Op == syntax.Pipe || nested.Op == syntax.PipeAll) {
				childPipes[child] = true
			}
		}
		return true
	})

	positions := make(map[*syntax.Stmt][]pipelinePosition)
	for stmt := range pipeStatements {
		if childPipes[stmt] {
			continue
		}
		ctx.nextPipelineID++
		pipelineID := ctx.nextPipelineID
		carriesInput := true
		for stage, stageRoot := range flattenPipeline(stmt) {
			if stage > 0 && !carriesInput {
				ctx.nextPipelineID++
				pipelineID = ctx.nextPipelineID
			}
			position := pipelinePosition{id: pipelineID, stage: stage}
			carriesInput = markPipelineIngress(positions, stageRoot, position, shadowedConstants).forwards
		}
	}
	return positions
}

func shadowedStaticCommandNames(f *syntax.File) map[string]bool {
	shadowed := make(map[string]bool)
	syntax.Walk(f, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.FuncDecl:
			declaration := node
			name := declaration.Name.Value
			if name == "true" || name == "false" {
				shadowed[name] = true
			}
		case *syntax.CallExpr:
			source, isEval, static := possibleEvalSource(node)
			if !isEval {
				break
			}
			if !static {
				shadowed["true"] = true
				shadowed["false"] = true
				break
			}
			nested, err := syntax.NewParser().Parse(strings.NewReader(source), "")
			if err != nil {
				break
			}
			for name := range shadowedStaticCommandNames(nested) {
				shadowed[name] = true
			}
		}
		return true
	})
	return shadowed
}

func possibleEvalSource(call *syntax.CallExpr) (source string, isEval, static bool) {
	argv := make([]string, 0, len(call.Args))
	complete := true
	for _, word := range call.Args {
		value, ok := staticWord(word, false)
		if !ok {
			complete = false
			break
		}
		argv = append(argv, value)
	}
	argv, _, noExecute, err := directCommandArgv(argv)
	if err != nil || noExecute || len(argv) == 0 || argv[0] != "eval" {
		return "", false, false
	}
	if !complete {
		return "", true, false
	}
	return strings.Join(argv[1:], " "), true, true
}

type stdinFlow struct {
	allConsume bool
	forwards   bool
}

func markPipelineIngress(positions map[*syntax.Stmt][]pipelinePosition, stmt *syntax.Stmt, position pipelinePosition, shadowedConstants map[string]bool) stdinFlow {
	if stmt == nil {
		return stdinFlow{}
	}
	if expansionFlow := markStatementExpansionIngress(positions, stmt, position, shadowedConstants); expansionFlow.allConsume {
		return expansionFlow
	}
	positions[stmt] = append(positions[stmt], position)
	if stdinReplaced(stmt) {
		return stdinFlow{}
	}
	var flow stdinFlow
	switch command := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		flow = simpleStdinFlow(command)
	case *syntax.BinaryCmd:
		if command.Op == syntax.Pipe || command.Op == syntax.PipeAll {
			carriesInput := true
			for stage, stageRoot := range flattenPipeline(stmt) {
				if !carriesInput {
					break
				}
				stageFlow := markPipelineIngress(positions, stageRoot, position, shadowedConstants)
				if stage == 0 {
					flow.allConsume = stageFlow.allConsume
				}
				carriesInput = stageFlow.forwards
			}
			flow.forwards = carriesInput
			break
		}
		flow = markPipelineList(positions, []*syntax.Stmt{command.X, command.Y}, position, shadowedConstants)
	case *syntax.Block:
		flow = markPipelineList(positions, command.Stmts, position, shadowedConstants)
	case *syntax.Subshell:
		flow = markPipelineList(positions, command.Stmts, position, shadowedConstants)
	case *syntax.IfClause:
		flow = markIfClauseIngress(positions, command, position, shadowedConstants)
	case *syntax.WhileClause:
		flow = markWhileClauseIngress(positions, command, position, shadowedConstants)
	case *syntax.ForClause:
		switch forClauseIterations(command) {
		case iterationGuaranteed:
			flow = markPipelineList(positions, command.Do, position, shadowedConstants)
		case iterationPossible:
			flow = markPipelineList(positions, command.Do, position, shadowedConstants)
			flow.allConsume = false
		}
	case *syntax.CaseClause:
		flow = markCaseClauseIngress(positions, command, position, shadowedConstants)
	case *syntax.TimeClause:
		flow = markPipelineIngress(positions, command.Stmt, position, shadowedConstants)
	default:
		// Unknown compound forms may consume or forward stdin. Preserve both
		// possibilities so later checks fail closed.
		flow.forwards = true
	}
	if stdoutReplaced(stmt) {
		flow.forwards = false
	}
	return flow
}

func markPipelineList(positions map[*syntax.Stmt][]pipelinePosition, stmts []*syntax.Stmt, position pipelinePosition, shadowedConstants map[string]bool) stdinFlow {
	var flow stdinFlow
	for _, stmt := range stmts {
		if flow.allConsume {
			break
		}
		statementFlow := markPipelineIngress(positions, stmt, position, shadowedConstants)
		flow.forwards = flow.forwards || statementFlow.forwards
		flow.allConsume = statementFlow.allConsume
	}
	return flow
}

func mergeAlternativeStdinFlows(flows ...stdinFlow) stdinFlow {
	if len(flows) == 0 {
		return stdinFlow{}
	}
	merged := stdinFlow{allConsume: true}
	for _, flow := range flows {
		merged.allConsume = merged.allConsume && flow.allConsume
		merged.forwards = merged.forwards || flow.forwards
	}
	return merged
}

type conditionTruth uint8

const (
	conditionUnknown conditionTruth = iota
	conditionTrue
	conditionFalse
)

func (truth conditionTruth) negated() conditionTruth {
	switch truth {
	case conditionTrue:
		return conditionFalse
	case conditionFalse:
		return conditionTrue
	default:
		return conditionUnknown
	}
}

func markIfClauseIngress(positions map[*syntax.Stmt][]pipelinePosition, clause *syntax.IfClause, position pipelinePosition, shadowedConstants map[string]bool) stdinFlow {
	if len(clause.Cond) == 0 {
		return markPipelineList(positions, clause.Then, position, shadowedConstants) // plain else
	}
	conditionFlow := markPipelineList(positions, clause.Cond, position, shadowedConstants)
	if conditionFlow.allConsume {
		return conditionFlow
	}
	thenFlow := func() stdinFlow {
		return markPipelineList(positions, clause.Then, position, shadowedConstants)
	}
	elseFlow := func() stdinFlow {
		if clause.Else == nil {
			return stdinFlow{} // condition false with no else
		}
		return markIfClauseIngress(positions, clause.Else, position, shadowedConstants)
	}
	var branches stdinFlow
	switch literalCondition(clause.Cond, shadowedConstants) {
	case conditionTrue:
		branches = thenFlow()
	case conditionFalse:
		branches = elseFlow()
	default:
		branches = mergeAlternativeStdinFlows(thenFlow(), elseFlow())
	}
	branches.forwards = branches.forwards || conditionFlow.forwards
	return branches
}

func literalCondition(stmts []*syntax.Stmt, shadowedConstants map[string]bool) conditionTruth {
	if len(stmts) != 1 {
		return conditionUnknown
	}
	stmt := stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 1 || len(call.Assigns) != 0 || len(stmt.Redirs) != 0 ||
		stmt.Background || stmt.Coprocess {
		return conditionUnknown
	}
	name := call.Args[0].Lit()
	truth := conditionUnknown
	switch name {
	case ":":
		truth = conditionTrue
	case "true":
		if !shadowedConstants[name] {
			truth = conditionTrue
		}
	case "false":
		if !shadowedConstants[name] {
			truth = conditionFalse
		}
	}
	if stmt.Negated {
		return truth.negated()
	}
	return truth
}

func markCaseClauseIngress(positions map[*syntax.Stmt][]pipelinePosition, clause *syntax.CaseClause, position pipelinePosition, shadowedConstants map[string]bool) stdinFlow {
	if expansionFlow := markWordExpansionIngress(positions, clause.Word, position, shadowedConstants); expansionFlow.allConsume {
		return expansionFlow
	}
	selector, static := staticWord(clause.Word, false)
	matches := make([]bool, len(clause.Items))
	if static {
		for index, item := range clause.Items {
			matches[index], static = staticCaseItemMatches(selector, item)
			if !static {
				break
			}
		}
	}
	if static {
		return markStaticCaseIngress(positions, clause.Items, matches, position, shadowedConstants)
	}
	return markUnknownCaseIngress(positions, clause.Items, position, shadowedConstants)
}

func markUnknownCaseIngress(positions map[*syntax.Stmt][]pipelinePosition, items []*syntax.CaseItem, position pipelinePosition, shadowedConstants map[string]bool) stdinFlow {
	flows := make([]stdinFlow, 0, len(items)+1)
	exhaustive := false
	for _, item := range items {
		itemFlow := markPipelineList(positions, item.Stmts, position, shadowedConstants)
		if item.Op != syntax.Break {
			itemFlow.allConsume = false // fallthrough control flow is not exhaustive here
		}
		flows = append(flows, itemFlow)
		defaultItem := false
		for _, pattern := range item.Patterns {
			if len(pattern.Parts) == 1 {
				if literal, ok := pattern.Parts[0].(*syntax.Lit); ok && literal.Value == "*" {
					exhaustive = true
					defaultItem = true
				}
			}
		}
		if defaultItem && item.Op == syntax.Break {
			break
		}
	}
	if !exhaustive {
		flows = append(flows, stdinFlow{}) // no case item matched
	}
	return mergeAlternativeStdinFlows(flows...)
}

func markStaticCaseIngress(positions map[*syntax.Stmt][]pipelinePosition, items []*syntax.CaseItem, matches []bool, position pipelinePosition, shadowedConstants map[string]bool) stdinFlow {
	var flow stdinFlow
	for _, index := range staticCaseExecution(items, matches) {
		item := items[index]
		itemFlow := markPipelineList(positions, item.Stmts, position, shadowedConstants)
		flow.allConsume = itemFlow.allConsume
		flow.forwards = flow.forwards || itemFlow.forwards
		if flow.allConsume {
			return flow
		}
	}
	return flow
}

func staticCaseItemMatches(selector string, item *syntax.CaseItem) (bool, bool) {
	for _, word := range item.Patterns {
		casePattern, static := staticWord(word, true)
		if !static {
			return false, false
		}
		expression, err := pattern.Regexp(casePattern, pattern.EntireString)
		if err != nil {
			return false, false
		}
		matched, err := regexp.MatchString(expression, selector)
		if err != nil {
			return false, false
		}
		if matched {
			return true, true
		}
	}
	return false, true
}

func staticWord(word *syntax.Word, casePattern bool) (string, bool) {
	return staticWordParts(word, casePattern, false)
}

func staticWordParts(word *syntax.Word, casePattern, quoted bool) (string, bool) {
	if word == nil {
		return "", false
	}
	var value strings.Builder
	for index, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			if !casePattern && !quoted && index == 0 && strings.HasPrefix(part.Value, "~") {
				return "", false
			}
			value.WriteString(part.Value)
		case *syntax.SglQuoted:
			if part.Dollar {
				return "", false
			}
			if casePattern {
				value.WriteString(pattern.QuoteMeta(part.Value, 0))
			} else {
				value.WriteString(part.Value)
			}
		case *syntax.DblQuoted:
			quotedValue, static := staticWordParts(&syntax.Word{Parts: part.Parts}, false, true)
			if !static {
				return "", false
			}
			if casePattern {
				value.WriteString(pattern.QuoteMeta(quotedValue, 0))
			} else {
				value.WriteString(quotedValue)
			}
		default:
			return "", false
		}
	}
	return value.String(), true
}

func markWhileClauseIngress(positions map[*syntax.Stmt][]pipelinePosition, clause *syntax.WhileClause, position pipelinePosition, shadowedConstants map[string]bool) stdinFlow {
	conditionFlow := markPipelineList(positions, clause.Cond, position, shadowedConstants)
	if conditionFlow.allConsume {
		return conditionFlow
	}
	truth := literalCondition(clause.Cond, shadowedConstants)
	bodyReachable := truth != conditionFalse
	bodyGuaranteed := truth == conditionTrue
	if clause.Until {
		bodyReachable = truth != conditionTrue
		bodyGuaranteed = truth == conditionFalse
	}
	if bodyReachable {
		bodyFlow := markPipelineList(positions, clause.Do, position, shadowedConstants)
		conditionFlow.forwards = conditionFlow.forwards || bodyFlow.forwards
		if bodyGuaranteed {
			conditionFlow.allConsume = bodyFlow.allConsume
			return conditionFlow
		}
	}
	conditionFlow.allConsume = false
	return conditionFlow
}

type loopIterations uint8

const (
	iterationNone loopIterations = iota
	iterationPossible
	iterationGuaranteed
)

func forClauseIterations(clause *syntax.ForClause) loopIterations {
	return analyzeForClause(clause).iterations
}

type forClauseAnalysis struct {
	iterations loopIterations
	mayRepeat  bool
}

func analyzeForClause(clause *syntax.ForClause) forClauseAnalysis {
	words, ok := clause.Loop.(*syntax.WordIter)
	if !ok || !words.InPos.IsValid() {
		return forClauseAnalysis{iterations: iterationPossible, mayRepeat: true}
	}
	if len(words.Items) == 0 {
		return forClauseAnalysis{iterations: iterationNone}
	}
	facts := forClauseAnalysis{iterations: iterationPossible, mayRepeat: len(words.Items) > 1}
	for _, word := range words.Items {
		if wordGuaranteesField(word) {
			facts.iterations = iterationGuaranteed
		}
		value, static := staticWord(word, false)
		if !static || strings.ContainsAny(value, "*?[") {
			facts.mayRepeat = true
		}
	}
	return facts
}

func wordGuaranteesField(word *syntax.Word) bool {
	guaranteed := false
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, "*?[") {
				return false
			}
			guaranteed = guaranteed || part.Value != ""
		case *syntax.SglQuoted:
			guaranteed = true
		case *syntax.DblQuoted:
			if doubleQuotedGuaranteesField(part) {
				guaranteed = true
			}
		default:
			return false
		}
	}
	return guaranteed
}

func doubleQuotedGuaranteesField(quoted *syntax.DblQuoted) bool {
	if len(quoted.Parts) == 0 {
		return true
	}
	for _, part := range quoted.Parts {
		parameter, isParameter := part.(*syntax.ParamExp)
		if !isParameter || !quotedParameterMayProduceZeroFields(parameter) {
			return true
		}
	}
	return false
}

func quotedParameterMayProduceZeroFields(parameter *syntax.ParamExp) bool {
	if parameter.Length {
		return false
	}
	if parameter.Param.Value == "@" {
		return true
	}
	index, ok := parameter.Index.(*syntax.Word)
	return ok && index.Lit() == "@"
}

func markStatementExpansionIngress(positions map[*syntax.Stmt][]pipelinePosition, stmt *syntax.Stmt, position pipelinePosition, shadowedConstants map[string]bool) stdinFlow {
	var nodes []syntax.Node
	if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
		for _, assignment := range call.Assigns {
			nodes = append(nodes, assignment)
		}
		for _, word := range call.Args {
			nodes = append(nodes, word)
		}
	}
	for _, redirect := range stmt.Redirs {
		nodes = append(nodes, redirect)
	}
	return markNodeExpansionIngress(positions, nodes, position, shadowedConstants)
}

func markWordExpansionIngress(positions map[*syntax.Stmt][]pipelinePosition, word *syntax.Word, position pipelinePosition, shadowedConstants map[string]bool) stdinFlow {
	if word == nil {
		return stdinFlow{}
	}
	return markNodeExpansionIngress(positions, []syntax.Node{word}, position, shadowedConstants)
}

func markNodeExpansionIngress(positions map[*syntax.Stmt][]pipelinePosition, nodes []syntax.Node, position pipelinePosition, shadowedConstants map[string]bool) stdinFlow {
	var expansions []syntax.Node
	for _, root := range nodes {
		syntax.Walk(root, func(node syntax.Node) bool {
			switch node.(type) {
			case *syntax.CmdSubst, *syntax.ProcSubst:
				expansions = append(expansions, node)
				return false
			}
			return true
		})
	}
	sort.SliceStable(expansions, func(i, j int) bool {
		return expansions[i].Pos().Offset() < expansions[j].Pos().Offset()
	})
	var flow stdinFlow
	for _, node := range expansions {
		if flow.allConsume {
			break
		}
		switch expansion := node.(type) {
		case *syntax.CmdSubst:
			flow.allConsume = markPipelineList(positions, expansion.Stmts, position, shadowedConstants).allConsume
		case *syntax.ProcSubst:
			if expansion.Op == syntax.CmdIn {
				markPipelineList(positions, expansion.Stmts, position, shadowedConstants)
			}
		}
	}
	return flow
}

func simpleStdinFlow(command *syntax.CallExpr) stdinFlow {
	if len(command.Args) == 0 {
		return stdinFlow{}
	}
	name := command.Args[0].Lit()
	if slash := strings.LastIndexAny(name, `/\`); slash >= 0 {
		name = name[slash+1:]
	}
	switch name {
	case ":", "true", "false", "printf", "echo", "pwd", "ls", "touch", "mkdir", "sleep", "test", "[":
		return stdinFlow{}
	case "cat":
		usesStdin := false
		hasFileOperand := false
		options := true
		for _, word := range command.Args[1:] {
			arg := word.Lit()
			if options && arg == "--" {
				options = false
				continue
			}
			if options && strings.HasPrefix(arg, "-") && arg != "-" {
				continue
			}
			if arg == "-" {
				usesStdin = true
			} else if arg == "" {
				usesStdin = true
			} else {
				hasFileOperand = true
			}
		}
		usesStdin = usesStdin || !hasFileOperand
		return stdinFlow{allConsume: usesStdin, forwards: usesStdin}
	case "tee":
		return stdinFlow{allConsume: true, forwards: true}
	case "read":
		return stdinFlow{allConsume: true}
	default:
		// An unknown command may leave stdin untouched and may copy it to
		// stdout. Keeping both possibilities is conservative without making a
		// later source-only pipeline inherit this command's input.
		return stdinFlow{forwards: true}
	}
}

func stdinReplaced(stmt *syntax.Stmt) bool {
	for _, redirect := range stmt.Redirs {
		if redirect.N != nil && redirect.N.Value != "0" {
			continue
		}
		switch redirect.Op {
		case syntax.RdrIn, syntax.RdrInOut, syntax.DplIn, syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
			return true
		}
	}
	return false
}

func stdoutReplaced(stmt *syntax.Stmt) bool {
	for _, redirect := range stmt.Redirs {
		if redirect.Op == syntax.RdrAll || redirect.Op == syntax.AppAll {
			return true
		}
		if redirect.N != nil && redirect.N.Value != "1" {
			continue
		}
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.DplOut:
			return true
		}
	}
	return false
}

func flattenPipeline(stmt *syntax.Stmt) []*syntax.Stmt {
	binary, ok := stmt.Cmd.(*syntax.BinaryCmd)
	if !ok || binary.Op != syntax.Pipe && binary.Op != syntax.PipeAll {
		return []*syntax.Stmt{stmt}
	}
	return append(flattenPipeline(binary.X), flattenPipeline(binary.Y)...)
}

type cwdState struct {
	cwd           string
	unknown       bool
	fsUncertain   bool
	cdpath        string
	cdpathSet     bool
	cdpathUnknown bool
}

type cwdOutcome struct {
	success    cwdState
	failure    cwdState
	canSuccess bool
	canFailure bool
}

func successOutcome(state cwdState) cwdOutcome {
	return cwdOutcome{success: state, canSuccess: true}
}

func bothOutcome(state cwdState) cwdOutcome {
	return cwdOutcome{success: state, failure: state, canSuccess: true, canFailure: true}
}

func (out cwdOutcome) negated() cwdOutcome {
	return cwdOutcome{
		success:    out.failure,
		failure:    out.success,
		canSuccess: out.canFailure,
		canFailure: out.canSuccess,
	}
}

func (out cwdOutcome) hasFilesystemUncertainty() bool {
	return out.canSuccess && out.success.fsUncertain || out.canFailure && out.failure.fsUncertain
}

func (out cwdOutcome) merged() cwdState {
	switch {
	case out.canSuccess && out.canFailure:
		return mergeCwd(out.success, out.failure)
	case out.canSuccess:
		return out.success
	case out.canFailure:
		return out.failure
	default:
		return cwdState{unknown: true}
	}
}

func mergeOutcomes(outcomes ...cwdOutcome) cwdOutcome {
	var merged cwdOutcome
	for _, out := range outcomes {
		if out.canSuccess {
			if merged.canSuccess {
				merged.success = mergeCwd(merged.success, out.success)
			} else {
				merged.success = out.success
				merged.canSuccess = true
			}
		}
		if out.canFailure {
			if merged.canFailure {
				merged.failure = mergeCwd(merged.failure, out.failure)
			} else {
				merged.failure = out.failure
				merged.canFailure = true
			}
		}
	}
	return merged
}

type shellFunction struct {
	source string
}

type shellFunctionSet struct {
	bodies         []shellFunction
	mayBeUndefined bool
}

type cwdWalker struct {
	src          string
	ctx          *normalizeContext
	states       map[*syntax.Stmt]cwdState
	replacements map[*syntax.Stmt][]Simple
	functions    map[string]shellFunctionSet
	active       map[string]bool
	shadowed     map[string]bool
	pipelines    map[*syntax.Stmt][]pipelinePosition
	recursive    map[*syntax.Stmt]cwdState
	uncertainDef bool
}

func (w *cwdWalker) list(stmts []*syntax.Stmt, state cwdState) cwdOutcome {
	out := successOutcome(state)
	for _, stmt := range stmts {
		out = w.stmt(stmt, out.merged())
	}
	return out
}

func (w *cwdWalker) stmt(stmt *syntax.Stmt, state cwdState) cwdOutcome {
	if declaration, ok := stmt.Cmd.(*syntax.FuncDecl); ok && !stmt.Background && !stmt.Coprocess {
		w.defineFunction(
			declaration.Name.Value,
			w.src[declaration.Body.Pos().Offset():declaration.Body.End().Offset()],
			w.uncertainDef || state.unknown,
		)
		return successOutcome(state)
	}
	w.states[stmt] = state
	var preCommandFunctions map[string]shellFunctionSet
	if len(stmt.Redirs) > 0 {
		preCommandFunctions = cloneFunctions(w.functions)
	}
	if w.redirectExpansions(stmt.Redirs, state) {
		state.fsUncertain = true
	}
	redirectFailure := len(stmt.Redirs) > 0
	if redirectsWrite(stmt.Redirs) {
		state.fsUncertain = true
	}

	if stmt.Background || stmt.Coprocess {
		child := w.isolated()
		child.command(stmt, state)
		// The parent races an arbitrary child command, whose filesystem effects
		// cannot be observed from the pre-execution filesystem.
		state.fsUncertain = true
		return bothOutcome(state)
	}
	out := w.command(stmt, state)
	if redirectFailure {
		w.joinFunctionEnvironment(preCommandFunctions)
		out = mergeOutcomes(out, cwdOutcome{failure: state, canFailure: true})
	}
	if stmt.Negated {
		out = out.negated()
	}
	return out
}

func (w *cwdWalker) defineFunction(name, source string, uncertain bool) {
	definition := shellFunction{source: source}
	if !uncertain {
		w.functions[name] = shellFunctionSet{bodies: []shellFunction{definition}}
	} else {
		set, existed := w.functions[name]
		if !existed {
			set.mayBeUndefined = true
		}
		set.bodies = appendFunctionBody(set.bodies, definition)
		w.functions[name] = set
	}
	if name == "true" || name == "false" {
		w.shadowed[name] = true
	}
}

func redirectsWrite(redirs []*syntax.Redirect) bool {
	for _, redirect := range redirs {
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
			return true
		case syntax.DplOut:
			if redirect.N == nil {
				return true
			}
		}
	}
	return false
}

func (w *cwdWalker) command(stmt *syntax.Stmt, state cwdState) cwdOutcome {
	switch command := stmt.Cmd.(type) {
	case nil:
		return bothOutcome(state)
	case *syntax.CallExpr:
		if w.expansions(command, state) {
			state.fsUncertain = true
		}
		return w.call(stmt, command, state)
	case *syntax.BinaryCmd:
		switch command.Op {
		case syntax.Pipe, syntax.PipeAll:
			left := w.isolated().stmt(command.X, state)
			right := w.isolated().stmt(command.Y, state)
			state.fsUncertain = state.fsUncertain || left.hasFilesystemUncertainty() || right.hasFilesystemUncertainty()
			return bothOutcome(state)
		case syntax.AndStmt:
			left := w.stmt(command.X, state)
			var paths []cwdOutcome
			if left.canFailure {
				paths = append(paths, cwdOutcome{failure: left.failure, canFailure: true})
			}
			if left.canSuccess {
				paths = append(paths, w.withFunctionEnvironmentAlternative(left.canFailure, func() cwdOutcome {
					return w.stmt(command.Y, left.success)
				}))
			}
			return mergeOutcomes(paths...)
		case syntax.OrStmt:
			left := w.stmt(command.X, state)
			var paths []cwdOutcome
			if left.canSuccess {
				paths = append(paths, cwdOutcome{success: left.success, canSuccess: true})
			}
			if left.canFailure {
				paths = append(paths, w.withFunctionEnvironmentAlternative(left.canSuccess, func() cwdOutcome {
					return w.stmt(command.Y, left.failure)
				}))
			}
			return mergeOutcomes(paths...)
		}
	case *syntax.Block:
		return w.list(command.Stmts, state)
	case *syntax.Subshell:
		child := w.isolated().list(command.Stmts, state)
		state.fsUncertain = state.fsUncertain || child.hasFilesystemUncertainty()
		return cwdOutcome{success: state, failure: state, canSuccess: child.canSuccess, canFailure: child.canFailure}
	case *syntax.IfClause:
		return w.ifClause(command, state)
	case *syntax.WhileClause:
		return w.whileClause(command, state)
	case *syntax.ForClause:
		if w.expansions(command.Loop, state) {
			state.fsUncertain = true
		}
		switch forClauseIterations(command) {
		case iterationNone:
			return successOutcome(state)
		}
		uncertainBody := forClauseIterations(command) == iterationPossible || forClauseMayRepeat(command)
		body := w.withUncertainDefinitions(uncertainBody, func() cwdOutcome { return w.list(command.Do, state) })
		post := body.merged()
		if forClauseIterations(command) == iterationPossible {
			post = mergeCwd(state, post)
		}
		if forClauseMayRepeat(command) && cwdMayChange(state, post) {
			post = unknownCwd(state, post)
		}
		return bothOutcome(post)
	case *syntax.CaseClause:
		return w.caseClause(command, state)
	case *syntax.TimeClause:
		return w.stmt(command.Stmt, state)
	case *syntax.FuncDecl:
		w.isolated().stmt(command.Body, state)
		return bothOutcome(state)
	default:
		if w.expansions(command, state) {
			state.fsUncertain = true
		}
		return bothOutcome(state)
	}
	return bothOutcome(unknownCwd(state))
}

func (w *cwdWalker) ifClause(clause *syntax.IfClause, state cwdState) cwdOutcome {
	if !clause.ThenPos.IsValid() {
		return w.list(clause.Then, state)
	}
	condition := w.list(clause.Cond, state)
	truth := literalCondition(clause.Cond, w.shadowed)
	var paths []cwdOutcome
	if truth != conditionFalse && condition.canSuccess {
		paths = append(paths, w.withUncertainDefinitions(truth == conditionUnknown, func() cwdOutcome {
			return w.list(clause.Then, condition.success)
		}))
	}
	if truth != conditionTrue && condition.canFailure {
		if clause.Else == nil {
			paths = append(paths, successOutcome(condition.failure))
		} else {
			paths = append(paths, w.withUncertainDefinitions(truth == conditionUnknown, func() cwdOutcome {
				return w.ifClause(clause.Else, condition.failure)
			}))
		}
	}
	return mergeOutcomes(paths...)
}

func (w *cwdWalker) whileClause(clause *syntax.WhileClause, state cwdState) cwdOutcome {
	condition := w.list(clause.Cond, state)
	truth := literalCondition(clause.Cond, w.shadowed)
	bodyReachable := truth != conditionFalse
	bodyState, exitState := condition.success, condition.failure
	if clause.Until {
		bodyReachable = truth != conditionTrue
		bodyState, exitState = condition.failure, condition.success
	}
	if !bodyReachable {
		return successOutcome(exitState)
	}
	body := w.withUncertainDefinitions(true, func() cwdOutcome { return w.list(clause.Do, bodyState) })
	bodyPost := body.merged()
	if cwdMayChange(state, bodyPost) {
		bodyPost = unknownCwd(state, bodyPost)
	}
	if truth == conditionUnknown {
		return bothOutcome(mergeCwd(exitState, bodyPost))
	}
	// A syntactically endless loop can still exit through break or an
	// unmodelled status/control transfer. Keep following commands reachable.
	return bothOutcome(bodyPost)
}

func (w *cwdWalker) caseClause(clause *syntax.CaseClause, state cwdState) cwdOutcome {
	w.expansions(clause.Word, state)
	selector, static := staticWord(clause.Word, false)
	if static {
		matches := make([]bool, len(clause.Items))
		for index, item := range clause.Items {
			matches[index], static = staticCaseItemMatches(selector, item)
			if !static {
				break
			}
		}
		if static {
			for _, index := range staticCaseExecution(clause.Items, matches) {
				state = w.list(clause.Items[index].Stmts, state).merged()
			}
			return bothOutcome(state)
		}
	}
	exits := []cwdState{state}
	for _, item := range clause.Items {
		for _, pattern := range item.Patterns {
			w.expansions(pattern, state)
		}
		exits = append(exits, w.withUncertainDefinitions(true, func() cwdOutcome {
			return w.list(item.Stmts, state)
		}).merged())
	}
	return bothOutcome(mergeCwd(exits...))
}

func (w *cwdWalker) withUncertainDefinitions(uncertain bool, walk func() cwdOutcome) cwdOutcome {
	previous := w.uncertainDef
	w.uncertainDef = previous || uncertain
	out := walk()
	w.uncertainDef = previous
	return out
}

func staticCaseExecution(items []*syntax.CaseItem, matches []bool) []int {
	var executed []int
	testing := true
	for index, item := range items {
		if testing && !matches[index] {
			continue
		}
		executed = append(executed, index)
		switch item.Op {
		case syntax.Break:
			return executed
		case syntax.Fallthrough:
			testing = false
		default:
			testing = true
		}
	}
	return executed
}

func (w *cwdWalker) expansions(node syntax.Node, state cwdState) bool {
	if node == nil {
		return false
	}
	filesystemUncertain := false
	syntax.Walk(node, func(node syntax.Node) bool {
		switch expansion := node.(type) {
		case *syntax.CmdSubst:
			filesystemUncertain = filesystemUncertain || w.isolated().list(expansion.Stmts, state).hasFilesystemUncertainty()
			return false
		case *syntax.ProcSubst:
			filesystemUncertain = filesystemUncertain || w.isolated().list(expansion.Stmts, state).hasFilesystemUncertainty()
			return false
		}
		return true
	})
	return filesystemUncertain
}

func (w *cwdWalker) isolated() *cwdWalker {
	child := *w
	child.functions = cloneFunctions(w.functions)
	return &child
}

func cloneFunctions(functions map[string]shellFunctionSet) map[string]shellFunctionSet {
	clone := make(map[string]shellFunctionSet, len(functions))
	for name, set := range functions {
		set.bodies = append([]shellFunction(nil), set.bodies...)
		clone[name] = set
	}
	return clone
}

func appendFunctionBody(bodies []shellFunction, definition shellFunction) []shellFunction {
	for _, body := range bodies {
		if body.source == definition.source {
			return bodies
		}
	}
	return append(bodies, definition)
}

func mergeFunctionAlternatives(alternatives ...map[string]shellFunctionSet) map[string]shellFunctionSet {
	merged := make(map[string]shellFunctionSet)
	for _, functions := range alternatives {
		for name, set := range functions {
			current := merged[name]
			current.mayBeUndefined = current.mayBeUndefined || set.mayBeUndefined
			for _, body := range set.bodies {
				current.bodies = appendFunctionBody(current.bodies, body)
			}
			merged[name] = current
		}
	}
	for name, set := range merged {
		for _, functions := range alternatives {
			if _, ok := functions[name]; !ok {
				set.mayBeUndefined = true
			}
		}
		merged[name] = set
	}
	return merged
}

func (w *cwdWalker) publishFunctions(functions map[string]shellFunctionSet, uncertain bool) {
	if uncertain {
		w.functions = mergeFunctionAlternatives(w.functions, functions)
	} else {
		w.functions = cloneFunctions(functions)
	}
	for name := range w.functions {
		if name == "true" || name == "false" {
			w.shadowed[name] = true
		}
	}
}

func (w *cwdWalker) joinFunctionEnvironment(alternative map[string]shellFunctionSet) {
	w.publishFunctions(mergeFunctionAlternatives(alternative, w.functions), false)
}

func (w *cwdWalker) withFunctionEnvironmentAlternative(includePrior bool, walk func() cwdOutcome) cwdOutcome {
	if !includePrior {
		return walk()
	}
	prior := cloneFunctions(w.functions)
	out := walk()
	w.joinFunctionEnvironment(prior)
	return out
}

func (w *cwdWalker) redirectExpansions(redirs []*syntax.Redirect, state cwdState) bool {
	filesystemUncertain := false
	for _, redirect := range redirs {
		if redirect.Word != nil {
			filesystemUncertain = filesystemUncertain || w.expansions(redirect.Word, state)
		}
	}
	return filesystemUncertain
}

func simpleForCall(src string, stmt *syntax.Stmt, call *syntax.CallExpr) Simple {
	s := Simple{}
	for _, word := range call.Args {
		raw := src[word.Pos().Offset():word.End().Offset()]
		if literal, ok := literalText(raw); ok {
			s.Argv = append(s.Argv, literal)
		} else {
			s.Argv = append(s.Argv, raw)
			s.Unresolved = true
		}
	}
	for _, redirect := range stmt.Redirs {
		if redirect.Word == nil {
			continue
		}
		raw := src[redirect.Word.Pos().Offset():redirect.Word.End().Offset()]
		if _, ok := literalText(raw); !ok {
			s.Unresolved = true
		}
	}
	return s
}

func (w *cwdWalker) call(stmt *syntax.Stmt, call *syntax.CallExpr, state cwdState) cwdOutcome {
	if len(call.Args) == 0 {
		return successOutcome(applyCallAssignments(state, call))
	}
	simple := simpleForCall(w.src, stmt, call)
	argv, bypassFunction, noExecute, err := directCommandArgv(simple.Argv)
	if err != nil {
		return bothOutcome(unknownCwd(state))
	}
	if noExecute {
		return bothOutcome(state)
	}
	if len(argv) == 0 {
		return bothOutcome(state)
	}
	local := applyCallAssignments(state, call)
	w.recursive[stmt] = local

	if functions, ok := w.functions[argv[0]]; ok && !bypassFunction {
		out := w.functionCall(stmt, simple, argv[0], functions, local)
		if callAssignsCDPath(call) {
			out = unknownCDPath(out)
		}
		return out
	}
	if argv[0] == "eval" {
		return w.eval(stmt, simple, argv, local)
	}
	if simple.Unresolved && bypassFunction {
		return bothOutcome(unknownCwd(state))
	}
	if simple.Unresolved && len(w.functions) > 0 && !bypassFunction {
		return bothOutcome(unknownCwd(state))
	}
	switch argv[0] {
	case "cd":
		return restoreCDPath(cdOutcome(local, simple, argv), state)
	case "pushd", "popd":
		return bothOutcome(unknownCwd(state))
	case "return", "break", "continue":
		return bothOutcome(unknownCwd(state))
	}

	_, shellCommand, _ := shellDashC(argv)
	if shellCommand || argv[0] == "watch" {
		state.fsUncertain = true
	}
	if len(simple.Redirects) > 0 || len(writeTargets(simple)) > 0 {
		state.fsUncertain = true
	}
	truth := literalCondition([]*syntax.Stmt{stmt}, w.shadowed)
	if stmt.Negated {
		truth = truth.negated() // stmt applies negation after the command outcome.
	}
	switch truth {
	case conditionTrue:
		return successOutcome(state)
	case conditionFalse:
		return cwdOutcome{failure: state, canFailure: true}
	default:
		return bothOutcome(state)
	}
}

func restoreCDPath(out cwdOutcome, persistent cwdState) cwdOutcome {
	restore := func(state cwdState) cwdState {
		state.cdpath = persistent.cdpath
		state.cdpathSet = persistent.cdpathSet
		state.cdpathUnknown = persistent.cdpathUnknown
		return state
	}
	if out.canSuccess {
		out.success = restore(out.success)
	}
	if out.canFailure {
		out.failure = restore(out.failure)
	}
	return out
}

func directCommandArgv(argv []string) (rest []string, bypassFunction, noExecute bool, err error) {
	for len(argv) > 0 {
		switch argv[0] {
		case "command":
			var none bool
			argv, none, err = consumeCommand(argv[1:])
			if err != nil || none {
				return argv, true, none, err
			}
		case "builtin":
			argv, err = consumeBuiltin(argv[1:])
			if err != nil || len(argv) == 0 {
				return argv, true, len(argv) == 0, err
			}
		default:
			return argv, bypassFunction, false, nil
		}
		bypassFunction = true
	}
	return nil, bypassFunction, true, nil
}

func (w *cwdWalker) eval(stmt *syntax.Stmt, simple Simple, argv []string, state cwdState) cwdOutcome {
	if state.unknown || simple.Unresolved {
		w.replacements[stmt] = []Simple{{Argv: simple.Argv, Cwd: state.cwd, Unresolved: true, cwdUnknown: true, pipelines: w.pipelines[stmt]}}
		w.shadowed["true"] = true
		w.shadowed["false"] = true
		return bothOutcome(unknownCwd(state))
	}
	if len(argv) == 1 {
		w.replacements[stmt] = nil
		return successOutcome(state)
	}
	result, err := normalizeWithState(strings.Join(argv[1:], " "), state, w.ctx, w.functions, w.active, w.pipelines[stmt])
	if err != nil {
		w.replacements[stmt] = []Simple{{Argv: simple.Argv, Cwd: state.cwd, Unresolved: true, cwdUnknown: true, pipelines: w.pipelines[stmt]}}
		return bothOutcome(unknownCwd(state))
	}
	w.replacements[stmt] = result.simples
	w.publishFunctions(result.functions, w.uncertainDef)
	return result.outcome
}

func (w *cwdWalker) functionCall(stmt *syntax.Stmt, simple Simple, name string, functions shellFunctionSet, state cwdState) cwdOutcome {
	if w.active[name] {
		w.replacements[stmt] = []Simple{{Argv: simple.Argv, Cwd: state.cwd, Unresolved: true, cwdUnknown: true, pipelines: w.pipelines[stmt]}}
		return bothOutcome(unknownCwd(state))
	}
	active := make(map[string]bool, len(w.active)+1)
	for activeName := range w.active {
		active[activeName] = true
	}
	active[name] = true
	baseFunctions := cloneFunctions(w.functions)
	var replacements []Simple
	var outcomes []cwdOutcome
	var functionAlternatives []map[string]shellFunctionSet
	unresolved := false
	for _, function := range functions.bodies {
		result, err := normalizeWithState(function.source, state, w.ctx, baseFunctions, active, w.pipelines[stmt])
		if err != nil {
			unresolved = true
			outcomes = append(outcomes, bothOutcome(unknownCwd(state)))
			functionAlternatives = append(functionAlternatives, baseFunctions)
			continue
		}
		replacements = append(replacements, result.simples...)
		outcomes = append(outcomes, result.outcome)
		functionAlternatives = append(functionAlternatives, result.functions)
	}
	ambiguous := functions.mayBeUndefined || len(functions.bodies) != 1
	if functions.mayBeUndefined || len(functions.bodies) == 0 {
		outcomes = append(outcomes, bothOutcome(unknownCwd(state)))
		functionAlternatives = append(functionAlternatives, baseFunctions)
	}
	if ambiguous || unresolved {
		replacements = append(replacements, Simple{Argv: simple.Argv, Cwd: state.cwd, Unresolved: true, cwdUnknown: state.unknown, pipelines: w.pipelines[stmt]})
	}
	w.replacements[stmt] = replacements
	w.publishFunctions(mergeFunctionAlternatives(functionAlternatives...), w.uncertainDef)
	return mergeOutcomes(outcomes...)
}

func applyCallAssignments(state cwdState, call *syntax.CallExpr) cwdState {
	for _, assignment := range call.Assigns {
		if assignment.Name == nil || assignment.Name.Value != "CDPATH" {
			continue
		}
		if assignment.Append || assignment.Index != nil || assignment.Array != nil {
			state.cdpathUnknown = true
			state.cdpathSet = false
			continue
		}
		value, ok := staticWord(assignment.Value, false)
		if !ok {
			state.cdpathUnknown = true
			state.cdpathSet = false
			continue
		}
		state.cdpath = value
		state.cdpathSet = true
		state.cdpathUnknown = false
	}
	return state
}

func callAssignsCDPath(call *syntax.CallExpr) bool {
	for _, assignment := range call.Assigns {
		if assignment.Name != nil && assignment.Name.Value == "CDPATH" {
			return true
		}
	}
	return false
}

func unknownCDPath(out cwdOutcome) cwdOutcome {
	mark := func(state cwdState) cwdState {
		state.cdpath = ""
		state.cdpathSet = false
		state.cdpathUnknown = true
		return state
	}
	if out.canSuccess {
		out.success = mark(out.success)
	}
	if out.canFailure {
		out.failure = mark(out.failure)
	}
	return out
}

type cdDirectoryStatus uint8

const (
	cdDirectoryUnknown cdDirectoryStatus = iota
	cdDirectoryMissing
	cdDirectoryAccessible
)

func cdOutcome(state cwdState, simple Simple, argv []string) cwdOutcome {
	if state.unknown {
		return bothOutcome(unknownCwd(state))
	}
	target, physical, ok := parseCdArgs(argv[1:])
	if !ok || simple.Unresolved || state.cwd == "" {
		return bothOutcome(unknownCwd(state))
	}
	resolved, status := resolveCdTarget(state, target, physical)
	success := state
	success.cwd = resolved
	success.unknown = resolved == ""
	if state.fsUncertain && cdUsesSearchPath(state, target) {
		success = unknownCwd(state)
		status = cdDirectoryUnknown
	}
	if physical && state.fsUncertain {
		success = unknownCwd(state)
		status = cdDirectoryUnknown
	}
	if physical && status == cdDirectoryAccessible {
		physicalPath, err := filepath.EvalSymlinks(resolved)
		if err != nil {
			status = cdDirectoryUnknown
			success = unknownCwd(state)
		} else {
			success.cwd = filepath.Clean(physicalPath)
		}
	}
	switch status {
	case cdDirectoryAccessible:
		if state.fsUncertain {
			return cwdOutcome{success: success, failure: state, canSuccess: true, canFailure: true}
		}
		return successOutcome(success)
	case cdDirectoryMissing:
		if state.fsUncertain {
			return cwdOutcome{success: success, failure: state, canSuccess: true, canFailure: true}
		}
		return cwdOutcome{failure: state, canFailure: true}
	default:
		return cwdOutcome{success: success, failure: state, canSuccess: true, canFailure: true}
	}
}

func cdUsesSearchPath(state cwdState, target string) bool {
	if filepath.IsAbs(target) || target == "." || target == ".." || strings.HasPrefix(target, "."+string(filepath.Separator)) || strings.HasPrefix(target, ".."+string(filepath.Separator)) {
		return false
	}
	return state.cdpathUnknown || state.cdpathSet && state.cdpath != ""
}

func parseCdArgs(args []string) (target string, physical bool, ok bool) {
	options := true
	mode := byte(0)
	seenE := false
	var operands []string
	for _, arg := range args {
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "-") {
			if arg == "-" {
				return "", false, false
			}
			for _, option := range strings.TrimPrefix(arg, "-") {
				switch option {
				case 'L', 'P':
					if mode != 0 && mode != byte(option) {
						return "", false, false
					}
					mode = byte(option)
				case 'e':
					seenE = true
				default:
					return "", false, false
				}
			}
			continue
		}
		options = false
		operands = append(operands, arg)
	}
	if len(operands) != 1 || operands[0] == "" || seenE && mode != 'P' {
		return "", false, false
	}
	return operands[0], mode == 'P', true
}

func resolveCdTarget(state cwdState, target string, physical bool) (string, cdDirectoryStatus) {
	if filepath.IsAbs(target) || strings.HasPrefix(target, "."+string(filepath.Separator)) || target == "." || target == ".." || strings.HasPrefix(target, ".."+string(filepath.Separator)) {
		candidate := cdCandidate(state.cwd, target, physical)
		return candidate, cdDirectoryState(candidate)
	}
	if state.cdpathUnknown {
		return "", cdDirectoryUnknown
	}
	if state.cdpathSet {
		if state.cdpath == "" {
			candidate := cdCandidate(state.cwd, target, physical)
			return candidate, cdDirectoryState(candidate)
		}
		unknown := false
		for _, entry := range filepath.SplitList(state.cdpath) {
			if entry == "" {
				entry = state.cwd
			} else if !filepath.IsAbs(entry) {
				entry = filepath.Join(state.cwd, entry)
			}
			candidate := cdCandidate(entry, target, physical)
			switch status := cdDirectoryState(candidate); status {
			case cdDirectoryAccessible:
				if unknown {
					return "", cdDirectoryUnknown
				}
				return candidate, status
			case cdDirectoryUnknown:
				unknown = true
			}
		}
		if unknown {
			return "", cdDirectoryUnknown
		}
		return cdCandidate(state.cwd, target, physical), cdDirectoryMissing
	}
	candidate := cdCandidate(state.cwd, target, physical)
	return candidate, cdDirectoryState(candidate)
}

func cdCandidate(base, target string, physical bool) string {
	candidate := target
	if !filepath.IsAbs(candidate) {
		if physical {
			candidate = strings.TrimSuffix(base, string(filepath.Separator)) + string(filepath.Separator) + candidate
		} else {
			candidate = filepath.Join(base, candidate)
		}
	}
	if physical {
		return candidate
	}
	return filepath.Clean(candidate)
}

func cdDirectoryState(candidate string) cdDirectoryStatus {
	info, err := os.Stat(candidate)
	if err != nil {
		if os.IsNotExist(err) {
			return cdDirectoryMissing
		}
		return cdDirectoryUnknown
	}
	if !info.IsDir() {
		return cdDirectoryMissing
	}
	if info.Mode().Perm()&0o111 == 0 {
		return cdDirectoryUnknown
	}
	searchProbe := strings.TrimSuffix(candidate, string(filepath.Separator)) + string(filepath.Separator) + "."
	if _, err := os.Stat(searchProbe); err != nil {
		return cdDirectoryUnknown
	}
	return cdDirectoryAccessible
}

func mergeCwd(states ...cwdState) cwdState {
	if len(states) == 0 {
		return cwdState{unknown: true}
	}
	merged := states[0]
	for _, state := range states[1:] {
		merged.fsUncertain = merged.fsUncertain || state.fsUncertain
		if state.unknown || merged.unknown || state.cwd != merged.cwd {
			merged.cwd = ""
			merged.unknown = true
		}
		if state.cdpathUnknown || merged.cdpathUnknown || state.cdpathSet != merged.cdpathSet || state.cdpath != merged.cdpath {
			merged.cdpathUnknown = true
			merged.cdpathSet = false
		}
	}
	return merged
}

func unknownCwd(states ...cwdState) cwdState {
	state := mergeCwd(states...)
	state.cwd = ""
	state.unknown = true
	return state
}

func cwdMayChange(before, after cwdState) bool {
	return before.unknown != after.unknown || before.cwd != after.cwd
}

func forClauseMayRepeat(clause *syntax.ForClause) bool {
	return analyzeForClause(clause).mayRepeat
}

// Normalize returns every command that will actually execute, with no-op
// wrappers stripped and argument-executing runners unwrapped.
func Normalize(command, cwd string) ([]Simple, error) {
	return normalizeWithContext(command, cwd, &normalizeContext{})
}

func normalizeWithContext(command, cwd string, ctx *normalizeContext) ([]Simple, error) {
	state := cwdState{cwd: cwd}
	if cdpath, ok := os.LookupEnv("CDPATH"); ok {
		state.cdpath = cdpath
		state.cdpathSet = true
	}
	result, err := normalizeWithState(command, state, ctx, nil, nil, nil)
	return result.simples, err
}

type normalizeResult struct {
	simples   []Simple
	outcome   cwdOutcome
	functions map[string]shellFunctionSet
}

func normalizeWithState(command string, state cwdState, ctx *normalizeContext, functions map[string]shellFunctionSet, active map[string]bool, inherited []pipelinePosition) (normalizeResult, error) {
	f, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil {
		return normalizeResult{}, err
	}
	shadowed := shadowedStaticCommandNames(f)
	for name := range functions {
		if name == "true" || name == "false" {
			shadowed[name] = true
		}
	}
	pipelines := pipelinePositions(f, ctx, shadowed)
	for _, position := range inherited {
		markPipelineList(pipelines, f.Stmts, position, shadowed)
	}
	if functions == nil {
		functions = make(map[string]shellFunctionSet)
	} else {
		functions = cloneFunctions(functions)
	}
	if active == nil {
		active = make(map[string]bool)
	}
	walker := cwdWalker{
		src:          command,
		ctx:          ctx,
		states:       make(map[*syntax.Stmt]cwdState),
		replacements: make(map[*syntax.Stmt][]Simple),
		functions:    functions,
		active:       active,
		shadowed:     shadowed,
		pipelines:    pipelines,
		recursive:    make(map[*syntax.Stmt]cwdState),
	}
	outcome := walker.list(f.Stmts, state)
	base := extractSimples(command, f, pipelines, walker.states)
	var out []Simple
	for _, s := range base {
		if recursiveState, ok := walker.recursive[s.origin]; ok {
			s.shellState = recursiveState
		}
		if replacement, ok := walker.replacements[s.origin]; ok {
			out = append(out, replacementWithOuterMetadata(s, replacement)...)
			continue
		}
		expanded, err := stripAndUnwrap(s, ctx)
		if err != nil {
			// This statement's wrappers could not be understood. Keep it
			// unknowable so sibling statements are still evaluated.
			degraded := s
			degraded.Unresolved = true
			degraded.origin = nil
			degraded.shellState = cwdState{}
			out = append(out, degraded)
			continue
		}
		for index := range expanded {
			expanded[index].origin = nil
			expanded[index].shellState = cwdState{}
		}
		out = append(out, expanded...)
	}
	return normalizeResult{simples: out, outcome: outcome, functions: cloneFunctions(walker.functions)}, nil
}

func replacementWithOuterMetadata(outer Simple, replacement []Simple) []Simple {
	result := make([]Simple, 0, len(replacement)+1)
	if len(outer.Redirects) > 0 || len(outer.ReadRedirects) > 0 {
		result = append(result, Simple{
			Redirects:     outer.Redirects,
			ReadRedirects: outer.ReadRedirects,
			Cwd:           outer.Cwd,
			Unresolved:    outer.Unresolved,
			pipelines:     outer.pipelines,
			cwdUnknown:    outer.cwdUnknown,
		})
	}
	for _, inner := range replacement {
		inner.Unresolved = inner.Unresolved || outer.Unresolved
		inner.cwdUnknown = inner.cwdUnknown || outer.cwdUnknown
		inner.origin = nil
		inner.shellState = cwdState{}
		result = append(result, inner)
	}
	return result
}

func commandDerivedFrom(outer Simple, argv []string) Simple {
	return Simple{
		Argv:       argv,
		Cwd:        outer.Cwd,
		Unresolved: outer.Unresolved,
		pipelines:  outer.pipelines,
		cwdUnknown: outer.cwdUnknown,
		shellState: outer.shellState,
	}
}

func stripAndUnwrap(s Simple, ctx *normalizeContext) ([]Simple, error) {
	if len(s.Argv) == 0 {
		if len(s.Redirects) == 0 && len(s.ReadRedirects) == 0 {
			return nil, nil
		}
		return []Simple{s}, nil
	}
	argv := s.Argv
	chrooted := false
loop:
	for len(argv) > 0 {
		var rest []string
		var err error
		switch head(argv) {
		case "env":
			rest, err = consumeEnv(argv[1:])
		case "timeout":
			rest, err = consumeTimeout(argv[1:])
		case "nice":
			rest, err = consumeNice(argv[1:])
		case "setsid":
			rest, err = consumeSetsid(argv[1:])
		case "stdbuf":
			rest, err = consumeStdbuf(argv[1:])
		case "ionice":
			rest, err = consumeIonice(argv[1:])
		case "watch":
			rest, err = consumeWatch(argv[1:])
			if err == nil {
				return normalizeWatch(s, rest, chrooted, ctx)
			}
		case "chroot":
			rest, err = consumeChroot(argv[1:])
			if err == nil {
				chrooted = true
			}
		case "nohup":
			rest, err = consumeNoFlags("nohup", argv[1:])
		case "xargs":
			rest, err = consumeXargs(argv[1:])
		case "exec":
			rest, err = consumeExec(argv[1:])
		case "command":
			var none bool
			rest, none, err = consumeCommand(argv[1:])
			if err == nil && none {
				argv = nil // -v/-V only locate a command; redirects still take effect
				break loop
			}
		case "builtin":
			rest, err = consumeBuiltin(argv[1:])
		case "time", "eval":
			rest = argv[1:]
		default:
			break loop
		}
		if err != nil {
			return nil, err
		}
		argv = rest
	}
	if len(argv) == 0 {
		if len(s.Redirects) == 0 && len(s.ReadRedirects) == 0 && !chrooted {
			return nil, nil
		}
		s.Argv = argv
		s.Unresolved = s.Unresolved || chrooted
		return []Simple{s}, nil
	}
	command := commandDerivedFrom(s, argv)
	command.Redirects = s.Redirects
	command.ReadRedirects = s.ReadRedirects
	result := []Simple{command}
	inner, err := runnerInner(argv)
	if err != nil {
		return nil, err
	}
	if inner != nil {
		result = append(result, commandDerivedFrom(s, inner))
	}
	source, dashC, err := shellDashC(argv)
	if err != nil {
		return nil, err
	}
	if dashC {
		inner, err := normalizeShellDashC(source, s.shellState, s.pipelines, ctx)
		if err != nil {
			return nil, err
		}
		result = append(result, inner...)
	}
	remoteSources, err := sshCommandSources(argv)
	if err != nil {
		return nil, err
	}
	for _, remoteSource := range remoteSources {
		inner, err := normalizeShellDashC(remoteSource, s.shellState, s.pipelines, ctx)
		if err != nil {
			return nil, err
		}
		result = append(result, inner...)
	}
	if chrooted {
		for i := range result {
			result[i].Unresolved = true
		}
	}
	return result, nil
}

// normalizeShellDashC re-tokenizes the literal text passed to a shell's -c flag.
func normalizeShellDashC(word string, state cwdState, inherited []pipelinePosition, ctx *normalizeContext) ([]Simple, error) {
	result, err := normalizeWithState(word, state, ctx, nil, nil, inherited)
	return result.simples, err
}

func normalizeWatch(outer Simple, argv []string, unresolved bool, ctx *normalizeContext) ([]Simple, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("watch: missing command argument; failing closed")
	}
	result, err := normalizeWithState(strings.Join(argv, " "), outer.shellState, ctx, nil, nil, outer.pipelines)
	if err != nil {
		return nil, err
	}
	inner := result.simples
	unresolved = unresolved || outer.Unresolved
	if unresolved {
		for i := range inner {
			inner[i].Unresolved = true
		}
	}
	if len(outer.Redirects) > 0 || len(outer.ReadRedirects) > 0 {
		metadata := Simple{
			Redirects:     outer.Redirects,
			ReadRedirects: outer.ReadRedirects,
			Cwd:           outer.Cwd,
			Unresolved:    unresolved,
			pipelines:     outer.pipelines,
			cwdUnknown:    outer.cwdUnknown,
		}
		return append([]Simple{metadata}, inner...), nil
	}
	if unresolved && len(inner) == 0 {
		return []Simple{{Cwd: outer.Cwd, Unresolved: true, pipelines: outer.pipelines, cwdUnknown: outer.cwdUnknown}}, nil
	}
	return inner, nil
}

func literalText(tok string) (string, bool) {
	// Parse in argument position so assignment-shaped words such as FOO=1
	// remain complete words rather than becoming assignment AST nodes.
	f, err := syntax.NewParser().Parse(strings.NewReader(": "+tok), "")
	if err != nil {
		return "", false
	}
	if len(f.Stmts) != 1 {
		return "", false
	}
	call, ok := f.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 2 {
		return "", false
	}
	word := call.Args[1]
	var b strings.Builder
	for _, p := range word.Parts {
		switch part := p.(type) {
		case *syntax.Lit:
			b.WriteString(part.Value)
		case *syntax.SglQuoted:
			b.WriteString(part.Value)
		case *syntax.DblQuoted:
			for _, dp := range part.Parts {
				lit, ok := dp.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

func unknownOpt(wrapper, tok string) error {
	return fmt.Errorf("%s: unrecognized option %q; failing closed", wrapper, tok)
}

func needsValue(wrapper, tok string) error {
	return fmt.Errorf("%s: option %q requires a value; failing closed", wrapper, tok)
}

// consumeKnownFlags skips options belonging to a wrapper. Unknown options fail
// closed because guessing their arity could make data look like a command.
func consumeKnownFlags(name string, argv []string, known, valued, optional map[string]bool) ([]string, error) {
	for i := 0; i < len(argv); {
		a := argv[i]
		if a == "--" {
			return argv[i+1:], nil
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			return argv[i:], nil
		}
		if strings.HasPrefix(a, "--") {
			base := a
			attached := false
			if eq := strings.IndexByte(a, '='); eq >= 0 {
				base, attached = a[:eq], true
			}
			switch {
			case known[base] && !attached:
				i++
			case valued[base]:
				if attached {
					i++
				} else {
					if i+1 >= len(argv) {
						return nil, needsValue(name, a)
					}
					i += 2
				}
			case optional[base]:
				i++
			default:
				return nil, unknownOpt(name, a)
			}
			continue
		}

		consumed := false
		for j := 1; j < len(a); j++ {
			flag := "-" + a[j:j+1]
			switch {
			case known[flag]:
				continue
			case valued[flag]:
				if j+1 < len(a) {
					i++
				} else {
					if i+1 >= len(argv) {
						return nil, needsValue(name, flag)
					}
					i += 2
				}
				consumed = true
			case optional[flag]:
				i++
				consumed = true
			default:
				return nil, unknownOpt(name, a)
			}
			if consumed {
				break
			}
		}
		if !consumed {
			i++
		}
	}
	return nil, nil
}

func consumeSetsid(argv []string) ([]string, error) {
	known := map[string]bool{
		"-f": true, "--fork": true,
		"-w": true, "--wait": true,
		"-c": true, "--ctty": true,
	}
	return consumeKnownFlags("setsid", argv, known, nil, nil)
}

func consumeStdbuf(argv []string) ([]string, error) {
	valued := map[string]bool{
		"-i": true, "--input": true,
		"-o": true, "--output": true,
		"-e": true, "--error": true,
	}
	return consumeKnownFlags("stdbuf", argv, nil, valued, nil)
}

func consumeIonice(argv []string) ([]string, error) {
	known := map[string]bool{"-t": true, "--ignore": true}
	valued := map[string]bool{
		"-c": true, "--class": true,
		"-n": true, "--classdata": true,
	}
	return consumeKnownFlags("ionice", argv, known, valued, nil)
}

func consumeWatch(argv []string) ([]string, error) {
	known := map[string]bool{
		"-d": true,
		"-t": true, "--no-title": true,
		"-b": true,
		"-e": true,
	}
	valued := map[string]bool{"-n": true, "--interval": true}
	optional := map[string]bool{"--differences": true}
	return consumeKnownFlags("watch", argv, known, valued, optional)
}

func consumeChroot(argv []string) ([]string, error) {
	valued := map[string]bool{"--userspec": true, "--groups": true}
	rest, err := consumeKnownFlags("chroot", argv, nil, valued, nil)
	if err != nil {
		return nil, err
	}
	if len(rest) == 0 {
		return nil, fmt.Errorf("chroot: missing new-root argument; failing closed")
	}
	if len(rest) == 1 {
		return nil, fmt.Errorf("chroot: missing command argument; failing closed")
	}
	return rest[1:], nil
}

func consumeEnv(argv []string) ([]string, error) {
	i := 0
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "--":
			return argv[i+1:], nil
		case a == "-i" || a == "-v" || a == "-0":
			i++
		case a == "-u":
			if i+1 >= len(argv) {
				return nil, needsValue("env", a)
			}
			i += 2
		case strings.HasPrefix(a, "-"):
			return nil, unknownOpt("env", a)
		case strings.Contains(a, "="):
			i++
		default:
			return argv[i:], nil
		}
	}
	return nil, nil
}

func consumeTimeout(argv []string) ([]string, error) {
	i := 0
	gotDuration := false
	for i < len(argv) {
		a := argv[i]
		if !strings.HasPrefix(a, "-") {
			if !gotDuration {
				gotDuration = true
				i++
				continue
			}
			return argv[i:], nil
		}
		switch {
		case a == "-k" || a == "-s":
			if i+1 >= len(argv) {
				return nil, needsValue("timeout", a)
			}
			i += 2
		case a == "-v" || a == "--preserve-status" || a == "--foreground":
			i++
		default:
			return nil, unknownOpt("timeout", a)
		}
	}
	return nil, nil
}

func consumeNice(argv []string) ([]string, error) {
	i := 0
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "-n":
			if i+1 >= len(argv) {
				return nil, needsValue("nice", a)
			}
			i += 2
		case len(a) > 1 && strings.HasPrefix(a, "-") && allDigits(a[1:]):
			i++
		case strings.HasPrefix(a, "-"):
			return nil, unknownOpt("nice", a)
		default:
			return argv[i:], nil
		}
	}
	return nil, nil
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func consumeNoFlags(wrapper string, argv []string) ([]string, error) {
	if len(argv) > 0 && strings.HasPrefix(argv[0], "-") {
		return nil, unknownOpt(wrapper, argv[0])
	}
	return argv, nil
}

func consumeXargs(argv []string) ([]string, error) {
	i := 0
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "-0" || a == "-r" || a == "-t" || a == "-p":
			i++
		case a == "-n" || a == "-I" || a == "-P" || a == "-E" || a == "-d":
			if i+1 >= len(argv) {
				return nil, needsValue("xargs", a)
			}
			i += 2
		case strings.HasPrefix(a, "-"):
			return nil, unknownOpt("xargs", a)
		default:
			return argv[i:], nil
		}
	}
	return nil, nil
}

func consumeExec(argv []string) ([]string, error) {
	i := 0
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "-a":
			if i+1 >= len(argv) {
				return nil, needsValue("exec", a)
			}
			i += 2
		case strings.HasPrefix(a, "-"):
			return nil, unknownOpt("exec", a)
		default:
			return argv[i:], nil
		}
	}
	return nil, nil
}

func consumeCommand(argv []string) (rest []string, none bool, err error) {
	i := 0
	locate := false
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "--":
			i++
			if locate || i == len(argv) {
				return nil, true, nil
			}
			return argv[i:], false, nil
		case strings.HasPrefix(a, "-"):
			if a == "-" {
				return nil, false, unknownOpt("command", a)
			}
			for _, option := range strings.TrimPrefix(a, "-") {
				switch option {
				case 'p':
				case 'v', 'V':
					locate = true
				default:
					return nil, false, unknownOpt("command", a)
				}
			}
			i++
		default:
			if locate {
				return nil, true, nil
			}
			return argv[i:], false, nil
		}
	}
	return nil, true, nil
}

func consumeBuiltin(argv []string) ([]string, error) {
	if len(argv) == 0 {
		return nil, nil
	}
	if argv[0] == "--" {
		return argv[1:], nil
	}
	if strings.HasPrefix(argv[0], "-") {
		return nil, unknownOpt("builtin", argv[0])
	}
	return argv, nil
}

type shellOptionSpec struct {
	shortFlags      string
	shortValues     string
	shortStops      string
	longFlags       map[string]bool
	longValues      map[string]bool
	longCommand     map[string]bool
	longStops       map[string]bool
	longBeforeShort bool
}

var (
	shShellOptions = shellOptionSpec{
		shortFlags:  "abCefhiklmnprstuvxX",
		shortValues: "o",
	}
	dashShellOptions = shellOptionSpec{
		shortFlags:  "aCefIimnqsuvxVEb",
		shortValues: "o",
	}
	zshShellOptions = shellOptionSpec{
		shortFlags:  "dfilnrsuvx",
		shortValues: "o",
		shortStops:  "b",
	}
	kshShellOptions = shellOptionSpec{
		shortFlags:  "abCefhiklmnprstuvxX",
		shortValues: "o",
	}
	ashShellOptions = shellOptionSpec{
		shortFlags:  "aCefhIiklmnprstuvx",
		shortValues: "o",
	}
	bashShellOptions = shellOptionSpec{
		shortFlags:  "abCefhiklmnprstuvxBEHPT",
		shortValues: "oO",
		longFlags: map[string]bool{
			"--debug": true, "--debugger": true, "--login": true,
			"--noediting": true,
			"--noprofile": true, "--norc": true, "--posix": true,
			"--pretty-print": true, "--restricted": true, "--verbose": true,
		},
		longValues: map[string]bool{"--init-file": true, "--rcfile": true},
		longStops: map[string]bool{
			"--dump-po-strings": true, "--dump-strings": true,
			"--help": true, "--version": true,
		},
		longBeforeShort: true,
	}
	fishShellOptions = shellOptionSpec{
		shortFlags:  "iINlnPv",
		shortValues: "CdDfp",
		longFlags: map[string]bool{
			"--interactive": true, "--login": true, "--no-config": true,
			"--no-execute": true, "--private": true,
		},
		longValues: map[string]bool{
			"--debug": true, "--debug-output": true, "--features": true,
			"--init-command": true, "--profile": true,
		},
		longCommand: map[string]bool{"--command": true},
	}
	cShellOptions = shellOptionSpec{shortFlags: "bdefFilmnqstvVxX"}
)

func shellOptions(shell string) (shellOptionSpec, bool) {
	switch shell {
	case "bash":
		return bashShellOptions, true
	case "sh":
		return shShellOptions, true
	case "dash":
		return dashShellOptions, true
	case "zsh":
		return zshShellOptions, true
	case "ksh", "mksh":
		return kshShellOptions, true
	case "ash":
		return ashShellOptions, true
	case "fish":
		return fishShellOptions, true
	case "csh", "tcsh":
		return cShellOptions, true
	default:
		return shellOptionSpec{}, false
	}
}

func shellDashC(argv []string) (string, bool, error) {
	shell := head(argv)
	spec, ok := shellOptions(shell)
	if !ok {
		return "", false, nil
	}
	shortSeen := false
	for i := 1; i < len(argv); {
		option := argv[i]
		if option == "" || option == "--" || option == "-" || option == "+" {
			return "", false, nil
		}
		if strings.HasPrefix(option, "--") {
			if spec.longBeforeShort && shortSeen {
				return "", false, unknownOpt(shell, option)
			}
			base := option
			value := ""
			attached := false
			if eq := strings.IndexByte(option, '='); eq >= 0 {
				base, value, attached = option[:eq], option[eq+1:], true
			}
			switch {
			case spec.longCommand[base]:
				if attached {
					return value, true, nil
				}
				if i+1 >= len(argv) {
					return "", false, needsValue(shell, option)
				}
				return argv[i+1], true, nil
			case spec.longValues[base]:
				if attached {
					i++
				} else {
					if i+1 >= len(argv) {
						return "", false, needsValue(shell, option)
					}
					i += 2
				}
			case spec.longFlags[base] && !attached:
				i++
			case spec.longStops[base] && !attached:
				return "", false, nil
			default:
				return "", false, unknownOpt(shell, option)
			}
			continue
		}
		if option[0] != '-' && option[0] != '+' {
			return "", false, nil
		}
		shortSeen = true

		command := false
		consumed := false
		for j := 1; j < len(option); j++ {
			flag := option[j]
			switch {
			case flag == 'c' && option[0] == '-':
				command = true
			case strings.ContainsRune(spec.shortStops, rune(flag)):
				return "", false, nil
			case strings.ContainsRune(spec.shortFlags, rune(flag)):
				continue
			case strings.ContainsRune(spec.shortValues, rune(flag)):
				if j+1 < len(option) {
					i++
				} else {
					if i+1 >= len(argv) {
						return "", false, needsValue(shell, "-"+string(flag))
					}
					i += 2
				}
				consumed = true
			default:
				return "", false, unknownOpt(shell, option)
			}
			if consumed {
				break
			}
		}
		if command {
			source := i + 1
			if consumed {
				source = i
			}
			if source >= len(argv) {
				return "", false, needsValue(shell, "-c")
			}
			return argv[source], true, nil
		}
		if !consumed {
			i++
		}
	}
	return "", false, nil
}

func runnerInner(argv []string) ([]string, error) {
	switch head(argv) {
	case "npx", "uvx", "bunx", "make", "just":
		if len(argv) > 1 {
			return argv[1:], nil
		}
	case "docker", "podman", "nerdctl":
		subcommand, err := dockerSubcommandIndex(argv)
		if err != nil {
			return nil, err
		}
		if subcommand >= 0 && (argv[subcommand] == "run" || argv[subcommand] == "exec") {
			spec := dockerRunOptionSpec
			if argv[subcommand] == "exec" {
				spec = dockerExecOptionSpec
			}
			values := make(map[string]string)
			i, err := parseDockerOptions(head(argv)+" "+argv[subcommand], argv, subcommand+1, spec, values)
			if err != nil {
				return nil, err
			}
			entrypoint, configured := values["--entrypoint"]
			if configured && entrypoint == "" {
				return nil, fmt.Errorf("%s run: empty --entrypoint; failing closed", head(argv))
			}
			if i >= len(argv) {
				return nil, fmt.Errorf("%s %s: missing image or container; failing closed", head(argv), argv[subcommand])
			}
			inner := argv[i+1:] // skip the image/container token
			if configured {
				return append([]string{entrypoint}, inner...), nil
			}
			if len(inner) > 0 {
				return inner, nil
			}
		}
	case "devbox", "mise", "nix":
		if len(argv) > 2 {
			return argv[2:], nil
		}
	case "busybox":
		if len(argv) == 1 {
			return nil, nil
		}
		if strings.HasPrefix(argv[1], "-") {
			return nil, fmt.Errorf("busybox: cannot determine applet from %q; failing closed", argv[1])
		}
		return argv[1:], nil
	}
	return nil, nil
}
