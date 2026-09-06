package engine

import (
	"fmt"
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
	pipelines := pipelinePositions(f, ctx)
	return extractSimples(src, f, pipelines, nil), nil
}

func extractSimples(src string, f *syntax.File, pipelines map[*syntax.Stmt][]pipelinePosition, states map[*syntax.Stmt]cwdState) []Simple {
	var out []Simple
	syntax.Walk(f, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
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
		if state, ok := states[stmt]; ok {
			s.Cwd = state.cwd
			s.Unresolved = state.unknown
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

func pipelinePositions(f *syntax.File, ctx *normalizeContext) map[*syntax.Stmt][]pipelinePosition {
	pipeStatements := make(map[*syntax.Stmt]bool)
	childPipes := make(map[*syntax.Stmt]bool)
	shadowedConstants := make(map[string]bool)
	syntax.Walk(f, func(node syntax.Node) bool {
		if declaration, ok := node.(*syntax.FuncDecl); ok {
			name := declaration.Name.Value
			if name == "true" || name == "false" {
				shadowedConstants[name] = true
			}
		}
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
		stmt.Negated || stmt.Background || stmt.Coprocess {
		return conditionUnknown
	}
	name := call.Args[0].Lit()
	switch name {
	case ":":
		return conditionTrue
	case "true":
		if !shadowedConstants[name] {
			return conditionTrue
		}
	case "false":
		if !shadowedConstants[name] {
			return conditionFalse
		}
	}
	return conditionUnknown
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
	testing := true
	for index, item := range items {
		if testing && !matches[index] {
			continue
		}
		itemFlow := markPipelineList(positions, item.Stmts, position, shadowedConstants)
		flow.allConsume = itemFlow.allConsume
		flow.forwards = flow.forwards || itemFlow.forwards
		if flow.allConsume {
			return flow
		}
		switch item.Op {
		case syntax.Break:
			return flow
		case syntax.Fallthrough:
			testing = false
		default: // ;;& and mksh's ;| resume pattern testing
			testing = true
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
	words, ok := clause.Loop.(*syntax.WordIter)
	if !ok || !words.InPos.IsValid() {
		return iterationPossible
	}
	if len(words.Items) == 0 {
		return iterationNone
	}
	for _, word := range words.Items {
		if wordGuaranteesField(word) {
			return iterationGuaranteed
		}
	}
	return iterationPossible
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
	cwd     string
	unknown bool
}

type cwdWalker struct {
	src    string
	states map[*syntax.Stmt]cwdState
}

func (w *cwdWalker) list(stmts []*syntax.Stmt, state cwdState) cwdState {
	for _, stmt := range stmts {
		state = w.stmt(stmt, state)
	}
	return state
}

func (w *cwdWalker) stmt(stmt *syntax.Stmt, state cwdState) cwdState {
	w.states[stmt] = state
	w.redirectExpansions(stmt.Redirs, state)

	isolated := stmt.Background || stmt.Coprocess
	exit := w.command(stmt, state)
	if isolated {
		return state
	}
	return exit
}

func (w *cwdWalker) command(stmt *syntax.Stmt, state cwdState) cwdState {
	switch command := stmt.Cmd.(type) {
	case nil:
		return state
	case *syntax.CallExpr:
		w.expansions(command, state)
		return applyCd(state, simpleForCall(w.src, stmt, command))
	case *syntax.BinaryCmd:
		switch command.Op {
		case syntax.Pipe, syntax.PipeAll:
			w.stmt(command.X, state)
			w.stmt(command.Y, state)
			return state
		case syntax.AndStmt:
			left := w.stmt(command.X, state)
			right := w.stmt(command.Y, w.cwdOnSuccess(command.X, state))
			return mergeCwd(left, right)
		case syntax.OrStmt:
			left := w.stmt(command.X, state)
			right := w.stmt(command.Y, w.cwdOnFailure(command.X, state))
			return mergeCwd(left, right)
		}
	case *syntax.Block:
		return w.list(command.Stmts, state)
	case *syntax.Subshell:
		w.list(command.Stmts, state)
		return state
	case *syntax.IfClause:
		return w.ifClause(command, state)
	case *syntax.WhileClause:
		condition := w.list(command.Cond, state)
		body := w.list(command.Do, condition)
		return mergeCwd(condition, body)
	case *syntax.ForClause:
		w.expansions(command.Loop, state)
		body := w.list(command.Do, state)
		return mergeCwd(state, body)
	case *syntax.CaseClause:
		w.expansions(command.Word, state)
		exits := []cwdState{state}
		for _, item := range command.Items {
			for _, pattern := range item.Patterns {
				w.expansions(pattern, state)
			}
			exits = append(exits, w.list(item.Stmts, state))
		}
		return mergeCwd(exits...)
	case *syntax.TimeClause:
		return w.stmt(command.Stmt, state)
	case *syntax.FuncDecl:
		w.stmt(command.Body, cwdState{unknown: true})
		return state
	default:
		w.expansions(command, state)
		return state
	}
	return cwdState{unknown: true}
}

func (w *cwdWalker) ifClause(clause *syntax.IfClause, state cwdState) cwdState {
	condition := w.list(clause.Cond, state)
	thenExit := w.list(clause.Then, condition)
	elseExit := condition
	if clause.Else != nil {
		elseExit = w.ifClause(clause.Else, condition)
	}
	return mergeCwd(thenExit, elseExit)
}

func (w *cwdWalker) expansions(node syntax.Node, state cwdState) {
	if node == nil {
		return
	}
	syntax.Walk(node, func(node syntax.Node) bool {
		switch expansion := node.(type) {
		case *syntax.CmdSubst:
			w.list(expansion.Stmts, state)
			return false
		case *syntax.ProcSubst:
			w.list(expansion.Stmts, state)
			return false
		}
		return true
	})
}

func (w *cwdWalker) redirectExpansions(redirs []*syntax.Redirect, state cwdState) {
	for _, redirect := range redirs {
		if redirect.Word != nil {
			w.expansions(redirect.Word, state)
		}
	}
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

func applyCd(state cwdState, s Simple) cwdState {
	argv := s.Argv
	for len(argv) > 0 && (argv[0] == "command" || argv[0] == "builtin") {
		argv = argv[1:]
	}
	if len(argv) == 0 {
		return state
	}
	switch argv[0] {
	case "pushd", "popd":
		return cwdState{unknown: true}
	case "cd":
	default:
		return state
	}
	if s.Unresolved {
		return cwdState{unknown: true}
	}

	var operands []string
	options := true
	for _, arg := range argv[1:] {
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "-") {
			if arg == "-" || strings.Trim(strings.TrimPrefix(arg, "-"), "LPe@") != "" {
				return cwdState{unknown: true}
			}
			continue
		}
		options = false
		operands = append(operands, arg)
	}
	if len(operands) != 1 || operands[0] == "" {
		return cwdState{unknown: true}
	}
	if filepath.IsAbs(operands[0]) {
		return cwdState{cwd: filepath.Clean(operands[0])}
	}
	if state.unknown || state.cwd == "" {
		return cwdState{unknown: true}
	}
	return cwdState{cwd: filepath.Clean(filepath.Join(state.cwd, operands[0]))}
}

func (w *cwdWalker) cwdOnSuccess(stmt *syntax.Stmt, state cwdState) cwdState {
	if stmt.Background || stmt.Coprocess {
		return state
	}
	switch command := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		return applyCd(state, simpleForCall(w.src, stmt, command))
	case *syntax.BinaryCmd:
		switch command.Op {
		case syntax.AndStmt:
			return w.cwdOnSuccess(command.Y, w.cwdOnSuccess(command.X, state))
		case syntax.OrStmt:
			left := w.cwdOnSuccess(command.X, state)
			right := w.cwdOnSuccess(command.Y, w.cwdOnFailure(command.X, state))
			return mergeCwd(left, right)
		case syntax.Pipe, syntax.PipeAll:
			return state
		}
	case *syntax.Subshell, *syntax.FuncDecl:
		return state
	case *syntax.TimeClause:
		return w.cwdOnSuccess(command.Stmt, state)
	}
	return cwdState{unknown: true}
}

func (w *cwdWalker) cwdOnFailure(stmt *syntax.Stmt, state cwdState) cwdState {
	if stmt.Background || stmt.Coprocess {
		return state
	}
	switch command := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		return applyCd(state, simpleForCall(w.src, stmt, command))
	case *syntax.BinaryCmd:
		switch command.Op {
		case syntax.AndStmt:
			left := w.cwdOnFailure(command.X, state)
			right := w.cwdOnFailure(command.Y, w.cwdOnSuccess(command.X, state))
			return mergeCwd(left, right)
		case syntax.OrStmt:
			return w.cwdOnFailure(command.Y, w.cwdOnFailure(command.X, state))
		case syntax.Pipe, syntax.PipeAll:
			return state
		}
	case *syntax.Subshell, *syntax.FuncDecl:
		return state
	case *syntax.TimeClause:
		return w.cwdOnFailure(command.Stmt, state)
	}
	return cwdState{unknown: true}
}

func mergeCwd(states ...cwdState) cwdState {
	if len(states) == 0 {
		return cwdState{unknown: true}
	}
	first := states[0]
	if first.unknown {
		return cwdState{unknown: true}
	}
	for _, state := range states[1:] {
		if state.unknown || state.cwd != first.cwd {
			return cwdState{unknown: true}
		}
	}
	return first
}

// Normalize returns every command that will actually execute, with no-op
// wrappers stripped and argument-executing runners unwrapped.
func Normalize(command, cwd string) ([]Simple, error) {
	return normalizeWithContext(command, cwd, &normalizeContext{})
}

func normalizeWithContext(command, cwd string, ctx *normalizeContext) ([]Simple, error) {
	f, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, err
	}
	pipelines := pipelinePositions(f, ctx)
	walker := cwdWalker{src: command, states: make(map[*syntax.Stmt]cwdState)}
	walker.list(f.Stmts, cwdState{cwd: cwd})
	base := extractSimples(command, f, pipelines, walker.states)
	var out []Simple
	for _, s := range base {
		expanded, err := stripAndUnwrap(s, ctx)
		if err != nil {
			// This statement's wrappers could not be understood. Keep it
			// unknowable so sibling statements are still evaluated.
			degraded := s
			degraded.Unresolved = true
			out = append(out, degraded)
			continue
		}
		out = append(out, expanded...)
	}
	return out, nil
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
		case "time", "eval", "builtin":
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
	result := []Simple{{Argv: argv, Redirects: s.Redirects, ReadRedirects: s.ReadRedirects, Cwd: s.Cwd, Unresolved: s.Unresolved, pipelines: s.pipelines}}
	inner, err := runnerInner(argv)
	if err != nil {
		return nil, err
	}
	if inner != nil {
		result = append(result, Simple{Argv: inner, Cwd: s.Cwd, Unresolved: s.Unresolved, pipelines: s.pipelines})
	}
	source, dashC, err := shellDashC(argv)
	if err != nil {
		return nil, err
	}
	if dashC {
		inner, err := normalizeShellDashC(source, s.Cwd, ctx)
		if err != nil {
			return nil, err
		}
		for i := range inner {
			inner[i].pipelines = append(inner[i].pipelines, s.pipelines...)
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
func normalizeShellDashC(word, cwd string, ctx *normalizeContext) ([]Simple, error) {
	return normalizeWithContext(word, cwd, ctx)
}

func normalizeWatch(outer Simple, argv []string, unresolved bool, ctx *normalizeContext) ([]Simple, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("watch: missing command argument; failing closed")
	}
	inner, err := normalizeWithContext(strings.Join(argv, " "), outer.Cwd, ctx)
	if err != nil {
		return nil, err
	}
	unresolved = unresolved || outer.Unresolved
	if unresolved {
		for i := range inner {
			inner[i].Unresolved = true
		}
	}
	for i := range inner {
		inner[i].pipelines = append(inner[i].pipelines, outer.pipelines...)
	}
	if len(outer.Redirects) > 0 || len(outer.ReadRedirects) > 0 {
		metadata := Simple{
			Redirects:     outer.Redirects,
			ReadRedirects: outer.ReadRedirects,
			Cwd:           outer.Cwd,
			Unresolved:    unresolved,
			pipelines:     outer.pipelines,
		}
		return append([]Simple{metadata}, inner...), nil
	}
	if unresolved && len(inner) == 0 {
		return []Simple{{Cwd: outer.Cwd, Unresolved: true, pipelines: outer.pipelines}}, nil
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
		case a == "-v" || a == "-V":
			locate = true
			i++
		case strings.HasPrefix(a, "-"):
			return nil, false, unknownOpt("command", a)
		default:
			if locate {
				return nil, true, nil
			}
			return argv[i:], false, nil
		}
	}
	return nil, true, nil
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
			i, err := skipDockerOptions(head(argv)+" "+argv[subcommand], argv, subcommand+1, spec)
			if err != nil {
				return nil, err
			}
			if i+1 < len(argv) {
				return argv[i+1:], nil // skip the image/container token
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
