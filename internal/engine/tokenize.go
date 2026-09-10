package engine

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/pattern"
	"mvdan.cc/sh/v3/syntax"
)

type Simple struct {
	Argv                  []string
	Redirects             []string
	ReadRedirects         []string
	Cwd                   string
	Unresolved            bool
	literalArgs           map[int]bool
	literalOut            map[int]bool
	literalIn             map[int]bool
	resolvedArgs          map[int]bool
	resolvedOut           map[int]bool
	resolvedIn            map[int]bool
	gitEnvironment        map[string]string
	gitEnvironmentUnknown bool
	gitInitExpected       bool
	fsUncertain           bool
	pipelines             []pipelinePosition
	cwdUnknown            bool
	origin                *syntax.Stmt
	shellState            cwdState
}

type pipelinePosition struct {
	id    int
	stage int
}

type normalizeContext struct {
	nextPipelineID int
	loopDepth      int
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
	return extractSimples(src, f, pipelines, nil, nil), nil
}

func extractSimples(src string, f *syntax.File, pipelines map[*syntax.Stmt][]pipelinePosition, states map[*syntax.Stmt]cwdState, replacements map[*syntax.Stmt][]Simple) []Simple {
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
		if _, replaced := replacements[stmt]; replaced && len(stmt.Redirs) == 0 {
			if _, call := stmt.Cmd.(*syntax.CallExpr); !call {
				out = append(out, Simple{Cwd: state.cwd, Unresolved: state.unknown, cwdUnknown: state.unknown, origin: stmt, shellState: state})
				return false
			}
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
		for index, w := range args {
			raw := src[w.Pos().Offset():w.End().Offset()]
			if lit, ok := literalText(raw); ok {
				s.Argv = append(s.Argv, lit)
				if _, stable := literalText(lit); !stable {
					if s.literalArgs == nil {
						s.literalArgs = make(map[int]bool)
					}
					s.literalArgs[index] = true
				}
			} else if resolved, ok := resolveLocalWord(w, state); tracked && ok {
				s.Argv = append(s.Argv, resolved)
				if s.resolvedArgs == nil {
					s.resolvedArgs = make(map[int]bool)
				}
				s.resolvedArgs[index] = true
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
			resolved := false
			if !literal {
				if tracked {
					target, resolved = resolveLocalWord(r.Word, state)
				}
				if !resolved {
					target = raw
					s.Unresolved = true
				}
			}
			if r.Op == syntax.DplOut && literal && (target == "-" || allDigits(target)) {
				continue
			}
			if write {
				index := len(s.Redirects)
				s.Redirects = append(s.Redirects, target)
				if literal {
					if _, stable := literalText(target); !stable {
						if s.literalOut == nil {
							s.literalOut = make(map[int]bool)
						}
						s.literalOut[index] = true
					}
				} else if resolved {
					if s.resolvedOut == nil {
						s.resolvedOut = make(map[int]bool)
					}
					s.resolvedOut[index] = true
				}
			}
			if read {
				index := len(s.ReadRedirects)
				s.ReadRedirects = append(s.ReadRedirects, target)
				if literal {
					if _, stable := literalText(target); !stable {
						if s.literalIn == nil {
							s.literalIn = make(map[int]bool)
						}
						s.literalIn[index] = true
					}
				} else if resolved {
					if s.resolvedIn == nil {
						s.resolvedIn = make(map[int]bool)
					}
					s.resolvedIn[index] = true
				}
			}
		}
		out = append(out, s)
		return true
	})
	return out
}

func (s Simple) wordUnresolved(index int) bool {
	if index < 0 || index >= len(s.Argv) || s.literalArgs[index] || s.resolvedArgs[index] {
		return false
	}
	_, literal := literalText(s.Argv[index])
	return !literal
}

func (s Simple) outputRedirectUnresolved(index int) bool {
	if index < 0 || index >= len(s.Redirects) || s.literalOut[index] || s.resolvedOut[index] {
		return false
	}
	_, literal := literalText(s.Redirects[index])
	return !literal
}

func (s Simple) inputRedirectUnresolved(index int) bool {
	if index < 0 || index >= len(s.ReadRedirects) || s.literalIn[index] || s.resolvedIn[index] {
		return false
	}
	_, literal := literalText(s.ReadRedirects[index])
	return !literal
}

func resolveLocalWord(word *syntax.Word, state cwdState) (string, bool) {
	if word == nil || len(state.variables) == 0 {
		return "", false
	}
	var value strings.Builder
	unquotedParameter := false
	fieldAnchor := false
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			value.WriteString(part.Value)
			fieldAnchor = fieldAnchor || part.Value != ""
		case *syntax.SglQuoted:
			if part.Dollar {
				return "", false
			}
			value.WriteString(part.Value)
			fieldAnchor = true
		case *syntax.DblQuoted:
			resolved, ok := resolveLocalQuotedParts(part.Parts, state.variables)
			if !ok {
				return "", false
			}
			value.WriteString(resolved)
			fieldAnchor = true
		case *syntax.ParamExp:
			if part.Excl || part.Length || part.Width || part.Index != nil || part.Slice != nil || part.Repl != nil || part.Names != 0 || part.Exp != nil || !validShellVariableName(part.Param.Value) {
				return "", false
			}
			if state.ifsUnknown {
				return "", false
			}
			ifs := " \t\n"
			if tracked, ok := state.variables["IFS"]; ok {
				ifs = tracked
			}
			resolved, ok := state.variables[part.Param.Value]
			if !ok || !unquotedValueGuaranteesOneField(resolved, ifs) {
				return "", false
			}
			unquotedParameter = true
			value.WriteString(resolved)
		default:
			return "", false
		}
	}
	if resolved := value.String(); unquotedParameter && !fieldAnchor && (len(word.Parts) != 1 || resolved == "") {
		return "", false
	}
	if resolved := value.String(); unquotedParameter && !unquotedValueGuaranteesOneField(resolved, "") {
		return "", false
	} else {
		return resolved, true
	}
}

func unquotedValueGuaranteesOneField(value, ifs string) bool {
	if strings.ContainsAny(value, ifs) || strings.ContainsAny(value, "*?[") {
		return false
	}
	return !strings.Contains(value, "@(") && !strings.Contains(value, "+(") && !strings.Contains(value, "!(")
}

func resolveLocalQuotedParts(parts []syntax.WordPart, variables map[string]string) (string, bool) {
	var value strings.Builder
	for _, part := range parts {
		switch part := part.(type) {
		case *syntax.Lit:
			value.WriteString(part.Value)
		case *syntax.ParamExp:
			if part.Excl || part.Length || part.Width || part.Index != nil || part.Slice != nil || part.Repl != nil || part.Names != 0 || part.Exp != nil {
				return "", false
			}
			resolved, ok := variables[part.Param.Value]
			if !ok {
				return "", false
			}
			value.WriteString(resolved)
		default:
			return "", false
		}
	}
	return value.String(), true
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
	cwd                   string
	unknown               bool
	fsUncertain           bool
	ifsUnknown            bool
	cdpath                string
	cdpathSet             bool
	cdpathUnknown         bool
	variables             map[string]string
	namerefs              map[string]string
	assignmentAttributes  map[string]bool
	attributesUnknown     bool
	gitEnvironmentUnknown bool
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
	state = applyExpansionVariableEffects(stmt, state)
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
		state.fsUncertain = true
		child := w.isolated()
		child.command(stmt, state)
		// The parent races an arbitrary child command, whose filesystem effects
		// cannot be observed from the pre-execution filesystem.
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
		if w.ctx.loopDepth == 0 && !forClauseContainsLoop(command) {
			if items, eligible := staticForItems(command); eligible {
				if name, eligible := staticForIterator(command.Loop, state); eligible {
					return w.enumerateStaticFor(stmt, command, name, items, state)
				}
			}
		}
		switch forClauseIterations(command) {
		case iterationNone:
			return successOutcome(state)
		}
		state = invalidateLoopVariables(state, command.Loop)
		uncertainBody := forClauseIterations(command) == iterationPossible || forClauseMayRepeat(command)
		leaveLoop := w.ctx.enterLoop()
		body := w.withUncertainDefinitions(uncertainBody, func() cwdOutcome { return w.list(command.Do, state) })
		leaveLoop()
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
	case *syntax.DeclClause:
		state = invalidateDeclarationVariables(state, command)
		return bothOutcome(state)
	case *syntax.LetClause, *syntax.ArithmCmd:
		state = withoutAllVariables(state)
		state.namerefs = nil
		return bothOutcome(state)
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

const maxStaticForItems = 16

func staticForItems(clause *syntax.ForClause) ([]string, bool) {
	words, ok := clause.Loop.(*syntax.WordIter)
	if !ok || !words.InPos.IsValid() || len(words.Items) == 0 || len(words.Items) > maxStaticForItems {
		return nil, false
	}
	items := make([]string, 0, len(words.Items))
	for _, word := range words.Items {
		braceProbe := *word
		braceProbe.Parts = append([]syntax.WordPart(nil), word.Parts...)
		if syntax.SplitBraces(&braceProbe) {
			return nil, false
		}
		value, static := staticWord(word, false)
		if !static || !wordGuaranteesField(word) {
			return nil, false
		}
		items = append(items, value)
	}
	return items, true
}

func forClauseContainsLoop(clause *syntax.ForClause) bool {
	contains := false
	for _, stmt := range clause.Do {
		syntax.Walk(stmt, func(node syntax.Node) bool {
			switch node.(type) {
			case *syntax.ForClause, *syntax.WhileClause:
				contains = true
				return false
			default:
				return !contains
			}
		})
		if contains {
			return true
		}
	}
	return false
}

func staticForIterator(loop syntax.Loop, state cwdState) (string, bool) {
	words, ok := loop.(*syntax.WordIter)
	if !ok || words.Name == nil || state.attributesUnknown || state.assignmentAttributes[words.Name.Value] {
		return "", false
	}
	if _, nameref := state.namerefs[words.Name.Value]; nameref {
		return "", false
	}
	return words.Name.Value, true
}

func (w *cwdWalker) enumerateStaticFor(stmt *syntax.Stmt, clause *syntax.ForClause, name string, items []string, state cwdState) cwdOutcome {
	leaveLoop := w.ctx.enterLoop()
	defer leaveLoop()
	var replacements []Simple
	baseFunctions := cloneFunctions(w.functions)
	functionAlternatives := []map[string]shellFunctionSet{baseFunctions}
	crossIterationMutation := false
	if len(clause.Do) == 0 {
		w.replacements[stmt] = nil
		return conservativeLoopOutcome(state)
	}
	body := w.src[clause.Do[0].Pos().Offset():clause.Do[len(clause.Do)-1].End().Offset()]
	for _, item := range items {
		candidateState := withVariable(state, name, item)
		result, err := normalizeWithState(body, candidateState, w.ctx, baseFunctions, w.active, w.pipelines[stmt])
		if err != nil {
			post := conservativeLoopState(state)
			w.replacements[stmt] = append(replacements, Simple{Cwd: post.cwd, Unresolved: true, cwdUnknown: true, pipelines: w.pipelines[stmt]})
			return bothOutcome(post)
		}
		replacements = append(replacements, result.simples...)
		functionAlternatives = append(functionAlternatives, result.functions)
		crossIterationMutation = crossIterationMutation || loopOutcomeChangesTrackedFacts(candidateState, result.outcome, result.simples)
		crossIterationMutation = crossIterationMutation || !sameFunctionEnvironment(baseFunctions, result.functions)
	}
	if len(items) > 1 && crossIterationMutation {
		post := conservativeLoopState(state)
		replacements = append(replacements, Simple{Cwd: post.cwd, Unresolved: true, cwdUnknown: true, pipelines: w.pipelines[stmt]})
	}
	w.replacements[stmt] = replacements
	w.publishFunctions(mergeFunctionAlternatives(functionAlternatives...), w.uncertainDef)
	return conservativeLoopOutcome(state)
}

func conservativeLoopOutcome(state cwdState) cwdOutcome {
	return bothOutcome(conservativeLoopState(state))
}

func loopOutcomeChangesTrackedFacts(before cwdState, out cwdOutcome, simples []Simple) bool {
	if out.canSuccess && !sameTrackedShellFacts(before, out.success) || out.canFailure && !sameTrackedShellFacts(before, out.failure) {
		return true
	}
	filesystemChanged := out.canSuccess && before.fsUncertain != out.success.fsUncertain ||
		out.canFailure && before.fsUncertain != out.failure.fsUncertain
	if !filesystemChanged {
		return false
	}
	for _, simple := range simples {
		switch head(simple.Argv) {
		case "cd":
			return true
		case "find":
			parsed := parseFindActions(simple.Argv)
			parsed.applySourceProvenance(simple)
			if parsed.exactScopedDeletion {
				return true
			}
		}
	}
	return false
}

func sameTrackedShellFacts(left, right cwdState) bool {
	return left.cwd == right.cwd &&
		left.unknown == right.unknown &&
		left.ifsUnknown == right.ifsUnknown &&
		left.cdpath == right.cdpath &&
		left.cdpathSet == right.cdpathSet &&
		left.cdpathUnknown == right.cdpathUnknown &&
		left.attributesUnknown == right.attributesUnknown &&
		left.gitEnvironmentUnknown == right.gitEnvironmentUnknown &&
		maps.Equal(left.variables, right.variables) &&
		maps.Equal(left.namerefs, right.namerefs) &&
		maps.Equal(left.assignmentAttributes, right.assignmentAttributes)
}

func conservativeLoopState(state cwdState) cwdState {
	state = unknownCwd(invalidateNamedVariables(state, nil, true))
	state.fsUncertain = true
	return state
}

func sameFunctionEnvironment(left, right map[string]shellFunctionSet) bool {
	if len(left) != len(right) {
		return false
	}
	for name, leftSet := range left {
		rightSet, ok := right[name]
		if !ok || leftSet.mayBeUndefined != rightSet.mayBeUndefined || len(leftSet.bodies) != len(rightSet.bodies) {
			return false
		}
		for index, leftBody := range leftSet.bodies {
			if leftBody.source != rightSet.bodies[index].source {
				return false
			}
		}
	}
	return true
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
	leaveLoop := w.ctx.enterLoop()
	defer leaveLoop()
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

func (ctx *normalizeContext) enterLoop() func() {
	ctx.loopDepth++
	return func() { ctx.loopDepth-- }
}

func (w *cwdWalker) caseClause(clause *syntax.CaseClause, state cwdState) cwdOutcome {
	if w.expansions(clause.Word, state) {
		state.fsUncertain = true
	}
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

func applyExpansionVariableEffects(node syntax.Node, state cwdState) cwdState {
	mutates := false
	syntax.Walk(node, func(node syntax.Node) bool {
		switch expression := node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			return false
		case *syntax.ParamExp:
			mutates = mutates || expression.Excl || expression.Index != nil || expression.Slice != nil || expression.Exp != nil && (expression.Exp.Op == syntax.AssignUnset || expression.Exp.Op == syntax.AssignUnsetOrNull)
		case *syntax.Assign:
			mutates = expression.Index != nil || expression.Array != nil
		case *syntax.ArithmExp:
			mutates = true
		}
		return !mutates
	})
	if mutates {
		return invalidateNamedVariables(state, nil, true)
	}
	return state
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

func simpleForCall(src string, stmt *syntax.Stmt, call *syntax.CallExpr, state cwdState) Simple {
	s := Simple{}
	for index, word := range call.Args {
		raw := src[word.Pos().Offset():word.End().Offset()]
		if literal, ok := literalText(raw); ok {
			s.Argv = append(s.Argv, literal)
		} else if resolved, ok := resolveLocalWord(word, state); ok {
			s.Argv = append(s.Argv, resolved)
			if s.resolvedArgs == nil {
				s.resolvedArgs = make(map[int]bool)
			}
			s.resolvedArgs[index] = true
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
		return successOutcome(applyPersistentAssignments(state, call))
	}
	simple := simpleForCall(w.src, stmt, call, state)
	local := applyCallAssignments(state, call)
	w.recursive[stmt] = local
	if !simple.wordUnresolved(0) {
		if functions, ok := w.functions[simple.Argv[0]]; ok {
			out := w.functionCall(stmt, simple, simple.Argv[0], functions, local)
			return restoreCallAssignments(out, state, call)
		}
	}
	argv, bypassFunction, noExecute, err := directCommandArgv(simple.Argv)
	if err != nil {
		return bothOutcome(unknownCwd(invalidateNamedVariables(state, nil, true)))
	}
	if noExecute {
		return bothOutcome(state)
	}
	if len(argv) == 0 {
		return bothOutcome(state)
	}
	if argv[0] == "eval" {
		return restoreCallAssignments(w.eval(stmt, simple, argv, local), state, call)
	}
	declarationCall := assignmentDeclarationBuiltin(argv[0])
	if declarationCall {
		state = invalidateCallVariables(state, argv)
		local = invalidateCallVariables(local, argv)
	}
	if simple.Unresolved && bypassFunction {
		return bothOutcome(unknownCwd(state))
	}
	if simple.Unresolved && len(w.functions) > 0 && !bypassFunction {
		return bothOutcome(unknownCwd(state))
	}
	if !declarationCall {
		state = invalidateCallVariables(state, argv)
		local = invalidateCallVariables(local, argv)
	}
	switch argv[0] {
	case "cd":
		return restoreCallAssignments(cdOutcome(local, simple, argv), state, call)
	case "pushd", "popd":
		return bothOutcome(unknownCwd(state))
	case ".", "source":
		return bothOutcome(unknownCwd(local))
	case "return", "break", "continue":
		return bothOutcome(unknownCwd(state))
	}

	_, shellCommand, _ := shellDashC(argv)
	if shellCommand || argv[0] == "watch" {
		state.fsUncertain = true
	}
	if command := head(simple.Argv); len(simple.Redirects) > 0 || len(writeTargets(simple)) > 0 || command != "cd" && command != ":" && command != "true" && command != "false" {
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

func directCommandArgv(argv []string) (rest []string, bypassFunction, noExecute bool, err error) {
	for len(argv) > 0 {
		if bypassFunction && (argv[0] == "command" || argv[0] == "builtin") {
			return nil, true, false, fmt.Errorf("nested shell builtin wrappers")
		}
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
		state = invalidateNamedVariables(state, nil, true)
		return bothOutcome(unknownCwd(state))
	}
	if len(argv) == 1 {
		w.replacements[stmt] = nil
		return successOutcome(state)
	}
	result, err := normalizeWithState(strings.Join(argv[1:], " "), state, w.ctx, w.functions, w.active, w.pipelines[stmt])
	if err != nil {
		w.replacements[stmt] = []Simple{{Argv: simple.Argv, Cwd: state.cwd, Unresolved: true, cwdUnknown: true, pipelines: w.pipelines[stmt]}}
		state = invalidateNamedVariables(state, nil, true)
		return bothOutcome(unknownCwd(state))
	}
	w.replacements[stmt] = result.simples
	w.publishFunctions(result.functions, w.uncertainDef)
	return result.outcome
}

func invalidateExpansionFacts(state cwdState) cwdState {
	state = withoutAllVariables(state)
	state.namerefs = nil
	return state
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
		if assignment.Name == nil {
			continue
		}
		name := assignment.Name.Value
		if target, ok := resolveNameref(state.namerefs, name); !ok {
			state = withoutAllVariables(state)
			state.namerefs = nil
			return state
		} else if target != name {
			state = withoutVariables(state, target)
			continue
		}
		if assignment.Append || assignment.Index != nil || assignment.Array != nil {
			state = withoutVariables(state, name)
			continue
		}
		value := ""
		ok := assignment.Value == nil
		if !ok {
			value, ok = staticWord(assignment.Value, false)
		}
		if ok {
			state = withVariable(state, name, value)
		} else {
			state = withoutVariables(state, name)
		}
	}
	return state
}

func restoreCallAssignments(out cwdOutcome, persistent cwdState, call *syntax.CallExpr) cwdOutcome {
	var names []string
	for _, assignment := range call.Assigns {
		if assignment.Name == nil {
			continue
		}
		names = append(names, assignment.Name.Value)
	}
	resolved, ok := resolveNamerefNames(persistent.namerefs, names)
	restore := func(state cwdState) cwdState {
		if !ok {
			state = withoutAllVariables(state)
			state.namerefs = nil
			return state
		}
		namerefs := make(map[string]string, len(state.namerefs))
		for name, target := range state.namerefs {
			namerefs[name] = target
		}
		for _, name := range resolved {
			state = restoreVariable(state, persistent, name)
			if target, exists := persistent.namerefs[name]; exists {
				namerefs[name] = target
			} else {
				delete(namerefs, name)
			}
		}
		state.namerefs = namerefs
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

func applyPersistentAssignments(state cwdState, call *syntax.CallExpr) cwdState {
	return applyCallAssignments(state, call)
}

func invalidateCallVariables(state cwdState, argv []string) cwdState {
	if len(argv) == 0 {
		return state
	}
	switch argv[0] {
	case "cd":
		return withoutVariables(state, "OLDPWD")
	case "pushd", "popd":
		return withoutVariables(state, "PWD", "OLDPWD")
	case ".", "source":
		state = invalidateNamedVariables(state, nil, true)
	case "read":
		names, uncontrolled := readVariableNames(argv[1:])
		return invalidateNamedVariables(state, names, uncontrolled)
	case "readarray", "mapfile":
		names, uncontrolled := mapfileVariableNames(argv[1:])
		state = invalidateNamedVariables(state, names, uncontrolled)
		if uncontrolled {
			state = unknownCwd(state)
			state.fsUncertain = true
		}
		return state
	case "declare", "typeset", "local", "readonly":
		return invalidateDeclarationCallVariables(state, argv)
	case "export", "unset":
		names, uncontrolled := declarationArgumentNames(argv[1:])
		return invalidateNamedVariables(state, names, uncontrolled)
	case "getopts":
		if len(argv) > 2 {
			return invalidateNamedVariables(state, []string{argv[2], "OPTARG", "OPTIND"}, !validShellVariableName(argv[2]))
		}
	case "let":
		state = withoutAllVariables(state)
		state.namerefs = nil
	case "set", "shopt", "trap":
		state = invalidateNamedVariables(state, nil, true)
	case "printf":
		name, found := printfVariableName(argv[1:])
		if found {
			return invalidateNamedVariables(state, []string{name}, !validShellVariableName(name))
		}
	}
	return state
}

func assignmentDeclarationBuiltin(name string) bool {
	switch name {
	case "declare", "typeset", "local", "readonly":
		return true
	default:
		return false
	}
}

func invalidateDeclarationCallVariables(state cwdState, argv []string) cwdState {
	names, assignmentAttributes, uncontrolled := declarationCallEffects(argv)
	state = invalidateNamedVariables(state, names, uncontrolled)
	if uncontrolled || !assignmentAttributes {
		return state
	}
	return withAssignmentAttributes(state, names)
}

func withAssignmentAttributes(state cwdState, names []string) cwdState {
	attributes := make(map[string]bool, len(state.assignmentAttributes)+len(names))
	for name := range state.assignmentAttributes {
		attributes[name] = true
	}
	for _, name := range names {
		attributes[name] = true
	}
	state.assignmentAttributes = attributes
	return state
}

func declarationCallEffects(argv []string) (names []string, assignmentAttributes, uncontrolled bool) {
	if len(argv) == 0 || !assignmentDeclarationBuiltin(argv[0]) {
		return nil, false, true
	}
	assignmentAttributes = argv[0] == "readonly"
	options := true
	for _, arg := range argv[1:] {
		if options && arg == "--" {
			options = false
			continue
		}
		if options && len(arg) > 1 && (arg[0] == '-' || arg[0] == '+') {
			for _, option := range arg[1:] {
				if !strings.ContainsRune("aAfFgiIlnprtux", option) {
					return names, false, true
				}
				if strings.ContainsRune("aAilnru", option) {
					if arg[0] == '+' {
						return names, false, true
					}
					assignmentAttributes = true
				}
			}
			continue
		}
		options = false
		name, _, _ := strings.Cut(arg, "=")
		if !validShellVariableName(name) {
			return names, false, true
		}
		names = append(names, name)
	}
	return names, assignmentAttributes, false
}

func invalidateDeclarationVariables(state cwdState, declaration *syntax.DeclClause) cwdState {
	var names []string
	uncontrolled := false
	for _, assignment := range declaration.Args {
		if assignment.Name != nil {
			names = append(names, assignment.Name.Value)
			continue
		}
		value, ok := staticWord(assignment.Value, false)
		if !ok || !strings.HasPrefix(value, "-") {
			uncontrolled = true
		}
	}
	state = invalidateNamedVariables(state, names, uncontrolled)
	if declarationHasAssignmentAttributes(declaration) {
		state = withAssignmentAttributes(state, names)
	}
	if uncontrolled || !declarationCreatesNameref(declaration) {
		return state
	}
	namerefs := make(map[string]string, len(state.namerefs)+len(names))
	for name, target := range state.namerefs {
		namerefs[name] = target
	}
	for _, assignment := range declaration.Args {
		if assignment.Name == nil || assignment.Value == nil {
			continue
		}
		target, ok := staticWord(assignment.Value, false)
		if !ok || !validShellVariableName(target) {
			state = withoutAllVariables(state)
			state.namerefs = nil
			return state
		}
		namerefs[assignment.Name.Value] = target
	}
	state.namerefs = namerefs
	return state
}

func declarationHasAssignmentAttributes(declaration *syntax.DeclClause) bool {
	if declaration.Variant != nil && (declaration.Variant.Value == "nameref" || declaration.Variant.Value == "readonly") {
		return true
	}
	for _, assignment := range declaration.Args {
		if assignment.Name != nil {
			continue
		}
		value, ok := staticWord(assignment.Value, false)
		if ok && strings.HasPrefix(value, "-") && strings.ContainsAny(strings.TrimPrefix(value, "-"), "aAilnru") {
			return true
		}
	}
	return false
}

func declarationCreatesNameref(declaration *syntax.DeclClause) bool {
	if declaration.Variant != nil && declaration.Variant.Value == "nameref" {
		return true
	}
	for _, assignment := range declaration.Args {
		if assignment.Name != nil {
			continue
		}
		value, ok := staticWord(assignment.Value, false)
		if ok && strings.HasPrefix(value, "-") && strings.Contains(strings.TrimPrefix(value, "-"), "n") {
			return true
		}
	}
	return false
}

func invalidateNamedVariables(state cwdState, names []string, uncontrolled ...bool) cwdState {
	if len(uncontrolled) > 0 && uncontrolled[0] {
		state = withoutAllVariables(state)
		state.namerefs = nil
		state.assignmentAttributes = nil
		state.attributesUnknown = true
		return state
	}
	return withoutVariables(state, names...)
}

func printfVariableName(argv []string) (string, bool) {
	for index, arg := range argv {
		switch {
		case arg == "--":
			return "", false
		case arg == "-v":
			if index+1 >= len(argv) {
				return "", false
			}
			return argv[index+1], true
		case strings.HasPrefix(arg, "-v") && len(arg) > 2:
			return arg[2:], true
		}
	}
	return "", false
}

func readVariableNames(argv []string) ([]string, bool) {
	var names []string
	for index := 0; index < len(argv); index++ {
		arg := argv[index]
		if arg == "--" {
			names = append(names, argv[index+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			cluster := strings.TrimPrefix(arg, "-")
			for optionIndex, option := range cluster {
				if strings.ContainsRune("adinNptu", option) {
					value := cluster[optionIndex+1:]
					if value == "" {
						if index+1 >= len(argv) {
							return nil, true
						}
						index++
						value = argv[index]
					}
					if option == 'a' {
						names = append(names, value)
					}
					break
				}
				if !strings.ContainsRune("ers", option) {
					return nil, true
				}
			}
			continue
		}
		names = append(names, arg)
	}
	for _, name := range names {
		if !validShellVariableName(name) {
			return names, true
		}
	}
	if len(names) == 0 {
		names = []string{"REPLY"}
	}
	return names, false
}

func mapfileVariableNames(argv []string) ([]string, bool) {
	for index := 0; index < len(argv); index++ {
		arg := argv[index]
		if arg == "--" {
			if index+1 == len(argv) {
				return []string{"MAPFILE"}, false
			}
			name := argv[index+1]
			return []string{name}, !validShellVariableName(name)
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			return []string{arg}, !validShellVariableName(arg)
		}
		cluster := strings.TrimPrefix(arg, "-")
		for optionIndex, option := range cluster {
			if strings.ContainsRune("dnOsuCc", option) {
				if optionIndex+1 == len(cluster) {
					if index+1 >= len(argv) {
						return nil, true
					}
					index++
				}
				if option == 'C' {
					return nil, true
				}
				break
			}
			if option != 't' {
				return nil, true
			}
		}
	}
	return []string{"MAPFILE"}, false
}

func declarationArgumentNames(argv []string) ([]string, bool) {
	var names []string
	for _, arg := range argv {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		name, _, _ := strings.Cut(arg, "=")
		if !validShellVariableName(name) {
			return names, true
		}
		names = append(names, name)
	}
	return names, false
}

func validShellVariableName(name string) bool {
	if name == "" || name[0] != '_' && (name[0] < 'A' || name[0] > 'Z') && (name[0] < 'a' || name[0] > 'z') {
		return false
	}
	for index := 1; index < len(name); index++ {
		char := name[index]
		if char != '_' && (char < 'A' || char > 'Z') && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func invalidateLoopVariables(state cwdState, loop syntax.Loop) cwdState {
	wordLoop, ok := loop.(*syntax.WordIter)
	if !ok || wordLoop.Name == nil {
		return withoutAllVariables(state)
	}
	return withoutVariables(state, wordLoop.Name.Value)
}

func withoutVariables(state cwdState, names ...string) cwdState {
	resolved, ok := resolveNamerefNames(state.namerefs, names)
	if !ok {
		state = withoutAllVariables(state)
		state.namerefs = nil
		return state
	}
	return withoutResolvedVariables(state, resolved...)
}

func withoutResolvedVariables(state cwdState, names ...string) cwdState {
	for _, name := range names {
		if name == "IFS" {
			state.ifsUnknown = true
		}
		if name == "CDPATH" {
			state.cdpath = ""
			state.cdpathSet = false
			state.cdpathUnknown = true
		}
		if gitRepositoryEnvironmentVariable(name) {
			state.gitEnvironmentUnknown = true
		}
	}
	if len(state.variables) == 0 {
		return state
	}
	variables := make(map[string]string, len(state.variables))
	for name, value := range state.variables {
		variables[name] = value
	}
	for _, name := range names {
		delete(variables, name)
	}
	state.variables = variables
	return state
}

func withoutAllVariables(state cwdState) cwdState {
	state.variables = nil
	state.ifsUnknown = true
	state.cdpath = ""
	state.cdpathSet = false
	state.cdpathUnknown = true
	state.gitEnvironmentUnknown = true
	return state
}

func withVariable(state cwdState, name, value string) cwdState {
	if !canPublishExactVariable(state, name) {
		return withoutResolvedVariables(state, name)
	}
	variables := make(map[string]string, len(state.variables)+1)
	for current, tracked := range state.variables {
		variables[current] = tracked
	}
	variables[name] = value
	state.variables = variables
	switch name {
	case "IFS":
		state.ifsUnknown = false
	case "CDPATH":
		state.cdpath = value
		state.cdpathSet = true
		state.cdpathUnknown = false
	}
	return state
}

func restoreVariable(state, persistent cwdState, name string) cwdState {
	if !canPublishExactVariable(state, name) {
		return withoutResolvedVariables(state, name)
	}
	variables := make(map[string]string, len(state.variables))
	for current, tracked := range state.variables {
		variables[current] = tracked
	}
	value, exists := persistent.variables[name]
	if exists {
		variables[name] = value
	} else {
		delete(variables, name)
	}
	state.variables = variables
	switch name {
	case "IFS":
		state.ifsUnknown = persistent.ifsUnknown
	case "CDPATH":
		state.cdpath = persistent.cdpath
		state.cdpathSet = persistent.cdpathSet
		state.cdpathUnknown = persistent.cdpathUnknown
	default:
		if gitRepositoryEnvironmentVariable(name) {
			state.gitEnvironmentUnknown = state.gitEnvironmentUnknown || persistent.gitEnvironmentUnknown || !exists
		}
	}
	return state
}

func canPublishExactVariable(state cwdState, name string) bool {
	return !state.attributesUnknown && !state.assignmentAttributes[name]
}

func resolveNamerefNames(namerefs map[string]string, names []string) ([]string, bool) {
	resolved := make([]string, 0, len(names))
	for _, name := range names {
		target, ok := resolveNameref(namerefs, name)
		if !ok {
			return nil, false
		}
		resolved = append(resolved, target)
	}
	return resolved, true
}

func resolveNameref(namerefs map[string]string, name string) (string, bool) {
	seen := make(map[string]bool)
	for {
		if seen[name] {
			return "", false
		}
		seen[name] = true
		target, ok := namerefs[name]
		if !ok {
			return name, true
		}
		name = target
	}
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
	if success.unknown {
		success = withoutVariables(success, "PWD")
	} else {
		success = withVariable(success, "PWD", success.cwd)
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
	merged.variables, merged.ifsUnknown, merged.gitEnvironmentUnknown = mergeVariableFacts(states)
	merged.namerefs = commonNamerefs(states)
	merged.assignmentAttributes = combinedAssignmentAttributes(states)
	for _, state := range states[1:] {
		merged.fsUncertain = merged.fsUncertain || state.fsUncertain
		merged.attributesUnknown = merged.attributesUnknown || state.attributesUnknown
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

func mergeVariableFacts(states []cwdState) (map[string]string, bool, bool) {
	ifsUnknown := !sameVariableValue(states, "IFS")
	gitEnvironmentUnknown := !sameGitRepositoryEnvironment(states)
	for _, state := range states {
		ifsUnknown = ifsUnknown || state.ifsUnknown
		gitEnvironmentUnknown = gitEnvironmentUnknown || state.gitEnvironmentUnknown
	}
	return commonVariables(states), ifsUnknown, gitEnvironmentUnknown
}

func sameVariableValue(states []cwdState, name string) bool {
	want, wantPresent := states[0].variables[name]
	for _, state := range states[1:] {
		value, present := state.variables[name]
		if present != wantPresent || value != want {
			return false
		}
	}
	return true
}

func sameGitRepositoryEnvironment(states []cwdState) bool {
	want := gitRepositoryEnvironment(states[0].variables)
	for _, state := range states[1:] {
		if !maps.Equal(want, gitRepositoryEnvironment(state.variables)) {
			return false
		}
	}
	return true
}

func combinedAssignmentAttributes(states []cwdState) map[string]bool {
	var combined map[string]bool
	for _, state := range states {
		for name := range state.assignmentAttributes {
			if combined == nil {
				combined = make(map[string]bool)
			}
			combined[name] = true
		}
	}
	return combined
}

func commonNamerefs(states []cwdState) map[string]string {
	if len(states) == 0 || len(states[0].namerefs) == 0 {
		return nil
	}
	common := make(map[string]string, len(states[0].namerefs))
	for name, target := range states[0].namerefs {
		common[name] = target
	}
	for _, state := range states[1:] {
		for name, target := range common {
			if candidate, ok := state.namerefs[name]; !ok || candidate != target {
				delete(common, name)
			}
		}
	}
	return common
}

func commonVariables(states []cwdState) map[string]string {
	if len(states) == 0 || len(states[0].variables) == 0 {
		return nil
	}
	common := make(map[string]string, len(states[0].variables))
	for name, value := range states[0].variables {
		common[name] = value
	}
	for _, state := range states[1:] {
		for name, value := range common {
			if candidate, ok := state.variables[name]; !ok || candidate != value {
				delete(common, name)
			}
		}
	}
	return common
}

func unknownCwd(states ...cwdState) cwdState {
	state := mergeCwd(states...)
	state.cwd = ""
	state.unknown = true
	return withoutVariables(state, "PWD")
}

func cwdMayChange(before, after cwdState) bool {
	return before.unknown != after.unknown || before.cwd != after.cwd
}

func forClauseMayRepeat(clause *syntax.ForClause) bool {
	return analyzeForClause(clause).mayRepeat
}

// Normalize returns conservative policy candidates, with no-op wrappers
// stripped and argument-executing runners unwrapped. Candidates may include
// syntactic loop-body commands that shell control flow would skip.
func Normalize(command, cwd string) ([]Simple, error) {
	return normalizeWithContext(command, cwd, &normalizeContext{})
}

func normalizeWithContext(command, cwd string, ctx *normalizeContext) ([]Simple, error) {
	state := cwdState{cwd: cwd, variables: make(map[string]string, 2)}
	if cwd != "" {
		state.variables["PWD"] = cwd
	}
	if home, ok := os.LookupEnv("HOME"); ok {
		state.variables["HOME"] = home
	}
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
	base := extractSimples(command, f, pipelines, walker.states, walker.replacements)
	var out []Simple
	for _, s := range base {
		if recursiveState, ok := walker.recursive[s.origin]; ok {
			s.shellState = recursiveState
			s.gitEnvironment = gitRepositoryEnvironment(recursiveState.variables)
			s.gitEnvironmentUnknown = recursiveState.gitEnvironmentUnknown
			if s.gitEnvironmentUnknown && head(s.Argv) == "git" {
				s.Unresolved = true
			}
		}
		if gitEnvironmentAssignmentUnknown(s.origin) {
			s.gitEnvironmentUnknown = true
			s.Unresolved = true
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
			Unresolved:    redirectsUnresolved(outer),
			literalOut:    outer.literalOut,
			literalIn:     outer.literalIn,
			resolvedOut:   outer.resolvedOut,
			resolvedIn:    outer.resolvedIn,
			pipelines:     outer.pipelines,
			cwdUnknown:    outer.cwdUnknown,
			fsUncertain:   outer.fsUncertain,
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
	return commandDerivedFromAt(outer, argv, argvSubsliceOffset(outer.Argv, argv))
}

func commandDerivedFromAt(outer Simple, argv []string, sourceArg int) Simple {
	derived := Simple{
		Argv:                  argv,
		Cwd:                   outer.Cwd,
		Unresolved:            outer.Unresolved || outer.gitEnvironmentUnknown && head(argv) == "git",
		literalOut:            outer.literalOut,
		literalIn:             outer.literalIn,
		resolvedOut:           outer.resolvedOut,
		resolvedIn:            outer.resolvedIn,
		gitEnvironment:        outer.gitEnvironment,
		gitEnvironmentUnknown: outer.gitEnvironmentUnknown,
		gitInitExpected:       outer.gitInitExpected,
		pipelines:             outer.pipelines,
		cwdUnknown:            outer.cwdUnknown,
		fsUncertain:           outer.fsUncertain || head(argv) == "find" && (outer.shellState.fsUncertain || len(outer.pipelines) > 0),
		shellState:            outer.shellState,
	}
	if sourceArg >= 0 && sourceArg+len(argv) <= len(outer.Argv) {
		derived.literalArgs = remapProvenance(outer.literalArgs, sourceArg, len(argv))
		derived.resolvedArgs = remapProvenance(outer.resolvedArgs, sourceArg, len(argv))
	}
	return derived
}

func gitRepositoryEnvironment(variables map[string]string) map[string]string {
	var environment map[string]string
	for _, name := range []string{"GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM"} {
		if value, ok := variables[name]; ok {
			if environment == nil {
				environment = make(map[string]string)
			}
			environment[name] = value
		}
	}
	return environment
}

func gitEnvironmentAssignmentUnknown(stmt *syntax.Stmt) bool {
	if stmt == nil {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return false
	}
	for _, assignment := range call.Assigns {
		if assignment.Name == nil || !gitRepositoryEnvironmentVariable(assignment.Name.Value) {
			continue
		}
		if assignment.Append || assignment.Index != nil || assignment.Array != nil {
			return true
		}
		if assignment.Value != nil {
			if _, ok := staticWord(assignment.Value, false); !ok {
				return true
			}
		}
	}
	return false
}

func gitRepositoryEnvironmentVariable(name string) bool {
	switch name {
	case "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM":
		return true
	default:
		return false
	}
}

func applyEnvGitEnvironment(simple Simple, argv []string) Simple {
	offset := argvSubsliceOffset(simple.Argv, argv)
	if offset < 0 {
		return simple
	}
	for index := 1; index < len(argv); index++ {
		arg := argv[index]
		switch {
		case arg == "--":
			return simple
		case arg == "-u":
			index++
			continue
		case strings.HasPrefix(arg, "-"):
			continue
		}
		name, value, assignment := strings.Cut(arg, "=")
		if !assignment {
			return simple
		}
		if !gitRepositoryEnvironmentVariable(name) {
			continue
		}
		if simple.wordUnresolved(offset + index) {
			simple.gitEnvironmentUnknown = true
			simple.Unresolved = true
			continue
		}
		if simple.gitEnvironment == nil {
			simple.gitEnvironment = make(map[string]string)
		}
		simple.gitEnvironment[name] = value
	}
	return simple
}

func argvSubsliceOffset(source, derived []string) int {
	for offset := 0; offset+len(derived) <= len(source); offset++ {
		matches := true
		for index := range derived {
			if source[offset+index] != derived[index] {
				matches = false
				break
			}
		}
		if matches {
			return offset
		}
	}
	return -1
}

func remapProvenance(provenance map[int]bool, offset, length int) map[int]bool {
	var remapped map[int]bool
	for index := range provenance {
		if index < offset || index >= offset+length {
			continue
		}
		if remapped == nil {
			remapped = make(map[int]bool)
		}
		remapped[index-offset] = true
	}
	return remapped
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
			s = applyEnvGitEnvironment(s, argv)
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
			s.shellState.fsUncertain = true
			rest, err = consumeXargs(argv[1:])
		case "unshare", "nsenter":
			s.shellState.fsUncertain = true
			rest, err = consumeNamespace(argv[1:])
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
		s.shellState.fsUncertain = true
		nested, err := stripAndUnwrap(commandDerivedFrom(s, inner), ctx)
		if err != nil {
			return nil, err
		}
		result = append(result, nested...)
	}
	source, dashC, err := shellDashC(argv)
	if err != nil {
		return nil, err
	}
	if dashC {
		innerState := invalidateExpansionFacts(s.shellState)
		inner, err := normalizeShellDashC(source, innerState, s.pipelines, ctx)
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
		remoteState := invalidateExpansionFacts(s.shellState)
		remoteState.fsUncertain = true
		inner, err := normalizeShellDashC(remoteSource, remoteState, s.pipelines, ctx)
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
	state := invalidateExpansionFacts(outer.shellState)
	state.fsUncertain = true
	result, err := normalizeWithState(strings.Join(argv, " "), state, ctx, nil, nil, outer.pipelines)
	if err != nil {
		return nil, err
	}
	inner := result.simples
	contextUnresolved := unresolved
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
			Unresolved:    contextUnresolved || redirectsUnresolved(outer),
			literalOut:    outer.literalOut,
			literalIn:     outer.literalIn,
			resolvedOut:   outer.resolvedOut,
			resolvedIn:    outer.resolvedIn,
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

func redirectsUnresolved(simple Simple) bool {
	for index := range simple.Redirects {
		if simple.outputRedirectUnresolved(index) {
			return true
		}
	}
	for index := range simple.ReadRedirects {
		if simple.inputRedirectUnresolved(index) {
			return true
		}
	}
	return false
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
		case a == "-i" || a == "--ignore-environment" || a == "-v" || a == "--debug" || a == "-0" || a == "--null":
			i++
		case a == "-u" || a == "--unset":
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

func consumeNamespace(argv []string) ([]string, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("namespace wrapper: missing command")
	}
	switch argv[0] {
	case "--":
		return argv[1:], nil
	case "-m", "--mount":
		return consumeNamespace(argv[1:])
	case "-t", "--target":
		if len(argv) < 2 {
			return nil, needsValue("namespace wrapper", argv[0])
		}
		return consumeNamespace(argv[2:])
	default:
		return consumeNoFlags("namespace wrapper", argv)
	}
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
