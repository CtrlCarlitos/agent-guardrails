package adapter

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
)

// This recognizes native research, not arbitrary MCP tools or shell networking.
func nativeResearchCall(tc engine.ToolCall) bool {
	query := ""
	switch tc.Plane + "/" + tc.NativeTool {
	case "claude/WebSearch", "opencode/websearch":
		query = "query"
	case "antigravity/search_web":
		query = "Query"
	case "claude/WebFetch", "opencode/webfetch", "antigravity/read_url_content":
		_, err := engine.NormalizeWebFetchURL(tc.URL)
		return err == nil
	default:
		return false
	}
	var input map[string]json.RawMessage
	var text string
	return json.Unmarshal(tc.Arguments, &input) == nil && json.Unmarshal(input[query], &text) == nil && strings.TrimSpace(text) != ""
}

var codexResearchReference = regexp.MustCompile(`^turn[0-9]+[A-Za-z]+[0-9]+$`)

func researchReference(ref string) bool {
	if codexResearchReference.MatchString(ref) {
		return true
	}
	_, err := engine.NormalizeWebFetchURL(ref)
	return err == nil
}

// Keep strict projection unchanged. This second, bounded classification lets
// the operator opt out of destination enforcement without allowing unknown
// operations, malformed payloads, local-file URLs, or credentialed URLs.
func codexResearchInput(input map[string]json.RawMessage) bool {
	operations := 0
	for key, raw := range input {
		if key == "response_length" {
			var length string
			if json.Unmarshal(raw, &length) != nil || (length != "short" && length != "medium" && length != "long") {
				return false
			}
			continue
		}
		var entries []json.RawMessage
		if json.Unmarshal(raw, &entries) != nil || len(entries) == 0 {
			return false
		}
		for _, entry := range entries {
			switch key {
			case "search_query", "image_query":
				if !researchFields(entry, "q", "domains", "recency") {
					return false
				}
				var q struct {
					Q       string   `json:"q"`
					Domains []string `json:"domains"`
					Recency *int     `json:"recency"`
				}
				if json.Unmarshal(entry, &q) != nil || strings.TrimSpace(q.Q) == "" {
					return false
				}
			case "open", "click", "find", "screenshot":
				field := map[string]string{"open": "lineno", "click": "id", "find": "pattern", "screenshot": "pageno"}[key]
				if !researchFields(entry, "ref_id", field) {
					return false
				}
				var ref struct {
					RefID   string `json:"ref_id"`
					ID      *int   `json:"id"`
					Pattern string `json:"pattern"`
					Page    *int   `json:"pageno"`
					Line    *int   `json:"lineno"`
				}
				if json.Unmarshal(entry, &ref) != nil || !researchReference(ref.RefID) {
					return false
				}
				if key == "click" && (ref.ID == nil || *ref.ID < 0) {
					return false
				}
				if key == "find" && ref.Pattern == "" {
					return false
				}
				if key == "screenshot" && (ref.Page == nil || *ref.Page < 0) {
					return false
				}
				if ref.Line != nil && *ref.Line < 0 {
					return false
				}
			default:
				return false
			}
			operations++
		}
	}
	return operations > 0
}

func researchFields(raw json.RawMessage, allowed ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return false
	}
	for key := range fields {
		found := false
		for _, candidate := range allowed {
			if key == candidate {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
