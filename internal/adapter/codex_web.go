package adapter

import (
	"encoding/json"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// codexWebCapability projects the whole request, never just its first action.
// The engine currently evaluates one fetch URL; opaque references, batches and
// operations without an inspectable destination must stay denied.
func codexWebCapability(input map[string]json.RawMessage) (policy.Capability, string) {
	searches := 0
	opens := 0
	target := ""
	for key, raw := range input {
		switch key {
		case "response_length":
			var length string
			if json.Unmarshal(raw, &length) != nil || (length != "short" && length != "medium" && length != "long") {
				return policy.CapabilityDeny, ""
			}
		case "search_query", "image_query":
			var queries []struct {
				Q string `json:"q"`
			}
			if json.Unmarshal(raw, &queries) != nil || len(queries) == 0 {
				return policy.CapabilityDeny, ""
			}
			for _, q := range queries {
				if strings.TrimSpace(q.Q) == "" {
					return policy.CapabilityDeny, ""
				}
			}
			searches += len(queries)
		case "open":
			var requests []struct {
				RefID string `json:"ref_id"`
			}
			if json.Unmarshal(raw, &requests) != nil || len(requests) != 1 {
				return policy.CapabilityDeny, ""
			}
			if _, err := engine.NormalizeWebFetchURL(requests[0].RefID); err != nil {
				return policy.CapabilityDeny, ""
			}
			opens++
			target = requests[0].RefID
		default:
			return policy.CapabilityDeny, ""
		}
	}
	if searches > 0 && opens == 0 {
		return policy.CapabilityWebSearch, ""
	}
	if opens == 1 && searches == 0 {
		return policy.CapabilityWebFetch, target
	}
	return policy.CapabilityDeny, ""
}
