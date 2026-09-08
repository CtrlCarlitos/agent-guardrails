package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/session"
)

const openCodeApprovalDomain = "agent-guardrails/opencode-approval/v1"
const openCodeApprovalTTL = 10 * time.Minute

func OpenCodeApprovalKey(tc ToolCall) (string, bool) {
	if tc.Plane != "opencode" || tc.Event != "pre" || tc.SessionID == "" || tc.CWD == "" || tc.Tool == "" || len(tc.Arguments) == 0 {
		return "", false
	}

	canonicalArguments, ok := canonicalOpenCodeArguments(tc.Arguments)
	if !ok {
		return "", false
	}

	hash := sha256.New()
	var length [8]byte
	for _, field := range [][]byte{
		[]byte(openCodeApprovalDomain),
		[]byte(tc.SessionID),
		[]byte(tc.CWD),
		[]byte(tc.Tool),
		canonicalArguments,
	} {
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		hash.Write(length[:])
		hash.Write(field)
	}
	return hex.EncodeToString(hash.Sum(nil)), true
}

func canonicalOpenCodeArguments(raw []byte) ([]byte, bool) {
	if !utf8.Valid(raw) || !validJSONSurrogates(raw) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	arguments, ok := decodeStrictJSONValue(decoder)
	if !ok {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	canonical, err := json.Marshal(arguments)
	return canonical, err == nil
}

func decodeStrictJSONValue(decoder *json.Decoder) (any, bool) {
	token, err := decoder.Token()
	if err != nil {
		return nil, false
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, true
	}

	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return nil, false
			}
			name, ok := nameToken.(string)
			if !ok {
				return nil, false
			}
			if _, duplicate := object[name]; duplicate {
				return nil, false
			}
			value, ok := decodeStrictJSONValue(decoder)
			if !ok {
				return nil, false
			}
			object[name] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, false
		}
		return object, true
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, ok := decodeStrictJSONValue(decoder)
			if !ok {
				return nil, false
			}
			array = append(array, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, false
		}
		return array, true
	default:
		return nil, false
	}
}

func validJSONSurrogates(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		for i++; i < len(raw) && raw[i] != '"'; i++ {
			if raw[i] != '\\' {
				continue
			}
			i++
			if i >= len(raw) {
				return false
			}
			if raw[i] != 'u' {
				continue
			}
			codePoint, ok := jsonHexQuad(raw[i+1:])
			if !ok {
				return false
			}
			i += 4
			switch {
			case codePoint >= 0xd800 && codePoint <= 0xdbff:
				if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
					return false
				}
				low, ok := jsonHexQuad(raw[i+3:])
				if !ok || low < 0xdc00 || low > 0xdfff {
					return false
				}
				i += 6
			case codePoint >= 0xdc00 && codePoint <= 0xdfff:
				return false
			}
		}
	}
	return true
}

func jsonHexQuad(raw []byte) (uint16, bool) {
	if len(raw) < 4 {
		return 0, false
	}
	value, err := strconv.ParseUint(string(raw[:4]), 16, 16)
	return uint16(value), err == nil
}

func ApplyOpenCodeApproval(v policy.Verdict, key string, st *session.State, now time.Time) policy.Verdict {
	if key == "" || st == nil {
		return v
	}

	for pendingKey, approval := range st.PendingApprovals {
		if !now.Before(approval.ExpiresAt) {
			delete(st.PendingApprovals, pendingKey)
		}
	}
	pending, exists := st.PendingApprovals[key]

	switch v.Decision {
	case policy.Allow, policy.Deny:
		if exists {
			delete(st.PendingApprovals, key)
		}
	case policy.Ask:
		if v.RuleID == "" {
			delete(st.PendingApprovals, key)
			return v
		}
		if exists && pending.OriginRuleID == v.RuleID {
			delete(st.PendingApprovals, key)
			return policy.Verdict{
				Decision:     policy.Allow,
				RuleID:       "ask-approved-by-retry",
				OriginRuleID: pending.OriginRuleID,
				Reason:       "approved by exact OpenCode retry after user confirmation",
			}
		}
		if st.PendingApprovals == nil {
			st.PendingApprovals = make(map[string]session.PendingApproval)
		}
		st.PendingApprovals[key] = session.PendingApproval{
			OriginRuleID: v.RuleID,
			ExpiresAt:    now.Add(openCodeApprovalTTL),
		}
	}
	return v
}
