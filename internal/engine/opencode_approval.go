package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/session"
)

const openCodeApprovalDomain = "agent-guardrails/opencode-approval/v1"
const openCodeApprovalTTL = 10 * time.Minute

func OpenCodeApprovalKey(tc ToolCall) (string, bool) {
	if tc.Plane != "opencode" || tc.Event != "pre" || tc.SessionID == "" || tc.CWD == "" || tc.Tool == "" || len(tc.Arguments) == 0 {
		return "", false
	}

	decoder := json.NewDecoder(bytes.NewReader(tc.Arguments))
	decoder.UseNumber()
	var arguments any
	if err := decoder.Decode(&arguments); err != nil {
		return "", false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return "", false
	}
	canonicalArguments, err := json.Marshal(arguments)
	if err != nil {
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
