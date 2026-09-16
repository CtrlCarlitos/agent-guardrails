// Package fetch implements Guardrail's constrained, redirect-aware web proxy.
package fetch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

const maxBody = 1 << 20

var errAsk = errors.New("unapproved web host")

func Fetch(ctx context.Context, raw string, pol *policy.Policy) (string, policy.Verdict, error) {
	if !allowed(raw, pol) {
		return "", policy.Verdict{Decision: policy.Ask, RuleID: "fetch-host", Reason: "web fetch to an unapproved host requires operator approval"}, nil
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if !allowed(req.URL.String(), pol) {
			return errAsk
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return "", policy.Verdict{Decision: policy.Deny, RuleID: "fetch-invalid"}, err
	}
	resp, err := client.Do(req)
	if errors.Is(err, errAsk) {
		return "", policy.Verdict{Decision: policy.Ask, RuleID: "fetch-host", Reason: "redirect destination requires operator approval"}, nil
	}
	if err != nil {
		return "", policy.Verdict{Decision: policy.Deny, RuleID: "fetch-failed"}, err
	}
	defer resp.Body.Close()
	media := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	if media != "text/plain" && media != "text/html" && media != "text/markdown" && media != "application/json" {
		return "", policy.Verdict{Decision: policy.Deny, RuleID: "fetch-content-type"}, nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return "", policy.Verdict{Decision: policy.Deny, RuleID: "fetch-failed"}, err
	}
	if len(b) > maxBody {
		return "", policy.Verdict{Decision: policy.Deny, RuleID: "fetch-too-large"}, nil
	}
	text := string(b)
	if media == "text/html" {
		text = normalizeHTML(text)
	}
	return text, policy.Verdict{Decision: policy.Allow}, nil
}

func allowed(raw string, pol *policy.Policy) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	err = policy.ValidateWebHost(host)
	if err != nil {
		return false
	}
	if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
		return true
	}
	if pol != nil {
		for _, allowed := range pol.Slots.WebHosts {
			if host == allowed {
				return true
			}
		}
	}
	return false
}

func normalizeHTML(s string) string {
	var out strings.Builder
	inTag := false
	for _, r := range s {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			out.WriteByte(' ')
			continue
		}
		if !inTag {
			out.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(out.String()), " ") + "\n"
}
