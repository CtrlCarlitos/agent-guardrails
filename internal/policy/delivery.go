package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// DeliveryPolicy is standing operator authorization, never an Overlay request.
// It delegates only the bounded delivery executor, not arbitrary gh/Git calls.
type DeliveryPolicy struct {
	GitHubID       int64    `toml:"github_id"`
	GitHub         string   `toml:"github"`
	Base           string   `toml:"base"`
	Method         string   `toml:"method"`
	ProtectedPaths []string `toml:"protected_paths"`
}

var deliveryRepo = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var deliveryBranch = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

func (p DeliveryPolicy) Validate() error {
	if p.GitHubID <= 0 || !deliveryRepo.MatchString(p.GitHub) || !deliveryBranch.MatchString(p.Base) || strings.Contains(p.Base, "..") || strings.HasSuffix(p.Base, "/") || strings.HasSuffix(p.Base, ".") {
		return fmt.Errorf("invalid delivery repository or base")
	}
	if p.Method != "squash" && p.Method != "merge" && p.Method != "rebase" {
		return fmt.Errorf("invalid delivery merge method")
	}
	for _, path := range p.ProtectedPaths {
		if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, "\\") {
			return fmt.Errorf("invalid delivery protected path")
		}
		for _, segment := range strings.Split(path, "/") {
			if segment == ".." {
				return fmt.Errorf("invalid delivery protected path")
			}
		}
		if _, err := doublestar.Match(path, ""); err != nil {
			return fmt.Errorf("invalid delivery protected path: %w", err)
		}
	}
	return nil
}

func (o *OperatorConfig) DeliveryFor(repo string) (DeliveryPolicy, bool) {
	entry, ok := o.grant(repo)
	if !ok || entry.Delivery == nil || entry.Delivery.Validate() != nil {
		return DeliveryPolicy{}, false
	}
	result := *entry.Delivery
	result.ProtectedPaths = append([]string(nil), result.ProtectedPaths...)
	return result, true
}

// DecodeDeliveryPolicy validates the same effective policy at consent and use.
// JSON null represents revocation, which grants no capability.
func DecodeDeliveryPolicy(text string) (*DeliveryPolicy, error) {
	if len(text) > 64<<10 {
		return nil, fmt.Errorf("delivery policy exceeds review budget")
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	var p *DeliveryPolicy
	if err := decoder.Decode(&p); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("trailing delivery policy input")
	}
	if p != nil {
		if err := p.Validate(); err != nil {
			return nil, err
		}
	}
	return p, nil
}
