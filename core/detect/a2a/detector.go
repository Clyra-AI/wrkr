package a2a

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/mcpgateway"
	"github.com/Clyra-AI/wrkr/core/model"
)

const detectorID = "a2a"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

type agentCard struct {
	Name                string   `json:"name"`
	Capabilities        []string `json:"capabilities"`
	AuthSchemes         []string `json:"auth_schemes"`
	Protocols           []string `json:"protocols"`
	InteractionPatterns []string `json:"interaction_patterns"`
}

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	info, err := os.Stat(scope.Root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	policy, _, policyErr := mcpgateway.LoadPolicy(scope.Root)
	if policyErr != nil {
		return nil, policyErr
	}

	files, err := detect.WalkFiles(scope.Root)
	if err != nil {
		return nil, err
	}
	findings := make([]model.Finding, 0)
	for _, rel := range files {
		if !isAgentCardPath(rel) {
			continue
		}
		var card agentCard
		if parseErr := detect.ParseJSONFile(detectorID, scope.Root, rel, &card); parseErr != nil {
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "a2a_agent",
				Location:    rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError:  parseErr,
			})
			continue
		}

		name, capabilities, authSchemes, protocols, validationErr := validateAgentCard(card)
		if validationErr != nil {
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "a2a_agent",
				Location:    rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError: &model.ParseError{
					Kind:     "schema_validation_error",
					Format:   "json",
					Path:     rel,
					Detector: detectorID,
					Message:  validationErr.Error(),
				},
			})
			continue
		}

		posture := mcpgateway.EvaluateCoverage(policy, name)
		severity := model.SeverityLow
		switch posture.Coverage {
		case mcpgateway.CoverageUnprotected:
			severity = model.SeverityHigh
		case mcpgateway.CoverageUnknown:
			severity = model.SeverityMedium
		}
		remediation := "Keep agent-card schema fields strict and deterministic."
		if posture.Coverage == mcpgateway.CoverageUnprotected {
			remediation = "Add deny-by-default gateway policy coverage for this A2A agent declaration."
		}

		findings = append(findings, model.Finding{
			FindingType: "a2a_agent_card",
			Severity:    severity,
			ToolType:    "a2a_agent",
			Location:    rel,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Evidence: []model.Evidence{
				{Key: "agent_name", Value: name},
				{Key: "capabilities", Value: strings.Join(capabilities, ",")},
				{Key: "auth_schemes", Value: strings.Join(authSchemes, ",")},
				{Key: "protocols", Value: strings.Join(protocols, ",")},
				{Key: "coverage", Value: posture.Coverage},
				{Key: "policy_posture", Value: posture.PolicyPosture},
				{Key: "default_behavior", Value: posture.DefaultAction},
				{Key: "reason_code", Value: posture.ReasonCode},
			},
			Remediation: remediation,
		})
	}

	model.SortFindings(findings)
	return findings, nil
}

func validateAgentCard(card agentCard) (string, []string, []string, []string, error) {
	name := strings.ToLower(strings.TrimSpace(card.Name))
	if name == "" {
		return "", nil, nil, nil, fmt.Errorf("agent card field name is required")
	}
	capabilities := normalizeList(card.Capabilities)
	authSchemes := normalizeList(card.AuthSchemes)
	protocols := normalizeList(card.Protocols)
	if len(authSchemes) == 0 {
		authSchemes = normalizeList(card.InteractionPatterns)
	}
	if len(capabilities) == 0 {
		return "", nil, nil, nil, fmt.Errorf("agent card field capabilities must contain at least one value")
	}
	if len(authSchemes) == 0 {
		return "", nil, nil, nil, fmt.Errorf("agent card field auth_schemes must contain at least one value")
	}
	if len(protocols) == 0 {
		return "", nil, nil, nil, fmt.Errorf("agent card field protocols must contain at least one value")
	}
	return name, capabilities, authSchemes, protocols, nil
}

func normalizeList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.ToLower(strings.TrimSpace(value))
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func isAgentCardPath(rel string) bool {
	lower := strings.ToLower(filepath.ToSlash(rel))
	base := strings.ToLower(filepath.Base(lower))
	if base != "agent.json" && base != "agent-card.json" {
		return false
	}
	return strings.HasSuffix(lower, "/.well-known/agent.json") || strings.HasSuffix(lower, "/agent.json") || strings.HasSuffix(lower, "/agent-card.json")
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return strings.TrimSpace(org)
}
