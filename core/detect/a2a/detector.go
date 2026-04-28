package a2a

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
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
	PolicyRefs          []string `json:"policy_refs"`
	Exposure            string   `json:"exposure"`
	DelegationModel     string   `json:"delegation_model"`
	SanitizationClaims  []string `json:"sanitization_claims"`
}

func (Detector) Detect(_ context.Context, scope detect.Scope, options detect.Options) ([]model.Finding, error) {
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}
	if detect.IsLocalMachineScope(scope) {
		return nil, nil
	}

	policy, _, policyErr := mcpgateway.LoadPolicyWithOptions(scope.Root, options)
	if policyErr != nil {
		return nil, policyErr
	}

	files, err := detect.WalkFilesWithOptions(scope.Root, options)
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
		trustDepth := buildA2ATrustDepth(rel, capabilities, authSchemes, protocols, card, posture)
		severity := model.SeverityLow
		switch {
		case a2aTrustDepthRequiresHighSeverity(trustDepth), posture.Coverage == mcpgateway.CoverageUnprotected:
			severity = model.SeverityHigh
		case a2aTrustDepthRequiresMediumSeverity(trustDepth), posture.Coverage == mcpgateway.CoverageUnknown:
			severity = model.SeverityMedium
		}
		remediation := "Keep agent-card schema fields strict and deterministic."
		if posture.Coverage == mcpgateway.CoverageUnprotected {
			remediation = "Add deny-by-default gateway policy coverage for this A2A agent declaration."
		}

		evidenceList := []model.Evidence{
			{Key: "agent_name", Value: name},
			{Key: "capabilities", Value: strings.Join(capabilities, ",")},
			{Key: "auth_schemes", Value: strings.Join(authSchemes, ",")},
			{Key: "protocols", Value: strings.Join(protocols, ",")},
			{Key: "coverage", Value: posture.Coverage},
			{Key: "policy_posture", Value: posture.PolicyPosture},
			{Key: "default_behavior", Value: posture.DefaultAction},
			{Key: "reason_code", Value: posture.ReasonCode},
		}
		evidenceList = append(evidenceList, a2aTrustDepthEvidence(trustDepth)...)

		findings = append(findings, model.Finding{
			FindingType: "a2a_agent_card",
			Severity:    severity,
			ToolType:    "a2a_agent",
			Location:    rel,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Evidence:    evidenceList,
			Remediation: remediation,
		})
	}

	model.SortFindings(findings)
	return findings, nil
}

func buildA2ATrustDepth(rel string, capabilities []string, authSchemes []string, protocols []string, card agentCard, posture mcpgateway.Result) *agginventory.TrustDepth {
	exposure := strings.TrimSpace(card.Exposure)
	if exposure == "" {
		switch {
		case strings.Contains(strings.ToLower(filepath.ToSlash(rel)), "/.well-known/"):
			exposure = agginventory.TrustExposurePublic
		case strings.HasPrefix(strings.ToLower(firstNonEmptyString(protocols...)), "http"):
			exposure = agginventory.TrustExposurePublic
		default:
			exposure = agginventory.TrustExposureUnknown
		}
	}
	delegation := strings.TrimSpace(card.DelegationModel)
	if delegation == "" {
		delegation = agginventory.TrustDelegationNone
		for _, capability := range capabilities {
			lower := strings.ToLower(strings.TrimSpace(capability))
			if strings.Contains(lower, "delegate") || strings.Contains(lower, "handoff") {
				delegation = agginventory.TrustDelegationAgent
				break
			}
		}
	}
	authStrength := agginventory.TrustAuthUnknown
	for _, scheme := range authSchemes {
		lower := strings.ToLower(strings.TrimSpace(scheme))
		switch {
		case strings.Contains(lower, "oauth"):
			authStrength = agginventory.TrustAuthOAuthDelegation
		case strings.Contains(lower, "workload"), strings.Contains(lower, "oidc"):
			authStrength = agginventory.TrustAuthWorkloadIdentity
		case strings.Contains(lower, "none"), strings.Contains(lower, "anonymous"):
			authStrength = agginventory.TrustAuthNone
		case strings.Contains(lower, "token"), strings.Contains(lower, "key"):
			authStrength = agginventory.TrustAuthStaticSecret
		}
	}
	gaps := make([]string, 0, 8)
	if exposure == agginventory.TrustExposurePublic {
		gaps = append(gaps, "public_exposure")
	}
	switch posture.Coverage {
	case mcpgateway.CoverageUnprotected:
		gaps = append(gaps, "gateway_unprotected")
	case mcpgateway.CoverageUnknown:
		gaps = append(gaps, "gateway_unknown")
	}
	if delegation == agginventory.TrustDelegationAgent && len(card.PolicyRefs) == 0 {
		gaps = append(gaps, "delegation_without_policy")
	}
	if len(card.PolicyRefs) == 0 && (delegation != agginventory.TrustDelegationNone || exposure == agginventory.TrustExposurePublic) {
		gaps = append(gaps, "policy_ref_missing")
	}
	if len(card.SanitizationClaims) == 0 && exposure == agginventory.TrustExposurePublic {
		gaps = append(gaps, "sanitization_unspecified")
	}
	for _, capability := range capabilities {
		lower := strings.ToLower(strings.TrimSpace(capability))
		if strings.Contains(lower, "write") || strings.Contains(lower, "deploy") || strings.Contains(lower, "delete") || strings.Contains(lower, "exec") {
			gaps = append(gaps, "destructive_capability")
			break
		}
	}
	return agginventory.NormalizeTrustDepth(&agginventory.TrustDepth{
		Surface:            agginventory.TrustSurfaceA2A,
		AuthStrength:       authStrength,
		DelegationModel:    delegation,
		Exposure:           exposure,
		PolicyRefs:         normalizeList(card.PolicyRefs),
		GatewayCoverage:    normalizeA2AGatewayCoverage(posture.Coverage),
		SanitizationClaims: normalizeList(card.SanitizationClaims),
		CapabilityExposure: capabilities,
		TrustGaps:          normalizeList(gaps),
	})
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func a2aTrustDepthEvidence(depth *agginventory.TrustDepth) []model.Evidence {
	normalized := agginventory.NormalizeTrustDepth(depth)
	if normalized == nil {
		return nil
	}
	return []model.Evidence{
		{Key: "trust_surface", Value: normalized.Surface},
		{Key: "auth_strength", Value: normalized.AuthStrength},
		{Key: "delegation_model", Value: normalized.DelegationModel},
		{Key: "exposure", Value: normalized.Exposure},
		{Key: "policy_binding", Value: normalized.PolicyBinding},
		{Key: "policy_refs", Value: strings.Join(normalized.PolicyRefs, ",")},
		{Key: "gateway_binding", Value: normalized.GatewayBinding},
		{Key: "gateway_coverage", Value: normalized.GatewayCoverage},
		{Key: "sanitization_claims", Value: strings.Join(normalized.SanitizationClaims, ",")},
		{Key: "capability_exposure", Value: strings.Join(normalized.CapabilityExposure, ",")},
		{Key: "trust_gaps", Value: strings.Join(normalized.TrustGaps, ",")},
		{Key: "trust_depth_score", Value: fmt.Sprintf("%.2f", normalized.TrustDepthScore)},
	}
}

func a2aTrustDepthRequiresHighSeverity(depth *agginventory.TrustDepth) bool {
	normalized := agginventory.NormalizeTrustDepth(depth)
	if normalized == nil {
		return false
	}
	if normalized.Exposure == agginventory.TrustExposurePublic && normalized.GatewayCoverage == agginventory.TrustCoverageUnprotected {
		return true
	}
	for _, gap := range normalized.TrustGaps {
		switch strings.TrimSpace(gap) {
		case "gateway_unprotected", "delegation_without_policy", "destructive_capability":
			return true
		}
	}
	return false
}

func a2aTrustDepthRequiresMediumSeverity(depth *agginventory.TrustDepth) bool {
	normalized := agginventory.NormalizeTrustDepth(depth)
	return normalized != nil && len(normalized.TrustGaps) > 0
}

func normalizeA2AGatewayCoverage(value string) string {
	switch strings.TrimSpace(value) {
	case mcpgateway.CoverageProtected:
		return agginventory.TrustCoverageProtected
	case mcpgateway.CoverageUnprotected:
		return agginventory.TrustCoverageUnprotected
	default:
		return agginventory.TrustCoverageUnknown
	}
}

func validateAgentCard(card agentCard) (string, []string, []string, []string, error) {
	name := strings.ToLower(strings.TrimSpace(card.Name))
	if name == "" {
		return "", nil, nil, nil, fmt.Errorf("agent card field name is required")
	}
	capabilities := normalizeList(card.Capabilities)
	authSchemes := normalizeList(card.AuthSchemes)
	protocols := normalizeList(card.Protocols)
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
