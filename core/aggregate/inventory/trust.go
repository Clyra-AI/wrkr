package inventory

import (
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/Clyra-AI/wrkr/core/model"
)

const (
	TrustSurfaceMCP = "mcp"
	TrustSurfaceA2A = "a2a"

	TrustAuthNone              = "none"
	TrustAuthStaticSecret      = "static_secret"
	TrustAuthWorkloadIdentity  = "workload_identity"
	TrustAuthInheritedHuman    = "inherited_human"
	TrustAuthOAuthDelegation   = "oauth_delegation"
	TrustAuthJIT               = "jit"
	TrustAuthUnknown           = "unknown"
	TrustDelegationNone        = "none"
	TrustDelegationToolProxy   = "tool_proxy"
	TrustDelegationAgent       = "agent_delegate"
	TrustDelegationUnknown     = "unknown"
	TrustExposureLocal         = "local"
	TrustExposurePrivate       = "private"
	TrustExposurePublic        = "public"
	TrustExposureUnknown       = "unknown"
	TrustPolicyDeclared        = "declared"
	TrustPolicyMissing         = "missing"
	TrustGatewayBound          = "bound"
	TrustGatewayUnbound        = "unbound"
	TrustGatewayUnknownBinding = "unknown"
	TrustCoverageProtected     = "protected"
	TrustCoverageUnprotected   = "unprotected"
	TrustCoverageUnknown       = "unknown"
)

type TrustDepth struct {
	Surface            string   `json:"surface,omitempty" yaml:"surface,omitempty"`
	AuthStrength       string   `json:"auth_strength" yaml:"auth_strength"`
	DelegationModel    string   `json:"delegation_model" yaml:"delegation_model"`
	Exposure           string   `json:"exposure" yaml:"exposure"`
	PolicyBinding      string   `json:"policy_binding" yaml:"policy_binding"`
	PolicyRefs         []string `json:"policy_refs,omitempty" yaml:"policy_refs,omitempty"`
	GatewayBinding     string   `json:"gateway_binding" yaml:"gateway_binding"`
	GatewayCoverage    string   `json:"gateway_coverage" yaml:"gateway_coverage"`
	SanitizationClaims []string `json:"sanitization_claims,omitempty" yaml:"sanitization_claims,omitempty"`
	CapabilityExposure []string `json:"capability_exposure,omitempty" yaml:"capability_exposure,omitempty"`
	TrustGaps          []string `json:"trust_gaps,omitempty" yaml:"trust_gaps,omitempty"`
	TrustDepthScore    float64  `json:"trust_depth_score" yaml:"trust_depth_score"`
}

func CloneTrustDepth(in *TrustDepth) *TrustDepth {
	if in == nil {
		return nil
	}
	out := *in
	out.PolicyRefs = append([]string(nil), in.PolicyRefs...)
	out.SanitizationClaims = append([]string(nil), in.SanitizationClaims...)
	out.CapabilityExposure = append([]string(nil), in.CapabilityExposure...)
	out.TrustGaps = append([]string(nil), in.TrustGaps...)
	return &out
}

func NormalizeTrustDepth(in *TrustDepth) *TrustDepth {
	if in == nil {
		return nil
	}
	out := CloneTrustDepth(in)
	out.Surface = normalizeTrustSurface(out.Surface)
	out.AuthStrength = normalizeTrustAuth(out.AuthStrength)
	out.DelegationModel = normalizeTrustDelegation(out.DelegationModel)
	out.Exposure = normalizeTrustExposure(out.Exposure)
	out.PolicyBinding = normalizeTrustPolicyBinding(out.PolicyBinding, out.PolicyRefs)
	out.GatewayBinding = normalizeTrustGatewayBinding(out.GatewayBinding, out.GatewayCoverage)
	out.GatewayCoverage = normalizeTrustCoverage(out.GatewayCoverage)
	out.PolicyRefs = normalizeTrustStringList(out.PolicyRefs)
	out.SanitizationClaims = normalizeTrustStringList(out.SanitizationClaims)
	out.CapabilityExposure = normalizeTrustStringList(out.CapabilityExposure)
	out.TrustGaps = normalizeTrustStringList(out.TrustGaps)
	if out.TrustDepthScore <= 0 {
		out.TrustDepthScore = trustDepthScoreFor(out)
	}
	out.TrustDepthScore = roundTrustScore(out.TrustDepthScore)
	return out
}

func MergeTrustDepth(current, incoming *TrustDepth) *TrustDepth {
	current = NormalizeTrustDepth(current)
	incoming = NormalizeTrustDepth(incoming)
	switch {
	case current == nil:
		return CloneTrustDepth(incoming)
	case incoming == nil:
		return CloneTrustDepth(current)
	}

	merged := CloneTrustDepth(current)
	if merged.Surface == "" || merged.Surface == "unknown" {
		merged.Surface = incoming.Surface
	}
	if authRiskRank(incoming.AuthStrength) > authRiskRank(merged.AuthStrength) {
		merged.AuthStrength = incoming.AuthStrength
	}
	if delegationRiskRank(incoming.DelegationModel) > delegationRiskRank(merged.DelegationModel) {
		merged.DelegationModel = incoming.DelegationModel
	}
	if exposureRiskRank(incoming.Exposure) > exposureRiskRank(merged.Exposure) {
		merged.Exposure = incoming.Exposure
	}
	if policyRiskRank(incoming.PolicyBinding) > policyRiskRank(merged.PolicyBinding) {
		merged.PolicyBinding = incoming.PolicyBinding
	}
	if gatewayCoverageRiskRank(incoming.GatewayCoverage) > gatewayCoverageRiskRank(merged.GatewayCoverage) {
		merged.GatewayCoverage = incoming.GatewayCoverage
	}
	if gatewayBindingRiskRank(incoming.GatewayBinding) > gatewayBindingRiskRank(merged.GatewayBinding) {
		merged.GatewayBinding = incoming.GatewayBinding
	}
	merged.PolicyRefs = normalizeTrustStringList(append(append([]string(nil), merged.PolicyRefs...), incoming.PolicyRefs...))
	merged.SanitizationClaims = normalizeTrustStringList(append(append([]string(nil), merged.SanitizationClaims...), incoming.SanitizationClaims...))
	merged.CapabilityExposure = normalizeTrustStringList(append(append([]string(nil), merged.CapabilityExposure...), incoming.CapabilityExposure...))
	merged.TrustGaps = normalizeTrustStringList(append(append([]string(nil), merged.TrustGaps...), incoming.TrustGaps...))
	if incoming.TrustDepthScore < merged.TrustDepthScore || merged.TrustDepthScore == 0 {
		merged.TrustDepthScore = incoming.TrustDepthScore
	}
	return NormalizeTrustDepth(merged)
}

func TrustDepthFromFinding(finding model.Finding) *TrustDepth {
	evidence := map[string]string{}
	for _, item := range finding.Evidence {
		key := strings.ToLower(strings.TrimSpace(item.Key))
		if key == "" {
			continue
		}
		evidence[key] = strings.TrimSpace(item.Value)
	}
	score := 0.0
	if raw := strings.TrimSpace(evidence["trust_depth_score"]); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
			score = parsed
		}
	}
	depth := NormalizeTrustDepth(&TrustDepth{
		Surface:            strings.TrimSpace(evidence["trust_surface"]),
		AuthStrength:       strings.TrimSpace(evidence["auth_strength"]),
		DelegationModel:    strings.TrimSpace(evidence["delegation_model"]),
		Exposure:           strings.TrimSpace(evidence["exposure"]),
		PolicyBinding:      strings.TrimSpace(evidence["policy_binding"]),
		PolicyRefs:         splitTrustList(evidence["policy_refs"]),
		GatewayBinding:     strings.TrimSpace(evidence["gateway_binding"]),
		GatewayCoverage:    strings.TrimSpace(evidence["gateway_coverage"]),
		SanitizationClaims: splitTrustList(evidence["sanitization_claims"]),
		CapabilityExposure: splitTrustList(firstNonEmptyTrustValue(evidence["capability_exposure"], evidence["capabilities"], evidence["declared_action_surface"])),
		TrustGaps:          splitTrustList(evidence["trust_gaps"]),
		TrustDepthScore:    score,
	})
	if depth == nil {
		return nil
	}
	if depth.Surface == "" &&
		depth.AuthStrength == TrustAuthUnknown &&
		depth.DelegationModel == TrustDelegationUnknown &&
		depth.Exposure == TrustExposureUnknown &&
		depth.PolicyBinding == TrustPolicyMissing &&
		depth.GatewayBinding == TrustGatewayUnknownBinding &&
		depth.GatewayCoverage == TrustCoverageUnknown &&
		len(depth.PolicyRefs) == 0 &&
		len(depth.SanitizationClaims) == 0 &&
		len(depth.CapabilityExposure) == 0 &&
		len(depth.TrustGaps) == 0 &&
		depth.TrustDepthScore == 0 {
		return nil
	}
	return depth
}

func normalizeTrustSurface(value string) string {
	switch strings.TrimSpace(value) {
	case TrustSurfaceMCP, TrustSurfaceA2A:
		return strings.TrimSpace(value)
	default:
		return ""
	}
}

func normalizeTrustAuth(value string) string {
	switch strings.TrimSpace(value) {
	case TrustAuthNone,
		TrustAuthStaticSecret,
		TrustAuthWorkloadIdentity,
		TrustAuthInheritedHuman,
		TrustAuthOAuthDelegation,
		TrustAuthJIT:
		return strings.TrimSpace(value)
	default:
		return TrustAuthUnknown
	}
}

func normalizeTrustDelegation(value string) string {
	switch strings.TrimSpace(value) {
	case TrustDelegationNone, TrustDelegationToolProxy, TrustDelegationAgent:
		return strings.TrimSpace(value)
	default:
		return TrustDelegationUnknown
	}
}

func normalizeTrustExposure(value string) string {
	switch strings.TrimSpace(value) {
	case TrustExposureLocal, TrustExposurePrivate, TrustExposurePublic:
		return strings.TrimSpace(value)
	default:
		return TrustExposureUnknown
	}
}

func normalizeTrustPolicyBinding(value string, refs []string) string {
	switch strings.TrimSpace(value) {
	case TrustPolicyDeclared:
		return TrustPolicyDeclared
	case TrustPolicyMissing:
		return TrustPolicyMissing
	}
	if len(refs) > 0 {
		return TrustPolicyDeclared
	}
	return TrustPolicyMissing
}

func normalizeTrustGatewayBinding(value, coverage string) string {
	switch strings.TrimSpace(value) {
	case TrustGatewayBound, TrustGatewayUnbound:
		return strings.TrimSpace(value)
	case TrustGatewayUnknownBinding:
		return TrustGatewayUnknownBinding
	}
	switch normalizeTrustCoverage(coverage) {
	case TrustCoverageProtected:
		return TrustGatewayBound
	case TrustCoverageUnprotected:
		return TrustGatewayUnbound
	default:
		return TrustGatewayUnknownBinding
	}
}

func normalizeTrustCoverage(value string) string {
	switch strings.TrimSpace(value) {
	case TrustCoverageProtected, TrustCoverageUnprotected:
		return strings.TrimSpace(value)
	default:
		return TrustCoverageUnknown
	}
}

func splitTrustList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return normalizeTrustStringList(strings.Split(raw, ","))
}

func normalizeTrustStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := set[trimmed]; ok {
			continue
		}
		set[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func trustDepthScoreFor(in *TrustDepth) float64 {
	score := 10.0
	for _, gap := range in.TrustGaps {
		switch strings.TrimSpace(gap) {
		case "gateway_unprotected", "public_exposure", "destructive_capability", "delegation_without_policy":
			score -= 2.0
		case "gateway_unknown", "policy_ref_missing", "sanitization_unspecified", "static_secret_auth":
			score -= 1.25
		default:
			score -= 0.5
		}
	}
	if in.Exposure == TrustExposurePublic {
		score -= 1.0
	}
	if in.GatewayCoverage == TrustCoverageUnprotected {
		score -= 1.5
	}
	if in.DelegationModel == TrustDelegationAgent && in.PolicyBinding != TrustPolicyDeclared {
		score -= 1.0
	}
	if in.AuthStrength == TrustAuthStaticSecret || in.AuthStrength == TrustAuthInheritedHuman {
		score -= 0.75
	}
	if score < 0 {
		return 0
	}
	return score
}

func authRiskRank(value string) int {
	switch normalizeTrustAuth(value) {
	case TrustAuthInheritedHuman:
		return 5
	case TrustAuthStaticSecret:
		return 4
	case TrustAuthOAuthDelegation:
		return 3
	case TrustAuthUnknown:
		return 2
	case TrustAuthNone:
		return 1
	default:
		return 0
	}
}

func delegationRiskRank(value string) int {
	switch normalizeTrustDelegation(value) {
	case TrustDelegationAgent:
		return 3
	case TrustDelegationToolProxy:
		return 2
	case TrustDelegationUnknown:
		return 1
	default:
		return 0
	}
}

func exposureRiskRank(value string) int {
	switch normalizeTrustExposure(value) {
	case TrustExposurePublic:
		return 3
	case TrustExposureUnknown:
		return 2
	case TrustExposurePrivate:
		return 1
	default:
		return 0
	}
}

func policyRiskRank(value string) int {
	switch normalizeTrustPolicyBinding(value, nil) {
	case TrustPolicyMissing:
		return 1
	default:
		return 0
	}
}

func gatewayCoverageRiskRank(value string) int {
	switch normalizeTrustCoverage(value) {
	case TrustCoverageUnprotected:
		return 3
	case TrustCoverageUnknown:
		return 2
	case TrustCoverageProtected:
		return 1
	default:
		return 0
	}
}

func gatewayBindingRiskRank(value string) int {
	switch normalizeTrustGatewayBinding(value, "") {
	case TrustGatewayUnbound:
		return 2
	case TrustGatewayUnknownBinding:
		return 1
	default:
		return 0
	}
}

func firstNonEmptyTrustValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func roundTrustScore(value float64) float64 {
	return math.Round(value*100) / 100
}
