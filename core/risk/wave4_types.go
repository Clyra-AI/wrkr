package risk

import (
	"sort"
	"strings"
)

const (
	HighStakesPresetReleaseAutomation     = "release_automation"
	HighStakesPresetProductionPath        = "production_path"
	HighStakesPresetCredentialAutomation  = "credential_bearing_automation" // #nosec G101 -- Deterministic high-stakes preset label, not credential material.
	HighStakesPresetInfrastructureAsCode  = "infrastructure_as_code"
	HighStakesPresetIdentityAuthCode      = "identity_auth_code"
	HighStakesPresetPackagePublishing     = "package_publishing"
	HighStakesPresetPaymentFlow           = "payment_flow"
	HighStakesPresetRegulatedCustomerFlow = "regulated_customer_workflow"
	HighStakesPresetExternalEgress        = "external_egress"
	HighStakesPresetMCPToolConfig         = "mcp_tool_config"
	HighStakesPresetMutableEndpoint       = "mutable_endpoint"

	ProductionContextCorrelated   = "correlated"
	ProductionContextAppendixOnly = "appendix_only"
)

type HighStakesPreset struct {
	Preset       string   `json:"preset,omitempty"`
	ReasonCodes  []string `json:"reason_codes,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

type ProductionContext struct {
	Status                    string   `json:"status,omitempty"`
	SurfaceLabel              string   `json:"surface_label,omitempty"`
	ToolType                  string   `json:"tool_type,omitempty"`
	Owner                     string   `json:"owner,omitempty"`
	CredentialMode            string   `json:"credential_mode,omitempty"`
	DeploymentStatus          string   `json:"deployment_status,omitempty"`
	ActionClasses             []string `json:"action_classes,omitempty"`
	PathType                  string   `json:"path_type,omitempty"`
	TargetClass               string   `json:"target_class,omitempty"`
	MutableEndpointOperations []string `json:"mutable_endpoint_operations,omitempty"`
	EvidenceRefs              []string `json:"evidence_refs,omitempty"`
	ReasonCodes               []string `json:"reason_codes,omitempty"`
}

func CloneHighStakesPresets(in []HighStakesPreset) []HighStakesPreset {
	if len(in) == 0 {
		return nil
	}
	out := make([]HighStakesPreset, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.Preset = strings.TrimSpace(copyItem.Preset)
		copyItem.ReasonCodes = dedupeSortedStrings(copyItem.ReasonCodes)
		copyItem.EvidenceRefs = dedupeSortedStrings(copyItem.EvidenceRefs)
		out = append(out, copyItem)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func CloneProductionContext(in *ProductionContext) *ProductionContext {
	if in == nil {
		return nil
	}
	out := *in
	out.Status = strings.TrimSpace(out.Status)
	out.SurfaceLabel = strings.TrimSpace(out.SurfaceLabel)
	out.ToolType = strings.TrimSpace(out.ToolType)
	out.Owner = strings.TrimSpace(out.Owner)
	out.CredentialMode = strings.TrimSpace(out.CredentialMode)
	out.DeploymentStatus = strings.TrimSpace(out.DeploymentStatus)
	out.PathType = strings.TrimSpace(out.PathType)
	out.TargetClass = strings.TrimSpace(out.TargetClass)
	out.ActionClasses = dedupeSortedStrings(out.ActionClasses)
	out.MutableEndpointOperations = dedupeStringsPreserveOrder(out.MutableEndpointOperations)
	out.EvidenceRefs = dedupeSortedStrings(out.EvidenceRefs)
	out.ReasonCodes = dedupeSortedStrings(out.ReasonCodes)
	return &out
}

func normalizeHighStakesPresets(in []HighStakesPreset) []HighStakesPreset {
	out := CloneHighStakesPresets(in)
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Preset != out[j].Preset {
			return out[i].Preset < out[j].Preset
		}
		return strings.Join(out[i].ReasonCodes, ",") < strings.Join(out[j].ReasonCodes, ",")
	})
	return out
}

func dedupeStringsPreserveOrder(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := value
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
