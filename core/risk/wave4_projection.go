package risk

import (
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func deriveHighStakesPresets(path ActionPath) []HighStakesPreset {
	presets := []HighStakesPreset{}
	add := func(preset string, reasons []string, refs ...string) {
		if strings.TrimSpace(preset) == "" {
			return
		}
		presets = append(presets, HighStakesPreset{
			Preset:       strings.TrimSpace(preset),
			ReasonCodes:  dedupeSortedStrings(reasons),
			EvidenceRefs: dedupeSortedStrings(refs),
		})
	}

	location := strings.ToLower(strings.TrimSpace(path.Location))
	if path.ProductionWrite || len(path.MatchedProductionTargets) > 0 || normalizeTargetClass(path.TargetClass) == TargetClassProductionImpacting {
		add(HighStakesPresetProductionPath, []string{"production_path:detected"}, append([]string(nil), path.TargetClassEvidenceRefs...)...)
	}
	if path.CredentialAccess || path.StandingPrivilege || len(path.AuthorityBindings) > 0 {
		add(HighStakesPresetCredentialAutomation, []string{"credential_authority:present"}, credentialEvidenceRefs(path)...)
	}
	if containsAnyPathClass(path.WritePathClasses, "infra_write") || strings.Contains(location, "terraform") || strings.Contains(location, "cloudformation") || strings.Contains(location, "k8s") || strings.Contains(location, "kubernetes") || strings.Contains(location, "helm") {
		add(HighStakesPresetInfrastructureAsCode, []string{"infrastructure_surface:detected"}, append([]string(nil), path.ActionPathTypeEvidenceRefs...)...)
	}
	if strings.Contains(location, "release") || containsAnyPathClass(path.WritePathClasses, "release_write", "package_publish") || path.MergeExecute || path.DeployWrite {
		add(HighStakesPresetReleaseAutomation, []string{"release_surface:detected"}, append([]string(nil), path.ControlEvidenceRefs...)...)
	}
	if strings.Contains(location, "auth") || strings.Contains(location, "identity") || strings.Contains(location, "iam") || strings.Contains(location, "rbac") || strings.Contains(location, "oidc") || strings.Contains(location, "oauth") || hasAuthorityBindingKind(path.AuthorityBindings, agginventory.AuthorityBindingCloudRole, agginventory.AuthorityBindingKubernetesRBAC, agginventory.AuthorityBindingWorkloadIdentity) {
		add(HighStakesPresetIdentityAuthCode, []string{"identity_or_auth_surface:detected"}, credentialEvidenceRefs(path)...)
	}
	if containsAnyPathClass(path.WritePathClasses, "package_publish") || strings.Contains(location, "package") || strings.Contains(location, "publish") {
		add(HighStakesPresetPackagePublishing, []string{"package_publish_surface:detected"}, append([]string(nil), path.ActionPathTypeEvidenceRefs...)...)
	}
	if pathHasMutableEndpointSemantic(path, agginventory.EndpointSemanticPayment, agginventory.EndpointSemanticRefund) || strings.Contains(location, "payment") || strings.Contains(location, "billing") {
		add(HighStakesPresetPaymentFlow, []string{"payment_surface:detected"}, mutableEndpointEvidenceRefs(path)...)
	}
	if pathHasMutableEndpointSemantic(path, agginventory.EndpointSemanticDataExport, agginventory.EndpointSemanticUserAdmin, agginventory.EndpointSemanticProductionMutation) || normalizeTargetClass(path.TargetClass) == TargetClassCustomerDataAdjacent {
		add(HighStakesPresetRegulatedCustomerFlow, []string{"customer_or_regulated_surface:detected"}, mutableEndpointEvidenceRefs(path)...)
	}
	if strings.TrimSpace(path.RiskZone) == RiskZoneExternalEgress || containsPathValue(path.ActionClasses, "egress") {
		add(HighStakesPresetExternalEgress, []string{"external_egress:detected"}, append([]string(nil), path.PolicyEvidenceRefs...)...)
	}
	if strings.Contains(location, ".mcp.json") || strings.Contains(location, "/mcp.") || strings.Contains(location, ".codex/") || strings.Contains(location, ".claude/") || strings.Contains(location, ".cursor/") || strings.HasSuffix(location, "agents.md") || strings.HasSuffix(location, "agents.override.md") {
		add(HighStakesPresetMCPToolConfig, []string{"tool_or_mcp_config:detected"}, []string{strings.TrimSpace(path.Location)}...)
	}
	if pathHasAnyMutableEndpoint(path) {
		add(HighStakesPresetMutableEndpoint, []string{"mutable_endpoint:present"}, mutableEndpointEvidenceRefs(path)...)
	}

	return normalizeHighStakesPresets(presets)
}

func deriveProductionContext(path ActionPath) *ProductionContext {
	if !pathHasAnyMutableEndpoint(path) && strings.TrimSpace(path.RiskZone) != RiskZoneProductionData {
		return nil
	}
	status := ProductionContextCorrelated
	reasons := []string{"production_context:derived"}
	if pathRequiresAppendixOnlyProductionContext(path) {
		status = ProductionContextAppendixOnly
		reasons = append(reasons, "production_context:appendix_only_without_authority_correlation")
	}
	return CloneProductionContext(&ProductionContext{
		Status:                    status,
		SurfaceLabel:              firstNonEmptyString(strings.TrimSpace(path.Purpose), strings.TrimSpace(path.Location), strings.TrimSpace(path.PathID)),
		ToolType:                  strings.TrimSpace(path.ToolType),
		Owner:                     strings.TrimSpace(path.OperationalOwner),
		CredentialMode:            credentialModeForPath(path),
		DeploymentStatus:          strings.TrimSpace(path.DeploymentStatus),
		ActionClasses:             append([]string(nil), path.ActionClasses...),
		PathType:                  strings.TrimSpace(path.ActionPathType),
		TargetClass:               strings.TrimSpace(path.TargetClass),
		MutableEndpointOperations: pathMutableEndpointOperations(path),
		EvidenceRefs:              dedupeSortedStrings(append(append(append([]string(nil), path.TargetClassEvidenceRefs...), path.ActionPathTypeEvidenceRefs...), mutableEndpointEvidenceRefs(path)...)),
		ReasonCodes:               dedupeSortedStrings(reasons),
	})
}

func pathRequiresAppendixOnlyProductionContext(path ActionPath) bool {
	toolType := strings.ToLower(strings.TrimSpace(path.ToolType))
	if toolType != "openapi" && toolType != "route" {
		return false
	}
	if !pathHasAnyMutableEndpoint(path) {
		return false
	}
	return !path.ProductionWrite &&
		len(path.MatchedProductionTargets) == 0 &&
		!path.DeployWrite &&
		!path.CredentialAccess &&
		!path.StandingPrivilege &&
		len(path.AuthorityBindings) == 0
}

func pathHasHighStakesPreset(path ActionPath) bool {
	return len(path.HighStakesPresets) > 0
}

func highStakesPresetScore(path ActionPath) int {
	score := 0
	for _, item := range path.HighStakesPresets {
		switch strings.TrimSpace(item.Preset) {
		case HighStakesPresetProductionPath, HighStakesPresetPaymentFlow, HighStakesPresetRegulatedCustomerFlow:
			score += 5
		case HighStakesPresetIdentityAuthCode, HighStakesPresetInfrastructureAsCode, HighStakesPresetCredentialAutomation:
			score += 4
		case HighStakesPresetReleaseAutomation, HighStakesPresetPackagePublishing, HighStakesPresetExternalEgress:
			score += 3
		case HighStakesPresetMCPToolConfig, HighStakesPresetMutableEndpoint:
			score += 2
		}
	}
	return score
}

func hasAuthorityBindingKind(bindings []*agginventory.AuthorityBinding, wants ...string) bool {
	for _, binding := range agginventory.NormalizeAuthorityBindings(bindings) {
		if binding == nil {
			continue
		}
		for _, want := range wants {
			if strings.TrimSpace(binding.Kind) == strings.TrimSpace(want) {
				return true
			}
		}
	}
	return false
}

func mutableEndpointEvidenceRefs(path ActionPath) []string {
	refs := []string{}
	for _, item := range pathMutableEndpointSemantics(path) {
		refs = append(refs, item.EvidenceRefs...)
		if strings.TrimSpace(item.Operation) != "" {
			refs = append(refs, strings.TrimSpace(item.Operation))
		}
	}
	return dedupeSortedStrings(refs)
}

func credentialEvidenceRefs(path ActionPath) []string {
	refs := []string{}
	if path.CredentialProvenance != nil {
		refs = append(refs, path.CredentialProvenance.EvidenceBasis...)
		if strings.TrimSpace(path.CredentialProvenance.EvidenceLocation) != "" {
			refs = append(refs, strings.TrimSpace(path.CredentialProvenance.EvidenceLocation))
		}
	}
	if path.CredentialAuthority != nil {
		refs = append(refs, path.CredentialAuthority.ReasonCodes...)
	}
	for _, binding := range path.AuthorityBindings {
		if binding == nil {
			continue
		}
		refs = append(refs, binding.EvidenceRefs...)
	}
	return dedupeSortedStrings(refs)
}
