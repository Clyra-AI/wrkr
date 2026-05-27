package privilegebudget

import (
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func classifyAuthorityBindings(
	authSurfaces []string,
	signals findingSignals,
	matchedTargets []string,
	deploymentStatus string,
	provenance *agginventory.CredentialProvenance,
	authority *agginventory.CredentialAuthority,
) []*agginventory.AuthorityBinding {
	values := []*agginventory.AuthorityBinding{}
	for _, raw := range signals.EvidenceKV["authority_binding"] {
		if binding := parseAuthorityBinding(raw); binding != nil {
			values = append(values, binding)
		}
	}

	targetSystem, likelyScope, scopeConfidence, reasons := classifyCredentialTargetMetadata(provenance, authSurfaces, signals)
	if targetSystem != "" || likelyScope != "" {
		kind := agginventory.AuthorityBindingSaaSToken
		if isCloudOrInfraSystem(targetSystem) {
			kind = agginventory.AuthorityBindingWorkloadIdentity
		}
		values = append(values, &agginventory.AuthorityBinding{
			Kind:         kind,
			Provider:     bindingProvider(targetSystem),
			Subject:      credentialSubject(provenance),
			TargetSystem: targetSystem,
			LikelyScope:  likelyScope,
			AccessLevel:  bindingAccessForScope(likelyScope, reasons),
			Environment:  firstSignalValue(signals, "workflow_environment"),
			Production:   bindingProduction(matchedTargets, deploymentStatus, signals),
			Confidence:   firstNonEmptyString(scopeConfidence, credentialConfidence(provenance)),
			EvidenceRefs: bindingEvidenceRefs(provenance, signals),
			ReasonCodes:  reasons,
		})
	}

	return agginventory.NormalizeAuthorityBindings(values)
}

func parseAuthorityBinding(raw string) *agginventory.AuthorityBinding {
	parts := strings.Split(strings.TrimSpace(raw), "|")
	if len(parts) < 10 {
		return nil
	}
	return agginventory.NormalizeAuthorityBinding(&agginventory.AuthorityBinding{
		Kind:         parts[0],
		Provider:     parts[1],
		Subject:      parts[2],
		TargetSystem: parts[3],
		Resource:     parts[4],
		LikelyScope:  parts[5],
		AccessLevel:  parts[6],
		Environment:  parts[7],
		Production:   parts[8] == "true",
		Confidence:   parts[9],
		EvidenceRefs: []string{"authority_binding:" + strings.TrimSpace(raw)},
		ReasonCodes:  []string{"binding:" + parts[0]},
	})
}

func decorateCredentialProvenance(
	in *agginventory.CredentialProvenance,
	authSurfaces []string,
	signals findingSignals,
) *agginventory.CredentialProvenance {
	if in == nil {
		return nil
	}
	out := agginventory.CloneCredentialProvenance(in)
	targetSystem, likelyScope, scopeConfidence, reasons := classifyCredentialTargetMetadata(out, authSurfaces, signals)
	out.TargetSystem = firstNonEmptyString(out.TargetSystem, targetSystem)
	out.LikelyScope = firstNonEmptyString(out.LikelyScope, likelyScope)
	out.ScopeConfidence = firstNonEmptyString(out.ScopeConfidence, scopeConfidence, out.Confidence)
	out.ClassificationReasons = mergeSortedEvidence(out.ClassificationReasons, reasons)
	if targetSystem != "" {
		out.EvidenceBasis = mergeSortedEvidence(out.EvidenceBasis, []string{"credential_target_system:" + targetSystem})
	}
	if likelyScope != "" {
		out.EvidenceBasis = mergeSortedEvidence(out.EvidenceBasis, []string{"credential_likely_scope:" + likelyScope})
	}
	return agginventory.NormalizeCredentialProvenance(out)
}

func decorateCredentialAuthority(
	in *agginventory.CredentialAuthority,
	provenance *agginventory.CredentialProvenance,
	authSurfaces []string,
	signals findingSignals,
) *agginventory.CredentialAuthority {
	if in == nil {
		return nil
	}
	out := agginventory.CloneCredentialAuthority(in)
	targetSystem, likelyScope, scopeConfidence, reasons := classifyCredentialTargetMetadata(provenance, authSurfaces, signals)
	out.TargetSystem = firstNonEmptyString(out.TargetSystem, targetSystem)
	out.LikelyScope = firstNonEmptyString(out.LikelyScope, likelyScope)
	out.ScopeConfidence = firstNonEmptyString(out.ScopeConfidence, scopeConfidence, out.Confidence)
	out.ReasonCodes = mergeSortedEvidence(out.ReasonCodes, reasons)
	return agginventory.NormalizeCredentialAuthority(out)
}

func classifyCredentialTargetMetadata(
	provenance *agginventory.CredentialProvenance,
	authSurfaces []string,
	signals findingSignals,
) (string, string, string, []string) {
	parts := []string{credentialSubject(provenance)}
	parts = append(parts, authSurfaces...)
	parts = append(parts, signals.EvidenceKV["credential_subject"]...)
	parts = append(parts, signals.EvidenceKV["workflow_secret_refs"]...)
	parts = append(parts, signals.EvidenceKV["credential_keys"]...)
	text := normalizeToken(strings.Join(parts, ","))
	if text == "" {
		return "", "", "", nil
	}

	type targetMatch struct {
		system     string
		scope      string
		confidence string
		reasons    []string
	}

	for _, candidate := range []struct {
		needles []string
		match   targetMatch
	}{
		{[]string{"slack"}, targetMatch{"slack", "notification_write", "high", []string{"target_system:slack", "scope:notification_write"}}},
		{[]string{"pagerduty", "opsgenie"}, targetMatch{"incident_response", "incident_response", "high", []string{"target_system:incident_response", "scope:incident_response"}}},
		{[]string{"datadog", "sentry", "newrelic", "grafana", "honeycomb"}, targetMatch{"observability", "observability_write", "high", []string{"target_system:observability", "scope:observability_write"}}},
		{[]string{"jira", "atlassian", "linear", "asana"}, targetMatch{"issue_tracking", "issue_tracking_write", "high", []string{"target_system:issue_tracking", "scope:issue_tracking_write"}}},
		{[]string{"github", "gitlab", "bitbucket", "gh_"}, targetMatch{"source_control", "source_control_write", "medium", []string{"target_system:source_control", "scope:source_control_write"}}},
		{[]string{"npm", "pypi", "rubygems", "dockerhub", "ghcr", "package"}, targetMatch{"package_registry", "package_publish", "high", []string{"target_system:package_registry", "scope:package_publish"}}},
		{[]string{"vercel", "netlify", "render", "fly", "railway", "heroku", "argo", "spacelift"}, targetMatch{"deployment_platform", "deploy_write", "high", []string{"target_system:deployment_platform", "scope:deploy_write"}}},
		{[]string{"vault", "doppler", "1password", "secretsmanager", "secret_manager"}, targetMatch{"secrets_manager", "secret_management", "medium", []string{"target_system:secrets_manager", "scope:secret_management"}}},
		{[]string{"aws", "gcp", "azure", "terraform", "cloudformation", "kubernetes", "oidc", "workload_identity"}, targetMatch{bindingProvider(text), "cloud_or_infra_access", "medium", []string{"target_system:" + bindingProvider(text), "scope:cloud_or_infra_access"}}},
	} {
		for _, needle := range candidate.needles {
			if strings.Contains(text, needle) {
				return candidate.match.system, candidate.match.scope, candidate.match.confidence, candidate.match.reasons
			}
		}
	}

	return "", "", "", nil
}

func bindingProvider(value string) string {
	switch {
	case strings.Contains(value, "aws"):
		return "aws"
	case strings.Contains(value, "azure"):
		return "azure"
	case strings.Contains(value, "gcp"), strings.Contains(value, "google"):
		return "gcp"
	case strings.Contains(value, "kubernetes"), strings.Contains(value, "kubectl"), strings.Contains(value, "helm"):
		return "kubernetes"
	case strings.Contains(value, "terraform"):
		return "terraform"
	case strings.Contains(value, "cloudformation"):
		return "cloudformation"
	default:
		return ""
	}
}

func bindingAccessForScope(scope string, reasons []string) string {
	switch {
	case strings.Contains(scope, "admin"):
		return agginventory.AuthorityAccessAdmin
	case strings.Contains(scope, "read"):
		return agginventory.AuthorityAccessRead
	case strings.Contains(scope, "write"), strings.Contains(scope, "publish"), strings.Contains(scope, "deploy"), strings.Contains(scope, "incident"), strings.Contains(scope, "notification"), strings.Contains(scope, "management"):
		return agginventory.AuthorityAccessWrite
	default:
		for _, reason := range reasons {
			if strings.Contains(reason, "admin") {
				return agginventory.AuthorityAccessAdmin
			}
		}
		return agginventory.AuthorityAccessUnknown
	}
}

func bindingProduction(matchedTargets []string, deploymentStatus string, signals findingSignals) bool {
	if len(matchedTargets) > 0 || strings.EqualFold(strings.TrimSpace(deploymentStatus), "deployed") {
		return true
	}
	for _, value := range append(signals.EvidenceKV["workflow_environment"], signals.EvidenceKV["target_class_hint"]...) {
		if strings.Contains(value, "prod") || strings.Contains(value, "production") || strings.Contains(value, "live") {
			return true
		}
	}
	return false
}

func bindingEvidenceRefs(provenance *agginventory.CredentialProvenance, signals findingSignals) []string {
	refs := []string{}
	if provenance != nil {
		refs = append(refs, provenance.EvidenceBasis...)
		if strings.TrimSpace(provenance.EvidenceLocation) != "" {
			refs = append(refs, provenance.EvidenceLocation)
		}
	}
	if location := credentialEvidenceLocation(signals); strings.TrimSpace(location) != "" {
		refs = append(refs, location)
	}
	return dedupeSorted(refs)
}

func credentialSubject(provenance *agginventory.CredentialProvenance) string {
	if provenance == nil {
		return ""
	}
	return strings.TrimSpace(provenance.Subject)
}

func credentialConfidence(provenance *agginventory.CredentialProvenance) string {
	if provenance == nil {
		return ""
	}
	return strings.TrimSpace(provenance.Confidence)
}

func isCloudOrInfraSystem(system string) bool {
	switch strings.TrimSpace(system) {
	case "aws", "azure", "gcp", "kubernetes", "terraform", "cloudformation":
		return true
	default:
		return false
	}
}
