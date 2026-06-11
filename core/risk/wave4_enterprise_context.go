package risk

import "strings"

type AgentIdentity struct {
	IdentityKey        string `json:"identity_key"`
	AgentID            string `json:"agent_id,omitempty"`
	HumanOwner         string `json:"human_owner,omitempty"`
	OwnerSource        string `json:"owner_source,omitempty"`
	DelegatedAuthority string `json:"delegated_authority,omitempty"`
	RuntimeProvider    string `json:"runtime_provider,omitempty"`
	RuntimeKind        string `json:"runtime_kind,omitempty"`
	ModelProvider      string `json:"model_provider,omitempty"`
	CredentialUsed     string `json:"credential_used,omitempty"`
	Scope              string `json:"scope,omitempty"`
	EvidenceState      string `json:"evidence_state,omitempty"`
}

type DecisionPrecedent struct {
	PrecedentKey     string   `json:"precedent_key,omitempty"`
	DecisionTraceRef string   `json:"decision_trace_ref,omitempty"`
	PriorDecision    string   `json:"prior_decision,omitempty"`
	DecisionSource   string   `json:"decision_source,omitempty"`
	DecisionAgeDays  int      `json:"decision_age_days,omitempty"`
	Confidence       string   `json:"confidence,omitempty"`
	ExpiresAt        string   `json:"expires_at,omitempty"`
	Status           string   `json:"status,omitempty"`
	EvidenceRefs     []string `json:"evidence_refs,omitempty"`
	ReasonCodes      []string `json:"reason_codes,omitempty"`
}

type DeliveryControlContext struct {
	Scope                  string   `json:"scope,omitempty"`
	Harnesses              []string `json:"harnesses,omitempty"`
	ResolverRefs           []string `json:"resolver_refs,omitempty"`
	EvalConfigRefs         []string `json:"eval_config_refs,omitempty"`
	DryRunRequired         bool     `json:"dry_run_required,omitempty"`
	SandboxGates           []string `json:"sandbox_gates,omitempty"`
	TestGates              []string `json:"test_gates,omitempty"`
	ValidationRequirements []string `json:"validation_requirements,omitempty"`
}

func CloneAgentIdentity(in *AgentIdentity) *AgentIdentity {
	if in == nil {
		return nil
	}
	out := *in
	out.IdentityKey = strings.TrimSpace(out.IdentityKey)
	out.AgentID = strings.TrimSpace(out.AgentID)
	out.HumanOwner = strings.TrimSpace(out.HumanOwner)
	out.OwnerSource = strings.TrimSpace(out.OwnerSource)
	out.DelegatedAuthority = strings.TrimSpace(out.DelegatedAuthority)
	out.RuntimeProvider = strings.TrimSpace(out.RuntimeProvider)
	out.RuntimeKind = strings.TrimSpace(out.RuntimeKind)
	out.ModelProvider = strings.TrimSpace(out.ModelProvider)
	out.CredentialUsed = strings.TrimSpace(out.CredentialUsed)
	out.Scope = strings.TrimSpace(out.Scope)
	out.EvidenceState = strings.TrimSpace(out.EvidenceState)
	return &out
}

func CloneDecisionPrecedent(in *DecisionPrecedent) *DecisionPrecedent {
	if in == nil {
		return nil
	}
	out := *in
	out.PrecedentKey = strings.TrimSpace(out.PrecedentKey)
	out.DecisionTraceRef = strings.TrimSpace(out.DecisionTraceRef)
	out.PriorDecision = strings.TrimSpace(out.PriorDecision)
	out.DecisionSource = strings.TrimSpace(out.DecisionSource)
	out.Confidence = strings.TrimSpace(out.Confidence)
	out.ExpiresAt = strings.TrimSpace(out.ExpiresAt)
	out.Status = strings.TrimSpace(out.Status)
	out.EvidenceRefs = dedupeSortedStrings(out.EvidenceRefs)
	out.ReasonCodes = dedupeSortedStrings(out.ReasonCodes)
	return &out
}

func CloneDeliveryControlContext(in *DeliveryControlContext) *DeliveryControlContext {
	if in == nil {
		return nil
	}
	out := *in
	out.Scope = strings.TrimSpace(out.Scope)
	out.Harnesses = dedupeSortedStrings(out.Harnesses)
	out.ResolverRefs = dedupeSortedStrings(out.ResolverRefs)
	out.EvalConfigRefs = dedupeSortedStrings(out.EvalConfigRefs)
	out.SandboxGates = dedupeSortedStrings(out.SandboxGates)
	out.TestGates = dedupeSortedStrings(out.TestGates)
	out.ValidationRequirements = dedupeSortedStrings(out.ValidationRequirements)
	return &out
}

func buildAgentIdentity(path ActionPath) *AgentIdentity {
	identityKey := strings.TrimSpace(path.AgentID)
	if identityKey == "" {
		return nil
	}
	evidenceState := "verified"
	if strings.TrimSpace(path.RuntimeContextEvidenceState) == "contradictory" ||
		strings.TrimSpace(path.RuntimeEvidenceState) == EvidenceStateContradictory ||
		strings.TrimSpace(path.OwnerEvidenceState) == EvidenceStateContradictory ||
		strings.TrimSpace(path.CredentialEvidenceState) == EvidenceStateContradictory {
		evidenceState = EvidenceStateContradictory
	} else if strings.TrimSpace(path.RuntimeContextEvidenceState) == "" &&
		strings.TrimSpace(path.OwnerEvidenceState) == EvidenceStateUnknown &&
		strings.TrimSpace(path.CredentialEvidenceState) == EvidenceStateUnknown {
		evidenceState = EvidenceStateUnknown
	}
	modelProvider := strings.TrimSpace(path.ModelProvider)
	if modelProvider == "" {
		modelProvider = strings.TrimSpace(path.RuntimeProvider)
	}
	return &AgentIdentity{
		IdentityKey:        identityKey,
		AgentID:            identityKey,
		HumanOwner:         strings.TrimSpace(path.OperationalOwner),
		OwnerSource:        strings.TrimSpace(path.OwnerSource),
		DelegatedAuthority: delegatedAuthorityLabel(path),
		RuntimeProvider:    strings.TrimSpace(path.RuntimeProvider),
		RuntimeKind:        strings.TrimSpace(path.RuntimeKind),
		ModelProvider:      modelProvider,
		CredentialUsed:     credentialUsedLabel(path),
		Scope:              identityScope(path),
		EvidenceState:      evidenceState,
	}
}

func delegatedAuthorityLabel(path ActionPath) string {
	if path.CredentialAuthority != nil {
		parts := []string{}
		if kind := strings.TrimSpace(path.CredentialAuthority.CredentialKind); kind != "" {
			parts = append(parts, kind)
		}
		if target := strings.TrimSpace(path.CredentialAuthority.TargetSystem); target != "" {
			parts = append(parts, target)
		}
		if scope := strings.TrimSpace(path.CredentialAuthority.LikelyScope); scope != "" {
			parts = append(parts, scope)
		}
		return strings.Join(dedupeSortedStrings(parts), " ")
	}
	if path.CredentialProvenance != nil {
		parts := []string{}
		if kind := strings.TrimSpace(path.CredentialProvenance.CredentialKind); kind != "" {
			parts = append(parts, kind)
		}
		if target := strings.TrimSpace(path.CredentialProvenance.TargetSystem); target != "" {
			parts = append(parts, target)
		}
		if scope := strings.TrimSpace(path.CredentialProvenance.LikelyScope); scope != "" {
			parts = append(parts, scope)
		}
		return strings.Join(dedupeSortedStrings(parts), " ")
	}
	return ""
}

func credentialUsedLabel(path ActionPath) string {
	if path.CredentialAuthority != nil {
		if kind := strings.TrimSpace(path.CredentialAuthority.CredentialKind); kind != "" {
			return kind
		}
	}
	if path.CredentialProvenance != nil {
		if kind := strings.TrimSpace(path.CredentialProvenance.CredentialKind); kind != "" {
			return kind
		}
	}
	if path.CredentialAccess {
		return "credential_access_present"
	}
	return ""
}

func identityScope(path ActionPath) string {
	if path.CredentialAuthority != nil && strings.TrimSpace(path.CredentialAuthority.LikelyScope) != "" {
		return strings.TrimSpace(path.CredentialAuthority.LikelyScope)
	}
	if path.CredentialProvenance != nil && strings.TrimSpace(path.CredentialProvenance.Scope) != "" {
		return strings.TrimSpace(path.CredentialProvenance.Scope)
	}
	if len(path.MatchedProductionTargets) > 0 {
		return strings.Join(path.MatchedProductionTargets, ",")
	}
	return strings.TrimSpace(path.Repo)
}

func buildDeliveryControlContext(path ActionPath) *DeliveryControlContext {
	harnesses := dedupeSortedStrings(path.DeliveryHarnesses)
	resolvers := dedupeSortedStrings(path.ResolverRefs)
	evals := dedupeSortedStrings(path.EvalConfigRefs)
	sandbox := dedupeSortedStrings(path.SandboxGates)
	tests := dedupeSortedStrings(path.TestGates)
	requirements := dedupeSortedStrings(path.ValidationRequirements)
	if len(harnesses) == 0 && len(resolvers) == 0 && len(evals) == 0 && len(sandbox) == 0 && len(tests) == 0 && len(requirements) == 0 && !path.DryRunRequired {
		return nil
	}
	return &DeliveryControlContext{
		Scope:                  "detection_only",
		Harnesses:              harnesses,
		ResolverRefs:           resolvers,
		EvalConfigRefs:         evals,
		DryRunRequired:         path.DryRunRequired,
		SandboxGates:           sandbox,
		TestGates:              tests,
		ValidationRequirements: requirements,
	}
}

func agentIdentityRank(in *AgentIdentity) int {
	if in == nil {
		return 0
	}
	score := 0
	if strings.TrimSpace(in.HumanOwner) != "" {
		score += 3
	}
	if strings.TrimSpace(in.DelegatedAuthority) != "" {
		score += 3
	}
	if strings.TrimSpace(in.RuntimeProvider) != "" {
		score += 2
	}
	if strings.TrimSpace(in.CredentialUsed) != "" {
		score += 2
	}
	if strings.TrimSpace(in.Scope) != "" {
		score += 1
	}
	return score
}

func normalizeRuntimeContextEvidenceState(value string) string {
	switch strings.TrimSpace(value) {
	case EvidenceStateVerified, EvidenceStateUnknown, EvidenceStateContradictory:
		return strings.TrimSpace(value)
	default:
		return ""
	}
}

func firstNonNilAgentIdentity(current, incoming *AgentIdentity) *AgentIdentity {
	switch {
	case current == nil:
		return incoming
	case incoming == nil:
		return current
	case agentIdentityRank(incoming) > agentIdentityRank(current):
		return incoming
	default:
		return current
	}
}

func mergeDeliveryControlContext(current, incoming *DeliveryControlContext) *DeliveryControlContext {
	if current == nil {
		return CloneDeliveryControlContext(incoming)
	}
	if incoming == nil {
		return CloneDeliveryControlContext(current)
	}
	merged := *current
	merged.Scope = firstNonEmptyString(current.Scope, incoming.Scope)
	merged.Harnesses = dedupeSortedStrings(append(append([]string(nil), current.Harnesses...), incoming.Harnesses...))
	merged.ResolverRefs = dedupeSortedStrings(append(append([]string(nil), current.ResolverRefs...), incoming.ResolverRefs...))
	merged.EvalConfigRefs = dedupeSortedStrings(append(append([]string(nil), current.EvalConfigRefs...), incoming.EvalConfigRefs...))
	merged.DryRunRequired = current.DryRunRequired || incoming.DryRunRequired
	merged.SandboxGates = dedupeSortedStrings(append(append([]string(nil), current.SandboxGates...), incoming.SandboxGates...))
	merged.TestGates = dedupeSortedStrings(append(append([]string(nil), current.TestGates...), incoming.TestGates...))
	merged.ValidationRequirements = dedupeSortedStrings(append(append([]string(nil), current.ValidationRequirements...), incoming.ValidationRequirements...))
	return &merged
}

func firstNonNilDecisionPrecedent(current, incoming *DecisionPrecedent) *DecisionPrecedent {
	switch {
	case current == nil:
		return incoming
	case incoming == nil:
		return current
	case strings.TrimSpace(incoming.Status) == "active" && strings.TrimSpace(current.Status) != "active":
		return incoming
	default:
		return current
	}
}

func runtimeContextEvidenceStateFromValues(values ...string) string {
	normalized := []string{}
	for _, value := range values {
		if trimmed := normalizeRuntimeContextEvidenceState(value); trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}
	normalized = dedupeSortedStrings(normalized)
	switch {
	case stringSliceContains(normalized, EvidenceStateContradictory):
		return EvidenceStateContradictory
	case stringSliceContains(normalized, EvidenceStateVerified):
		return EvidenceStateVerified
	case stringSliceContains(normalized, EvidenceStateUnknown):
		return EvidenceStateUnknown
	default:
		return ""
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(want) {
			return true
		}
	}
	return false
}
