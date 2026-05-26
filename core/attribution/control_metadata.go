package attribution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/config"
	"github.com/Clyra-AI/wrkr/core/detect/gaitpolicy"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
)

type ControlMetadata struct {
	Path                      string                    `json:"path"`
	Owner                     string                    `json:"owner,omitempty"`
	OwnerSource               string                    `json:"owner_source,omitempty"`
	ControlResolutionState    string                    `json:"control_resolution_state,omitempty"`
	ControlResolutionReasons  []string                  `json:"control_resolution_reasons,omitempty"`
	ControlEvidenceRefs       []string                  `json:"control_evidence_refs,omitempty"`
	ConstraintEvidenceClasses []string                  `json:"constraint_evidence_classes,omitempty"`
	ConstraintEvidenceRefs    []string                  `json:"constraint_evidence_refs,omitempty"`
	ConstraintEvidenceStatus  string                    `json:"constraint_evidence_status,omitempty"`
	ApprovalEvidenceState     string                    `json:"approval_evidence_state,omitempty"`
	OwnerEvidenceState        string                    `json:"owner_evidence_state,omitempty"`
	ProofEvidenceState        string                    `json:"proof_evidence_state,omitempty"`
	RuntimeEvidenceState      string                    `json:"runtime_evidence_state,omitempty"`
	TargetEvidenceState       string                    `json:"target_evidence_state,omitempty"`
	CredentialEvidenceState   string                    `json:"credential_evidence_state,omitempty"`
	ExternalReferences        []string                  `json:"external_references,omitempty"`
	TargetClass               string                    `json:"target_class,omitempty"`
	TargetClassReasons        []string                  `json:"target_class_reasons,omitempty"`
	TargetClassEvidenceRefs   []string                  `json:"target_class_evidence_refs,omitempty"`
	EvidenceDecisions         []evidencepolicy.Decision `json:"evidence_decisions,omitempty"`
}

type controlMetadataPayload struct {
	Controls []ControlMetadata `json:"controls"`
}

func ResolveControlMetadata(byPath map[string]ControlMetadata, location string) (ControlMetadata, bool) {
	if len(byPath) == 0 {
		return ControlMetadata{}, false
	}
	location = filepath.ToSlash(strings.TrimSpace(location))
	if location == "" {
		return ControlMetadata{}, false
	}
	keys := make([]string, 0, len(byPath))
	for key := range byPath {
		keys = append(keys, filepath.ToSlash(strings.TrimSpace(key)))
	}
	sort.Slice(keys, func(i, j int) bool {
		leftExact := keys[i] == location
		rightExact := keys[j] == location
		if leftExact != rightExact {
			return leftExact
		}
		return keys[i] < keys[j]
	})

	matched := ControlMetadata{}
	found := false
	for _, key := range keys {
		meta, ok := byPath[key]
		if !ok || !controlMetadataPatternMatches(key, location) {
			continue
		}
		matched = mergeControlMetadata(matched, meta)
		found = true
	}
	if !found {
		return ControlMetadata{}, false
	}
	return matched, true
}

func loadControlMetadataAt(repoRoot string, generatedAt time.Time) map[string]ControlMetadata {
	if strings.TrimSpace(repoRoot) == "" {
		return nil
	}

	files := []string{
		filepath.Join(repoRoot, ".wrkr", "provenance", "control-metadata.json"),
		filepath.Join(repoRoot, ".wrkr", "provenance", "control-declarations.json"),
		filepath.Join(repoRoot, ".wrkr", "provenance", "external-control-evidence.json"),
	}
	byPath := map[string]ControlMetadata{}
	for _, path := range files {
		payload, err := os.ReadFile(path) // #nosec G304 -- deterministic local control metadata sidecar under the scanned repo root.
		if err != nil {
			continue
		}
		if strings.HasSuffix(path, "external-control-evidence.json") {
			for _, item := range loadExternalControlMetadata(payload, generatedAt) {
				normalizedPath := filepath.ToSlash(strings.TrimSpace(item.Path))
				if normalizedPath == "" {
					continue
				}
				current := byPath[normalizedPath]
				byPath[normalizedPath] = mergeControlMetadata(current, item)
			}
			continue
		}
		var decoded controlMetadataPayload
		if json.Unmarshal(payload, &decoded) != nil {
			continue
		}
		for _, item := range decoded.Controls {
			normalizedPath := filepath.ToSlash(strings.TrimSpace(item.Path))
			if normalizedPath == "" {
				continue
			}
			item.Path = normalizedPath
			item.Owner = strings.TrimSpace(item.Owner)
			item.OwnerSource = strings.TrimSpace(item.OwnerSource)
			item.ControlResolutionState = strings.TrimSpace(item.ControlResolutionState)
			item.ControlResolutionReasons = normalizeStringList(item.ControlResolutionReasons)
			item.ControlEvidenceRefs = normalizeStringList(item.ControlEvidenceRefs)
			item.ConstraintEvidenceClasses = normalizeStringList(item.ConstraintEvidenceClasses)
			item.ConstraintEvidenceRefs = normalizeStringList(item.ConstraintEvidenceRefs)
			item.ConstraintEvidenceStatus = strings.TrimSpace(item.ConstraintEvidenceStatus)
			item.ApprovalEvidenceState = strings.TrimSpace(item.ApprovalEvidenceState)
			item.OwnerEvidenceState = strings.TrimSpace(item.OwnerEvidenceState)
			item.ProofEvidenceState = strings.TrimSpace(item.ProofEvidenceState)
			item.RuntimeEvidenceState = strings.TrimSpace(item.RuntimeEvidenceState)
			item.TargetEvidenceState = strings.TrimSpace(item.TargetEvidenceState)
			item.CredentialEvidenceState = strings.TrimSpace(item.CredentialEvidenceState)
			item.ExternalReferences = normalizeStringList(item.ExternalReferences)
			item.TargetClass = strings.TrimSpace(item.TargetClass)
			item.TargetClassReasons = normalizeStringList(item.TargetClassReasons)
			item.TargetClassEvidenceRefs = normalizeStringList(item.TargetClassEvidenceRefs)

			current := byPath[normalizedPath]
			byPath[normalizedPath] = mergeControlMetadata(current, item)
		}
	}
	for _, item := range loadDeclaredControlMetadata(repoRoot, generatedAt) {
		normalizedPath := filepath.ToSlash(strings.TrimSpace(item.Path))
		if normalizedPath == "" {
			continue
		}
		current := byPath[normalizedPath]
		byPath[normalizedPath] = mergeControlMetadata(current, item)
	}
	for _, item := range loadGaitPolicyControlMetadata(repoRoot, generatedAt) {
		normalizedPath := filepath.ToSlash(strings.TrimSpace(item.Path))
		if normalizedPath == "" {
			continue
		}
		current := byPath[normalizedPath]
		byPath[normalizedPath] = mergeControlMetadata(current, item)
	}
	if len(byPath) == 0 {
		return nil
	}
	return byPath
}

func controlMetadataPatternMatches(pattern, location string) bool {
	pattern = strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(pattern)), "/")
	location = strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(location)), "/")
	if pattern == "" || location == "" {
		return false
	}
	if pattern == "*" || pattern == location {
		return true
	}
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(location, strings.TrimSuffix(pattern, "/"))
	}
	if strings.Contains(pattern, "*") {
		ok, err := filepath.Match(pattern, location)
		return err == nil && ok
	}
	return strings.HasSuffix(location, pattern)
}

func mergeControlMetadata(current, incoming ControlMetadata) ControlMetadata {
	if strings.TrimSpace(current.Path) == "" {
		return finalizeControlMetadata(incoming)
	}
	current.Path = firstNonEmptyMetadata(current.Path, incoming.Path)
	current.ControlResolutionReasons = normalizeStringList(append(append([]string(nil), current.ControlResolutionReasons...), incoming.ControlResolutionReasons...))
	current.ControlEvidenceRefs = normalizeStringList(append(append([]string(nil), current.ControlEvidenceRefs...), incoming.ControlEvidenceRefs...))
	current.ConstraintEvidenceClasses = normalizeStringList(append(append([]string(nil), current.ConstraintEvidenceClasses...), incoming.ConstraintEvidenceClasses...))
	current.ConstraintEvidenceRefs = normalizeStringList(append(append([]string(nil), current.ConstraintEvidenceRefs...), incoming.ConstraintEvidenceRefs...))
	current.ConstraintEvidenceStatus = mergeConstraintEvidenceStatus(current.ConstraintEvidenceStatus, incoming.ConstraintEvidenceStatus)
	current.ProofEvidenceState = firstNonEmptyMetadata(current.ProofEvidenceState, incoming.ProofEvidenceState)
	current.RuntimeEvidenceState = firstNonEmptyMetadata(current.RuntimeEvidenceState, incoming.RuntimeEvidenceState)
	current.TargetEvidenceState = firstNonEmptyMetadata(current.TargetEvidenceState, incoming.TargetEvidenceState)
	current.CredentialEvidenceState = firstNonEmptyMetadata(current.CredentialEvidenceState, incoming.CredentialEvidenceState)
	current.ExternalReferences = normalizeStringList(append(append([]string(nil), current.ExternalReferences...), incoming.ExternalReferences...))
	current.TargetClassReasons = normalizeStringList(append(append([]string(nil), current.TargetClassReasons...), incoming.TargetClassReasons...))
	current.TargetClassEvidenceRefs = normalizeStringList(append(append([]string(nil), current.TargetClassEvidenceRefs...), incoming.TargetClassEvidenceRefs...))
	current.EvidenceDecisions = mergeEvidenceDecisions(current.EvidenceDecisions, incoming.EvidenceDecisions)
	current.TargetClass = firstNonEmptyMetadata(current.TargetClass, incoming.TargetClass)
	return finalizeControlMetadata(current)
}

func finalizeControlMetadata(meta ControlMetadata) ControlMetadata {
	if decision, ok := decisionForField(meta.EvidenceDecisions, evidencepolicy.FieldOwner); ok {
		meta.Owner = strings.TrimSpace(decision.SelectedValue)
		meta.OwnerSource = strings.TrimSpace(decision.SelectedSourceType)
		meta.OwnerEvidenceState = decisionEvidenceState(decision, evidencepolicy.FieldOwner)
		if decision.SelectedFreshnessState == evidencepolicy.FreshnessStateExpired || decision.SelectedFreshnessState == evidencepolicy.FreshnessStateStale {
			meta.OwnerEvidenceState = "unknown"
		}
		meta.ControlEvidenceRefs = normalizeStringList(append(meta.ControlEvidenceRefs, decisionEvidenceRefs(decision)...))
		if strings.TrimSpace(decision.ConflictState) == evidencepolicy.ConflictStateAmbiguous {
			meta.ControlResolutionState = "contradictory_control"
		}
	}
	if decision, ok := decisionForField(meta.EvidenceDecisions, evidencepolicy.FieldApproval); ok {
		meta.ApprovalEvidenceState = decisionEvidenceState(decision, evidencepolicy.FieldApproval)
		if decision.SelectedFreshnessState == evidencepolicy.FreshnessStateExpired || decision.SelectedFreshnessState == evidencepolicy.FreshnessStateStale {
			meta.ApprovalEvidenceState = "unknown"
			meta.ControlResolutionReasons = normalizeStringList(append(meta.ControlResolutionReasons, "approval_evidence:"+decision.SelectedFreshnessState))
		}
		meta.ControlEvidenceRefs = normalizeStringList(append(meta.ControlEvidenceRefs, decisionEvidenceRefs(decision)...))
		if strings.TrimSpace(decision.ConflictState) == evidencepolicy.ConflictStateAmbiguous {
			meta.ControlResolutionState = "contradictory_control"
		}
	}
	if decision, ok := decisionForField(meta.EvidenceDecisions, evidencepolicy.FieldConstraint); ok {
		meta.ConstraintEvidenceRefs = normalizeStringList(append(meta.ConstraintEvidenceRefs, decisionEvidenceRefs(decision)...))
		switch {
		case strings.TrimSpace(decision.ConflictState) == evidencepolicy.ConflictStateAmbiguous:
			meta.ConstraintEvidenceStatus = "conflict"
			meta.ControlResolutionState = "contradictory_control"
		case decision.SelectedFreshnessState == evidencepolicy.FreshnessStateExpired || decision.SelectedFreshnessState == evidencepolicy.FreshnessStateStale:
			meta.ConstraintEvidenceStatus = "stale"
		case strings.TrimSpace(meta.ConstraintEvidenceStatus) == "":
			meta.ConstraintEvidenceStatus = "matched"
		}
	}
	if decision, ok := decisionForField(meta.EvidenceDecisions, evidencepolicy.FieldTarget); ok {
		meta.TargetClass = strings.TrimSpace(decision.SelectedValue)
		meta.TargetClassReasons = normalizeStringList(append(meta.TargetClassReasons, decision.ReasonCodes...))
		meta.TargetClassEvidenceRefs = normalizeStringList(append(meta.TargetClassEvidenceRefs, decisionEvidenceRefs(decision)...))
	}
	if strings.TrimSpace(meta.ControlResolutionState) == "" {
		for _, decision := range meta.EvidenceDecisions {
			switch strings.TrimSpace(decision.SelectedSourceType) {
			case evidencepolicy.SourceTypeProviderExport, evidencepolicy.SourceTypeGitHubTeamExport, evidencepolicy.SourceTypeBackstageExport, evidencepolicy.SourceTypeTicketExport:
				meta.ControlResolutionState = "external_control_reference"
			case evidencepolicy.SourceTypeSignedDeclaration, evidencepolicy.SourceTypeRepoPolicy, evidencepolicy.SourceTypePolicyConfig:
				if strings.TrimSpace(meta.ControlResolutionState) == "" {
					meta.ControlResolutionState = "declared_control"
				}
			}
		}
	}
	return meta
}

func decisionForField(decisions []evidencepolicy.Decision, field string) (evidencepolicy.Decision, bool) {
	for _, item := range decisions {
		if strings.TrimSpace(item.Field) == strings.TrimSpace(field) {
			return item, true
		}
	}
	return evidencepolicy.Decision{}, false
}

func decisionEvidenceRefs(decision evidencepolicy.Decision) []string {
	values := append([]string(nil), decision.SelectedEvidenceRefs...)
	for _, item := range decision.RejectedCandidates {
		values = append(values, item.EvidenceRefs...)
	}
	return normalizeStringList(values)
}

func decisionEvidenceState(decision evidencepolicy.Decision, field string) string {
	switch strings.TrimSpace(decision.SelectedStatus) {
	case "unmatched":
		return "unknown"
	case "conflict":
		return "contradictory"
	}
	switch strings.TrimSpace(field) {
	case evidencepolicy.FieldOwner:
		switch evidencepolicy.NormalizeSourceType(decision.SelectedSourceType) {
		case evidencepolicy.SourceTypeSignedDeclaration, evidencepolicy.SourceTypeCustomerOwnerMap:
			return "declared"
		case evidencepolicy.SourceTypeGitHubMetadata, evidencepolicy.SourceTypeRepoFallback:
			return "inferred"
		default:
			return "verified"
		}
	default:
		switch evidencepolicy.NormalizeSourceType(decision.SelectedSourceType) {
		case evidencepolicy.SourceTypeProviderExport, evidencepolicy.SourceTypeGitHubTeamExport, evidencepolicy.SourceTypeBackstageExport, evidencepolicy.SourceTypeTicketExport:
			return "verified"
		case evidencepolicy.SourceTypeGitHubMetadata, evidencepolicy.SourceTypeRepoFallback:
			return "inferred"
		default:
			return "declared"
		}
	}
}

func mergeEvidenceDecisions(current, incoming []evidencepolicy.Decision) []evidencepolicy.Decision {
	if len(current) == 0 && len(incoming) == 0 {
		return nil
	}
	byField := map[string][]evidencepolicy.Candidate{}
	for _, item := range append(append([]evidencepolicy.Decision(nil), current...), incoming...) {
		field := strings.TrimSpace(item.Field)
		if field == "" {
			continue
		}
		byField[field] = append(byField[field], decisionCandidates(item)...)
	}
	out := make([]evidencepolicy.Decision, 0, len(byField))
	for field, candidates := range byField {
		decision := evidencepolicy.ResolveDecision(candidates, time.Time{})
		decision.Field = field
		out = append(out, cloneDecision(decision))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

func decisionCandidates(decision evidencepolicy.Decision) []evidencepolicy.Candidate {
	out := []evidencepolicy.Candidate{{
		Field:          decision.Field,
		Value:          decision.SelectedValue,
		SourceType:     decision.SelectedSourceType,
		Source:         decision.SelectedSource,
		EvidenceRefs:   normalizeStringList(append([]string(nil), decision.SelectedEvidenceRefs...)),
		ObservedAt:     decision.SelectedObservedAt,
		ValidUntil:     decision.SelectedValidUntil,
		MaxAge:         decision.SelectedMaxAge,
		Issuer:         decision.SelectedIssuer,
		Confidence:     decision.SelectedConfidence,
		FreshnessState: decision.SelectedFreshnessState,
		Status:         decision.SelectedStatus,
		ReasonCodes:    normalizeStringList(append([]string(nil), decision.ReasonCodes...)),
	}}
	for _, item := range decision.RejectedCandidates {
		copyItem := item
		copyItem.Field = decision.Field
		out = append(out, copyItem)
	}
	return out
}

func cloneDecision(in evidencepolicy.Decision) evidencepolicy.Decision {
	out := in
	out.SelectedEvidenceRefs = normalizeStringList(append([]string(nil), in.SelectedEvidenceRefs...))
	out.ReasonCodes = normalizeStringList(append([]string(nil), in.ReasonCodes...))
	out.ConflictReasonCodes = normalizeStringList(append([]string(nil), in.ConflictReasonCodes...))
	if len(in.RejectedCandidates) > 0 {
		out.RejectedCandidates = make([]evidencepolicy.Candidate, 0, len(in.RejectedCandidates))
		for _, item := range in.RejectedCandidates {
			copyItem := item
			copyItem.EvidenceRefs = normalizeStringList(append([]string(nil), item.EvidenceRefs...))
			copyItem.ReasonCodes = normalizeStringList(append([]string(nil), item.ReasonCodes...))
			out.RejectedCandidates = append(out.RejectedCandidates, copyItem)
		}
	}
	return out
}

func normalizeStringList(values []string) []string {
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

func firstNonEmptyMetadata(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

type externalControlEvidencePayload struct {
	SchemaVersion string                          `json:"schema_version"`
	Records       []externalControlEvidenceRecord `json:"records"`
}

type externalControlEvidenceRecord struct {
	RecordKind    string   `json:"record_kind"`
	SourceType    string   `json:"source_type"`
	Source        string   `json:"source"`
	Repo          string   `json:"repo"`
	Path          string   `json:"path"`
	Workflow      string   `json:"workflow"`
	Location      string   `json:"location"`
	ObservedAt    string   `json:"observed_at"`
	ValidUntil    string   `json:"valid_until"`
	MaxAge        string   `json:"max_age"`
	Issuer        string   `json:"issuer"`
	Confidence    string   `json:"confidence"`
	EvidenceClass string   `json:"evidence_class"`
	Status        string   `json:"status"`
	Owner         string   `json:"owner"`
	EvidenceRefs  []string `json:"evidence_refs"`
}

func loadExternalControlMetadata(payload []byte, generatedAt time.Time) []ControlMetadata {
	var decoded externalControlEvidencePayload
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil
	}
	if strings.TrimSpace(decoded.SchemaVersion) != "" && strings.TrimSpace(decoded.SchemaVersion) != "v1" {
		return nil
	}
	out := make([]ControlMetadata, 0, len(decoded.Records))
	for _, record := range decoded.Records {
		if strings.TrimSpace(record.RecordKind) != "external_control" {
			continue
		}
		path := filepath.ToSlash(firstNonEmptyMetadata(record.Path, record.Workflow, record.Location))
		if path == "" {
			continue
		}
		item := ControlMetadata{
			Path:                     path,
			ControlResolutionReasons: []string{"external_evidence:" + strings.TrimSpace(record.EvidenceClass)},
			ControlEvidenceRefs:      normalizeStringList(record.EvidenceRefs),
			ExternalReferences:       normalizeStringList(record.EvidenceRefs),
			ConstraintEvidenceStatus: normalizeExternalConstraintStatus(record.Status),
		}
		switch strings.TrimSpace(record.EvidenceClass) {
		case "owner_assignment":
			item.EvidenceDecisions = append(item.EvidenceDecisions, evidencepolicy.ResolveDecision([]evidencepolicy.Candidate{{
				Field:        evidencepolicy.FieldOwner,
				Value:        strings.TrimSpace(record.Owner),
				SourceType:   strings.TrimSpace(record.SourceType),
				Source:       strings.TrimSpace(record.Source),
				EvidenceRefs: normalizeStringList(record.EvidenceRefs),
				ObservedAt:   strings.TrimSpace(record.ObservedAt),
				ValidUntil:   strings.TrimSpace(record.ValidUntil),
				MaxAge:       strings.TrimSpace(record.MaxAge),
				Issuer:       strings.TrimSpace(record.Issuer),
				Confidence:   strings.TrimSpace(record.Confidence),
				Status:       strings.TrimSpace(record.Status),
			}}, generatedAt))
		case "approval", "branch_protection", "protected_environment", "deployment_approval", "required_check", "security_gate":
			item.EvidenceDecisions = append(item.EvidenceDecisions, evidencepolicy.ResolveDecision([]evidencepolicy.Candidate{{
				Field:        evidencepolicy.FieldApproval,
				Value:        strings.TrimSpace(record.EvidenceClass),
				SourceType:   strings.TrimSpace(record.SourceType),
				Source:       strings.TrimSpace(record.Source),
				EvidenceRefs: normalizeStringList(record.EvidenceRefs),
				ObservedAt:   strings.TrimSpace(record.ObservedAt),
				ValidUntil:   strings.TrimSpace(record.ValidUntil),
				MaxAge:       strings.TrimSpace(record.MaxAge),
				Issuer:       strings.TrimSpace(record.Issuer),
				Confidence:   strings.TrimSpace(record.Confidence),
				Status:       strings.TrimSpace(record.Status),
			}}, generatedAt))
		}
		switch strings.TrimSpace(record.EvidenceClass) {
		case "branch_protection", "protected_environment", "deployment_approval", "required_check", "security_gate", "freeze_window", "kill_switch":
			item.ConstraintEvidenceClasses = []string{strings.TrimSpace(record.EvidenceClass)}
			item.ConstraintEvidenceRefs = normalizeStringList(record.EvidenceRefs)
			item.EvidenceDecisions = append(item.EvidenceDecisions, evidencepolicy.ResolveDecision([]evidencepolicy.Candidate{{
				Field:        evidencepolicy.FieldConstraint,
				Value:        strings.TrimSpace(record.EvidenceClass),
				SourceType:   strings.TrimSpace(record.SourceType),
				Source:       strings.TrimSpace(record.Source),
				EvidenceRefs: normalizeStringList(record.EvidenceRefs),
				ObservedAt:   strings.TrimSpace(record.ObservedAt),
				ValidUntil:   strings.TrimSpace(record.ValidUntil),
				MaxAge:       strings.TrimSpace(record.MaxAge),
				Issuer:       strings.TrimSpace(record.Issuer),
				Confidence:   strings.TrimSpace(record.Confidence),
				Status:       strings.TrimSpace(record.Status),
			}}, generatedAt))
		}
		out = append(out, item)
	}
	return out
}

func normalizeExternalConstraintStatus(value string) string {
	switch strings.TrimSpace(value) {
	case "matched", "unmatched", "stale", "conflict":
		return strings.TrimSpace(value)
	default:
		return "matched"
	}
}

func mergeConstraintEvidenceStatus(current, incoming string) string {
	switch normalizeExternalConstraintStatus(current) {
	case "conflict":
		return "conflict"
	case "stale":
		if normalizeExternalConstraintStatus(incoming) == "conflict" {
			return "conflict"
		}
		return "stale"
	case "unmatched":
		switch normalizeExternalConstraintStatus(incoming) {
		case "conflict", "stale", "matched":
			return normalizeExternalConstraintStatus(incoming)
		default:
			return "unmatched"
		}
	}
	return normalizeExternalConstraintStatus(incoming)
}

func loadGaitPolicyControlMetadata(repoRoot string, generatedAt time.Time) []ControlMetadata {
	constraints, err := gaitpolicy.LoadDeploymentConstraints(repoRoot)
	if err != nil || len(constraints) == 0 {
		return nil
	}
	out := make([]ControlMetadata, 0, len(constraints))
	for _, item := range constraints {
		path := filepath.ToSlash(firstNonEmptyMetadata(item.Workflow, item.Path))
		if path == "" {
			continue
		}
		reasons := []string{}
		classes := []string{}
		refs := []string{}
		if item.Branch != "" {
			classes = append(classes, "branch_protection")
			reasons = append(reasons, "gait_constraint:branch_protection")
			refs = append(refs, item.PolicyPath+"#branch="+item.Branch)
		}
		if len(item.RequiredChecks) > 0 {
			classes = append(classes, "required_check")
			reasons = append(reasons, "gait_constraint:required_check")
			for _, check := range item.RequiredChecks {
				refs = append(refs, item.PolicyPath+"#required_check="+check)
			}
		}
		if len(item.SecurityGates) > 0 {
			classes = append(classes, "security_gate")
			reasons = append(reasons, "gait_constraint:security_gate")
			for _, gate := range item.SecurityGates {
				refs = append(refs, item.PolicyPath+"#security_gate="+gate)
			}
		}
		if len(item.FreezeWindows) > 0 {
			classes = append(classes, "freeze_window")
			reasons = append(reasons, "gait_constraint:freeze_window")
			for _, freeze := range item.FreezeWindows {
				refs = append(refs, item.PolicyPath+"#freeze_window="+freeze)
			}
		}
		if len(item.KillSwitches) > 0 {
			classes = append(classes, "kill_switch")
			reasons = append(reasons, "gait_constraint:kill_switch")
			for _, kill := range item.KillSwitches {
				refs = append(refs, item.PolicyPath+"#kill_switch="+kill)
			}
		}
		if item.Environment != "" {
			classes = append(classes, "protected_environment")
			reasons = append(reasons, "gait_constraint:protected_environment")
			refs = append(refs, item.PolicyPath+"#environment="+item.Environment)
		}
		if item.ApprovalRequired {
			classes = append(classes, "deployment_approval")
			reasons = append(reasons, "gait_constraint:deployment_approval")
			refs = append(refs, item.PolicyPath+"#approval_required")
		}
		if len(classes) == 0 {
			continue
		}
		out = append(out, ControlMetadata{
			Path:                      path,
			ControlResolutionReasons:  normalizeStringList(reasons),
			ControlEvidenceRefs:       normalizeStringList(refs),
			ConstraintEvidenceClasses: normalizeStringList(classes),
			ConstraintEvidenceRefs:    normalizeStringList(refs),
			ConstraintEvidenceStatus:  "matched",
			EvidenceDecisions: append(
				[]evidencepolicy.Decision{},
				evidencepolicy.ResolveDecision([]evidencepolicy.Candidate{{
					Field:        evidencepolicy.FieldApproval,
					Value:        approvalStateFromGaitConstraint(item),
					SourceType:   evidencepolicy.SourceTypeRepoPolicy,
					Source:       item.PolicyPath,
					EvidenceRefs: normalizeStringList(refs),
					Status:       "matched",
				}}, generatedAt),
				evidencepolicy.ResolveDecision([]evidencepolicy.Candidate{{
					Field:        evidencepolicy.FieldConstraint,
					Value:        strings.Join(normalizeStringList(classes), ","),
					SourceType:   evidencepolicy.SourceTypeRepoPolicy,
					Source:       item.PolicyPath,
					EvidenceRefs: normalizeStringList(refs),
					Status:       "matched",
				}}, generatedAt),
			),
		})
	}
	return out
}

func loadDeclaredControlMetadata(repoRoot string, generatedAt time.Time) []ControlMetadata {
	doc, paths, err := config.LoadControlDeclarations(repoRoot)
	if err != nil || len(paths) == 0 {
		return nil
	}
	out := []ControlMetadata{}
	for _, item := range doc.Owners {
		for _, path := range declarationPaths(item.Path, item.Pattern, item.Paths) {
			out = append(out, ControlMetadata{
				Path: path,
				EvidenceDecisions: []evidencepolicy.Decision{
					evidencepolicy.ResolveDecision([]evidencepolicy.Candidate{{
						Field:        evidencepolicy.FieldOwner,
						Value:        strings.TrimSpace(item.Owner),
						SourceType:   evidencepolicy.SourceTypeSignedDeclaration,
						Source:       strings.Join(paths, "|"),
						EvidenceRefs: normalizeStringList(item.EvidenceRefs),
						ObservedAt:   strings.TrimSpace(item.ObservedAt),
						ValidUntil:   strings.TrimSpace(item.ValidUntil),
						MaxAge:       strings.TrimSpace(item.MaxAge),
						Issuer:       firstNonEmptyMetadata(item.Issuer, doc.Issuer),
						Confidence:   strings.TrimSpace(item.Confidence),
					}}, generatedAt),
				},
			})
		}
	}
	for _, item := range doc.Targets {
		for _, path := range declarationPaths(item.Path, item.Pattern, item.Paths) {
			targetValue := strings.TrimSpace(item.TargetClass)
			if item.NonProduction && targetValue == "" {
				targetValue = "test_demo_sandbox"
			}
			out = append(out, ControlMetadata{
				Path: path,
				EvidenceDecisions: []evidencepolicy.Decision{
					evidencepolicy.ResolveDecision([]evidencepolicy.Candidate{{
						Field:        evidencepolicy.FieldTarget,
						Value:        targetValue,
						SourceType:   evidencepolicy.SourceTypeSignedDeclaration,
						Source:       strings.Join(paths, "|"),
						EvidenceRefs: normalizeStringList(item.EvidenceRefs),
						ObservedAt:   strings.TrimSpace(item.ObservedAt),
						ValidUntil:   strings.TrimSpace(item.ValidUntil),
						MaxAge:       strings.TrimSpace(item.MaxAge),
						Issuer:       firstNonEmptyMetadata(item.Issuer, doc.Issuer),
						Confidence:   strings.TrimSpace(item.Confidence),
						ReasonCodes:  normalizeStringList([]string{"declaration:target_class", nonProductionReason(item.NonProduction)}),
					}}, generatedAt),
				},
			})
		}
	}
	for _, item := range doc.Controls {
		path := filepath.ToSlash(firstNonEmptyMetadata(item.Workflow, item.Path))
		if path == "" {
			continue
		}
		refs := normalizeStringList(item.EvidenceRefs)
		classes := []string{}
		if strings.TrimSpace(item.Branch) != "" {
			classes = append(classes, "branch_protection")
		}
		if strings.TrimSpace(item.Environment) != "" {
			classes = append(classes, "protected_environment")
		}
		if item.ApprovalRequired {
			classes = append(classes, "deployment_approval")
		}
		if len(item.RequiredChecks) > 0 {
			classes = append(classes, "required_check")
		}
		if len(item.SecurityGates) > 0 {
			classes = append(classes, "security_gate")
		}
		if len(item.FreezeWindows) > 0 {
			classes = append(classes, "freeze_window")
		}
		if len(item.KillSwitches) > 0 {
			classes = append(classes, "kill_switch")
		}
		out = append(out, ControlMetadata{
			Path:                      path,
			ConstraintEvidenceClasses: normalizeStringList(classes),
			ConstraintEvidenceRefs:    refs,
			EvidenceDecisions: []evidencepolicy.Decision{
				evidencepolicy.ResolveDecision([]evidencepolicy.Candidate{{
					Field:        evidencepolicy.FieldApproval,
					Value:        firstNonEmptyMetadata(boolDecisionValue(item.ApprovalRequired), strings.TrimSpace(item.Environment), strings.TrimSpace(item.Branch)),
					SourceType:   evidencepolicy.SourceTypeSignedDeclaration,
					Source:       strings.Join(paths, "|"),
					EvidenceRefs: refs,
					ObservedAt:   strings.TrimSpace(item.ObservedAt),
					ValidUntil:   strings.TrimSpace(item.ValidUntil),
					MaxAge:       strings.TrimSpace(item.MaxAge),
					Issuer:       firstNonEmptyMetadata(item.Issuer, doc.Issuer),
					Confidence:   strings.TrimSpace(item.Confidence),
				}}, generatedAt),
				evidencepolicy.ResolveDecision([]evidencepolicy.Candidate{{
					Field:        evidencepolicy.FieldConstraint,
					Value:        strings.Join(normalizeStringList(classes), ","),
					SourceType:   evidencepolicy.SourceTypeSignedDeclaration,
					Source:       strings.Join(paths, "|"),
					EvidenceRefs: refs,
					ObservedAt:   strings.TrimSpace(item.ObservedAt),
					ValidUntil:   strings.TrimSpace(item.ValidUntil),
					MaxAge:       strings.TrimSpace(item.MaxAge),
					Issuer:       firstNonEmptyMetadata(item.Issuer, doc.Issuer),
					Confidence:   strings.TrimSpace(item.Confidence),
				}}, generatedAt),
			},
		})
	}
	return out
}

func declarationPaths(pathValue, pattern string, values []string) []string {
	out := normalizeStringList(append(append([]string(nil), values...), pathValue, pattern))
	if len(out) == 0 {
		return nil
	}
	return out
}

func nonProductionReason(value bool) string {
	if value {
		return "declaration:non_production"
	}
	return ""
}

func boolDecisionValue(value bool) string {
	if value {
		return "approval_required"
	}
	return ""
}

func approvalStateFromGaitConstraint(item gaitpolicy.DeploymentConstraint) string {
	if item.ApprovalRequired || item.Environment != "" || item.Branch != "" {
		return "declared"
	}
	return ""
}
