package attribution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect/gaitpolicy"
)

type ControlMetadata struct {
	Path                      string   `json:"path"`
	Owner                     string   `json:"owner,omitempty"`
	OwnerSource               string   `json:"owner_source,omitempty"`
	ControlResolutionState    string   `json:"control_resolution_state,omitempty"`
	ControlResolutionReasons  []string `json:"control_resolution_reasons,omitempty"`
	ControlEvidenceRefs       []string `json:"control_evidence_refs,omitempty"`
	ConstraintEvidenceClasses []string `json:"constraint_evidence_classes,omitempty"`
	ConstraintEvidenceRefs    []string `json:"constraint_evidence_refs,omitempty"`
	ConstraintEvidenceStatus  string   `json:"constraint_evidence_status,omitempty"`
	ApprovalEvidenceState     string   `json:"approval_evidence_state,omitempty"`
	OwnerEvidenceState        string   `json:"owner_evidence_state,omitempty"`
	ProofEvidenceState        string   `json:"proof_evidence_state,omitempty"`
	RuntimeEvidenceState      string   `json:"runtime_evidence_state,omitempty"`
	TargetEvidenceState       string   `json:"target_evidence_state,omitempty"`
	CredentialEvidenceState   string   `json:"credential_evidence_state,omitempty"`
	ExternalReferences        []string `json:"external_references,omitempty"`
}

type controlMetadataPayload struct {
	Controls []ControlMetadata `json:"controls"`
}

func loadControlMetadata(repoRoot string) map[string]ControlMetadata {
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
			for _, item := range loadExternalControlMetadata(payload) {
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

			current := byPath[normalizedPath]
			byPath[normalizedPath] = mergeControlMetadata(current, item)
		}
	}
	for _, item := range loadGaitPolicyControlMetadata(repoRoot) {
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

func mergeControlMetadata(current, incoming ControlMetadata) ControlMetadata {
	if strings.TrimSpace(current.Path) == "" {
		return incoming
	}
	current.Owner = firstNonEmptyMetadata(current.Owner, incoming.Owner)
	current.OwnerSource = firstNonEmptyMetadata(current.OwnerSource, incoming.OwnerSource)
	current.ControlResolutionState = firstNonEmptyMetadata(current.ControlResolutionState, incoming.ControlResolutionState)
	current.ControlResolutionReasons = normalizeStringList(append(append([]string(nil), current.ControlResolutionReasons...), incoming.ControlResolutionReasons...))
	current.ControlEvidenceRefs = normalizeStringList(append(append([]string(nil), current.ControlEvidenceRefs...), incoming.ControlEvidenceRefs...))
	current.ConstraintEvidenceClasses = normalizeStringList(append(append([]string(nil), current.ConstraintEvidenceClasses...), incoming.ConstraintEvidenceClasses...))
	current.ConstraintEvidenceRefs = normalizeStringList(append(append([]string(nil), current.ConstraintEvidenceRefs...), incoming.ConstraintEvidenceRefs...))
	current.ConstraintEvidenceStatus = mergeConstraintEvidenceStatus(current.ConstraintEvidenceStatus, incoming.ConstraintEvidenceStatus)
	current.ApprovalEvidenceState = firstNonEmptyMetadata(current.ApprovalEvidenceState, incoming.ApprovalEvidenceState)
	current.OwnerEvidenceState = firstNonEmptyMetadata(current.OwnerEvidenceState, incoming.OwnerEvidenceState)
	current.ProofEvidenceState = firstNonEmptyMetadata(current.ProofEvidenceState, incoming.ProofEvidenceState)
	current.RuntimeEvidenceState = firstNonEmptyMetadata(current.RuntimeEvidenceState, incoming.RuntimeEvidenceState)
	current.TargetEvidenceState = firstNonEmptyMetadata(current.TargetEvidenceState, incoming.TargetEvidenceState)
	current.CredentialEvidenceState = firstNonEmptyMetadata(current.CredentialEvidenceState, incoming.CredentialEvidenceState)
	current.ExternalReferences = normalizeStringList(append(append([]string(nil), current.ExternalReferences...), incoming.ExternalReferences...))
	return current
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
	Repo          string   `json:"repo"`
	Path          string   `json:"path"`
	Workflow      string   `json:"workflow"`
	Location      string   `json:"location"`
	EvidenceClass string   `json:"evidence_class"`
	Status        string   `json:"status"`
	Owner         string   `json:"owner"`
	EvidenceRefs  []string `json:"evidence_refs"`
}

func loadExternalControlMetadata(payload []byte) []ControlMetadata {
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
			ControlResolutionState:   "external_control_reference",
			ControlResolutionReasons: []string{"external_evidence:" + strings.TrimSpace(record.EvidenceClass)},
			ControlEvidenceRefs:      normalizeStringList(record.EvidenceRefs),
			ExternalReferences:       normalizeStringList(record.EvidenceRefs),
			ConstraintEvidenceStatus: normalizeExternalConstraintStatus(record.Status),
		}
		if item.ConstraintEvidenceStatus == "conflict" {
			item.ControlResolutionState = "contradictory_control"
		}
		switch strings.TrimSpace(record.EvidenceClass) {
		case "owner_assignment":
			item.Owner = strings.TrimSpace(record.Owner)
			item.OwnerEvidenceState = externalEvidenceState(record.SourceType, record.Status)
		case "approval", "branch_protection", "protected_environment", "deployment_approval", "required_check", "security_gate":
			item.ApprovalEvidenceState = externalEvidenceState(record.SourceType, record.Status)
		}
		switch strings.TrimSpace(record.EvidenceClass) {
		case "branch_protection", "protected_environment", "deployment_approval", "required_check", "security_gate", "freeze_window", "kill_switch":
			item.ConstraintEvidenceClasses = []string{strings.TrimSpace(record.EvidenceClass)}
			item.ConstraintEvidenceRefs = normalizeStringList(record.EvidenceRefs)
		}
		out = append(out, item)
	}
	return out
}

func externalEvidenceState(sourceType string, status string) string {
	switch normalizeExternalConstraintStatus(status) {
	case "conflict":
		return "contradictory"
	case "stale":
		return "unknown"
	}
	switch strings.TrimSpace(sourceType) {
	case "provider_export", "github_team_export", "backstage_export":
		return "verified"
	default:
		return "declared"
	}
}

func normalizeExternalConstraintStatus(value string) string {
	switch strings.TrimSpace(value) {
	case "matched", "stale", "conflict":
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
	}
	return normalizeExternalConstraintStatus(incoming)
}

func loadGaitPolicyControlMetadata(repoRoot string) []ControlMetadata {
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
			ControlResolutionState:    "declared_control",
			ControlResolutionReasons:  normalizeStringList(reasons),
			ControlEvidenceRefs:       normalizeStringList(refs),
			ConstraintEvidenceClasses: normalizeStringList(classes),
			ConstraintEvidenceRefs:    normalizeStringList(refs),
			ConstraintEvidenceStatus:  "matched",
			ApprovalEvidenceState:     approvalStateFromGaitConstraint(item),
		})
	}
	return out
}

func approvalStateFromGaitConstraint(item gaitpolicy.DeploymentConstraint) string {
	if item.ApprovalRequired || item.Environment != "" || item.Branch != "" {
		return "declared"
	}
	return ""
}
