package attribution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Provenance struct {
	Provider           string                       `json:"provider,omitempty"`
	Kind               string                       `json:"kind,omitempty"`
	Reference          string                       `json:"reference,omitempty"`
	Number             int                          `json:"number,omitempty"`
	Title              string                       `json:"title,omitempty"`
	ProviderURL        string                       `json:"provider_url,omitempty"`
	HeadSHA            string                       `json:"head_sha,omitempty"`
	MergeCommitSHA     string                       `json:"merge_commit_sha,omitempty"`
	Author             string                       `json:"author,omitempty"`
	UpdatedAt          string                       `json:"updated_at,omitempty"`
	BaseBranch         string                       `json:"base_branch,omitempty"`
	HeadBranch         string                       `json:"head_branch,omitempty"`
	MergedBy           string                       `json:"merged_by,omitempty"`
	MergeMethod        string                       `json:"merge_method,omitempty"`
	MergeState         string                       `json:"merge_state,omitempty"`
	ChangedFiles       []string                     `json:"changed_files,omitempty"`
	Reviewers          []ProvenanceActor            `json:"reviewers,omitempty"`
	Approvals          []ProvenanceActor            `json:"approvals,omitempty"`
	Checks             []ProvenanceCheck            `json:"checks,omitempty"`
	Deployments        []ProvenanceDeployment       `json:"deployments,omitempty"`
	BranchProtections  []ProvenanceBranchProtection `json:"branch_protections,omitempty"`
	EnvironmentGates   []ProvenanceEnvironmentGate  `json:"environment_gates,omitempty"`
	ConflictState      string                       `json:"conflict_state,omitempty"`
	MissingEvidence    []string                     `json:"missing_evidence,omitempty"`
	EvidenceRefs       []string                     `json:"evidence_refs,omitempty"`
	AIAssisted         bool                         `json:"ai_assisted,omitempty"`
	AutomationAssisted bool                         `json:"automation_assisted,omitempty"`
}

type ProvenanceActor struct {
	Name        string `json:"name,omitempty"`
	State       string `json:"state,omitempty"`
	Role        string `json:"role,omitempty"`
	ObservedAt  string `json:"observed_at,omitempty"`
	ProviderURL string `json:"provider_url,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

type ProvenanceCheck struct {
	Name        string `json:"name,omitempty"`
	Status      string `json:"status,omitempty"`
	Conclusion  string `json:"conclusion,omitempty"`
	Category    string `json:"category,omitempty"`
	ObservedAt  string `json:"observed_at,omitempty"`
	ProviderURL string `json:"provider_url,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

type ProvenanceDeployment struct {
	Environment string `json:"environment,omitempty"`
	Status      string `json:"status,omitempty"`
	ObservedAt  string `json:"observed_at,omitempty"`
	ProviderURL string `json:"provider_url,omitempty"`
	GateState   string `json:"gate_state,omitempty"`
}

type ProvenanceBranchProtection struct {
	Branch            string   `json:"branch,omitempty"`
	Status            string   `json:"status,omitempty"`
	RequiredApprovals int      `json:"required_approvals,omitempty"`
	RequiredChecks    []string `json:"required_checks,omitempty"`
	EvidenceRefs      []string `json:"evidence_refs,omitempty"`
}

type ProvenanceEnvironmentGate struct {
	Environment       string   `json:"environment,omitempty"`
	Status            string   `json:"status,omitempty"`
	RequiredReviewers []string `json:"required_reviewers,omitempty"`
	DeploymentIDs     []string `json:"deployment_ids,omitempty"`
}

type provenanceBundlePayload struct {
	SchemaVersion string                   `json:"schema_version"`
	GeneratedAt   string                   `json:"generated_at"`
	Entries       []provenanceEntryPayload `json:"entries"`
}

type provenanceEntryPayload struct {
	Provider           string                              `json:"provider"`
	Kind               string                              `json:"kind"`
	Number             int                                 `json:"number"`
	Title              string                              `json:"title"`
	ProviderURL        string                              `json:"provider_url"`
	HeadSHA            string                              `json:"head_sha"`
	MergeCommitSHA     string                              `json:"merge_commit_sha"`
	Author             string                              `json:"author"`
	UpdatedAt          string                              `json:"updated_at"`
	BaseBranch         string                              `json:"base_branch"`
	HeadBranch         string                              `json:"head_branch"`
	MergedBy           string                              `json:"merged_by"`
	MergeMethod        string                              `json:"merge_method"`
	MergeState         string                              `json:"merge_state"`
	ChangedFiles       []string                            `json:"changed_files"`
	Reviewers          []provenanceActorPayload            `json:"reviewers"`
	Approvals          []provenanceActorPayload            `json:"approvals"`
	Checks             []provenanceCheckPayload            `json:"checks"`
	Deployments        []provenanceDeploymentPayload       `json:"deployments"`
	BranchProtections  []provenanceBranchProtectionPayload `json:"branch_protections"`
	EnvironmentGates   []provenanceEnvironmentGatePayload  `json:"environment_gates"`
	EvidenceRefs       []string                            `json:"evidence_refs"`
	AIAssisted         bool                                `json:"ai_assisted"`
	AutomationAssisted bool                                `json:"automation_assisted"`
}

type provenanceActorPayload struct {
	Name        string `json:"name"`
	State       string `json:"state"`
	Role        string `json:"role"`
	ObservedAt  string `json:"observed_at"`
	ProviderURL string `json:"provider_url"`
	Required    bool   `json:"required"`
}

type provenanceCheckPayload struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Conclusion  string `json:"conclusion"`
	Category    string `json:"category"`
	ObservedAt  string `json:"observed_at"`
	ProviderURL string `json:"provider_url"`
	Required    bool   `json:"required"`
}

type provenanceDeploymentPayload struct {
	Environment string `json:"environment"`
	Status      string `json:"status"`
	ObservedAt  string `json:"observed_at"`
	ProviderURL string `json:"provider_url"`
	GateState   string `json:"gate_state"`
}

type provenanceBranchProtectionPayload struct {
	Branch            string   `json:"branch"`
	Status            string   `json:"status"`
	RequiredApprovals int      `json:"required_approvals"`
	RequiredChecks    []string `json:"required_checks"`
	EvidenceRefs      []string `json:"evidence_refs"`
}

type provenanceEnvironmentGatePayload struct {
	Environment       string   `json:"environment"`
	Status            string   `json:"status"`
	RequiredReviewers []string `json:"required_reviewers"`
	DeploymentIDs     []string `json:"deployment_ids"`
}

func CloneProvenance(in *Provenance) *Provenance {
	if in == nil {
		return nil
	}
	out := *in
	out.ChangedFiles = append([]string(nil), in.ChangedFiles...)
	out.Reviewers = append([]ProvenanceActor(nil), in.Reviewers...)
	out.Approvals = append([]ProvenanceActor(nil), in.Approvals...)
	out.Checks = append([]ProvenanceCheck(nil), in.Checks...)
	out.Deployments = append([]ProvenanceDeployment(nil), in.Deployments...)
	out.BranchProtections = append([]ProvenanceBranchProtection(nil), in.BranchProtections...)
	out.EnvironmentGates = append([]ProvenanceEnvironmentGate(nil), in.EnvironmentGates...)
	out.MissingEvidence = append([]string(nil), in.MissingEvidence...)
	out.EvidenceRefs = append([]string(nil), in.EvidenceRefs...)
	return &out
}

func NormalizeProvenance(in *Provenance) *Provenance {
	if in == nil {
		return nil
	}
	out := CloneProvenance(in)
	out.Provider = strings.TrimSpace(out.Provider)
	out.Kind = normalizeKind(out.Kind)
	out.Reference = strings.TrimSpace(out.Reference)
	out.Title = strings.TrimSpace(out.Title)
	out.ProviderURL = strings.TrimSpace(out.ProviderURL)
	out.HeadSHA = strings.TrimSpace(out.HeadSHA)
	out.MergeCommitSHA = strings.TrimSpace(out.MergeCommitSHA)
	out.Author = strings.TrimSpace(out.Author)
	out.UpdatedAt = normalizeMetadataTimestamp(out.UpdatedAt)
	out.BaseBranch = strings.TrimSpace(out.BaseBranch)
	out.HeadBranch = strings.TrimSpace(out.HeadBranch)
	out.MergedBy = strings.TrimSpace(out.MergedBy)
	out.MergeMethod = strings.TrimSpace(out.MergeMethod)
	out.MergeState = strings.TrimSpace(out.MergeState)
	out.ChangedFiles = normalizeChangedFiles(out.ChangedFiles)
	out.Reviewers = normalizeProvenanceActorList(out.Reviewers)
	out.Approvals = normalizeProvenanceActorList(out.Approvals)
	out.Checks = mergeProvenanceChecks(out.Checks, &out.MissingEvidence)
	out.Deployments = mergeProvenanceDeployments(out.Deployments, &out.MissingEvidence)
	out.BranchProtections = mergeProvenanceBranchProtections(out.BranchProtections, &out.MissingEvidence)
	out.EnvironmentGates = mergeProvenanceEnvironmentGates(out.EnvironmentGates, &out.MissingEvidence)
	out.EvidenceRefs = uniqueSortedStrings(out.EvidenceRefs)
	if out.Reference == "" {
		if out.Number > 0 {
			out.Reference = defaultReferenceForKind(out.Kind, out.Number)
		} else {
			out.Reference = fallbackReference(out.Kind, out.ProviderURL, out.Title, out.HeadSHA)
		}
	}
	if len(out.Reviewers) == 0 {
		out.MissingEvidence = append(out.MissingEvidence, "reviewers_missing")
	}
	if len(out.Approvals) == 0 {
		out.MissingEvidence = append(out.MissingEvidence, "approvals_missing")
	}
	if len(out.Checks) == 0 {
		out.MissingEvidence = append(out.MissingEvidence, "checks_missing")
	}
	if len(out.Deployments) == 0 {
		out.MissingEvidence = append(out.MissingEvidence, "deployments_missing")
	}
	if len(out.BranchProtections) == 0 {
		out.MissingEvidence = append(out.MissingEvidence, "branch_protection_missing")
	}
	if len(out.EnvironmentGates) == 0 {
		out.MissingEvidence = append(out.MissingEvidence, "environment_gates_missing")
	}
	out.MissingEvidence = uniqueSortedStrings(out.MissingEvidence)
	out.ConflictState = "none"
	for _, item := range out.MissingEvidence {
		if strings.HasPrefix(item, "conflicting_") {
			out.ConflictState = "conflict"
			break
		}
	}
	if out.ConflictState == "none" && len(out.MissingEvidence) > 0 {
		out.ConflictState = "partial"
	}
	return out
}

func loadProviderProvenanceCandidates(repoRoot string) []Candidate {
	payload, err := os.ReadFile(filepath.Join(repoRoot, ".wrkr", "provenance", "pr-mr-provenance.json")) // #nosec G304 -- deterministic local provenance sidecar under the scanned repo root.
	if err != nil {
		return nil
	}
	if err := ValidateProvenanceJSON(payload); err != nil {
		return nil
	}
	var decoded provenanceBundlePayload
	if json.Unmarshal(payload, &decoded) != nil {
		return nil
	}
	out := make([]Candidate, 0, len(decoded.Entries))
	for _, entry := range decoded.Entries {
		provenance := NormalizeProvenance(&Provenance{
			Provider:           strings.TrimSpace(entry.Provider),
			Kind:               strings.TrimSpace(entry.Kind),
			Number:             entry.Number,
			Title:              strings.TrimSpace(entry.Title),
			ProviderURL:        strings.TrimSpace(entry.ProviderURL),
			HeadSHA:            strings.TrimSpace(entry.HeadSHA),
			MergeCommitSHA:     strings.TrimSpace(entry.MergeCommitSHA),
			Author:             strings.TrimSpace(entry.Author),
			UpdatedAt:          strings.TrimSpace(entry.UpdatedAt),
			BaseBranch:         strings.TrimSpace(entry.BaseBranch),
			HeadBranch:         strings.TrimSpace(entry.HeadBranch),
			MergedBy:           strings.TrimSpace(entry.MergedBy),
			MergeMethod:        strings.TrimSpace(entry.MergeMethod),
			MergeState:         strings.TrimSpace(entry.MergeState),
			ChangedFiles:       normalizeChangedFiles(entry.ChangedFiles),
			Reviewers:          normalizeProvenanceActors(entry.Reviewers),
			Approvals:          normalizeProvenanceActors(entry.Approvals),
			Checks:             normalizeProvenanceChecks(entry.Checks),
			Deployments:        normalizeProvenanceDeployments(entry.Deployments),
			BranchProtections:  normalizeProvenanceBranchProtections(entry.BranchProtections),
			EnvironmentGates:   normalizeProvenanceEnvironmentGates(entry.EnvironmentGates),
			EvidenceRefs:       uniqueSortedStrings(entry.EvidenceRefs),
			AIAssisted:         entry.AIAssisted,
			AutomationAssisted: entry.AutomationAssisted,
		})
		out = append(out, Candidate{
			Source:       SourceProviderProvenance,
			Provider:     strings.TrimSpace(entry.Provider),
			Reference:    strings.TrimSpace(provenance.Reference),
			PRNumber:     entry.Number,
			CommitSHA:    strings.TrimSpace(entry.HeadSHA),
			Author:       strings.TrimSpace(entry.Author),
			Timestamp:    strings.TrimSpace(entry.UpdatedAt),
			ProviderURL:  strings.TrimSpace(entry.ProviderURL),
			ChangedFiles: append([]string(nil), provenance.ChangedFiles...),
			Provenance:   provenance,
		})
	}
	return out
}

func normalizeKind(value string) string {
	switch strings.TrimSpace(value) {
	case "merge_request", "mr":
		return "merge_request"
	default:
		return "pull_request"
	}
}

func fallbackReference(kind, providerURL, title, headSHA string) string {
	raw := strings.TrimSpace(kind) + "|" + strings.TrimSpace(providerURL) + "|" + strings.TrimSpace(title) + "|" + strings.TrimSpace(headSHA)
	sum := sha256.Sum256([]byte(raw))
	return "ref/" + hex.EncodeToString(sum[:6])
}

func normalizeProvenanceActors(in []provenanceActorPayload) []ProvenanceActor {
	out := make([]ProvenanceActor, 0, len(in))
	for _, item := range in {
		out = append(out, ProvenanceActor{
			Name:        strings.TrimSpace(item.Name),
			State:       strings.TrimSpace(item.State),
			Role:        strings.TrimSpace(item.Role),
			ObservedAt:  normalizeMetadataTimestamp(item.ObservedAt),
			ProviderURL: strings.TrimSpace(item.ProviderURL),
			Required:    item.Required,
		})
	}
	return normalizeProvenanceActorList(out)
}

func normalizeProvenanceChecks(in []provenanceCheckPayload) []ProvenanceCheck {
	out := make([]ProvenanceCheck, 0, len(in))
	for _, item := range in {
		out = append(out, ProvenanceCheck{
			Name:        strings.TrimSpace(item.Name),
			Status:      strings.TrimSpace(item.Status),
			Conclusion:  strings.TrimSpace(item.Conclusion),
			Category:    strings.TrimSpace(item.Category),
			ObservedAt:  normalizeMetadataTimestamp(item.ObservedAt),
			ProviderURL: strings.TrimSpace(item.ProviderURL),
			Required:    item.Required,
		})
	}
	return out
}

func normalizeProvenanceDeployments(in []provenanceDeploymentPayload) []ProvenanceDeployment {
	out := make([]ProvenanceDeployment, 0, len(in))
	for _, item := range in {
		out = append(out, ProvenanceDeployment{
			Environment: strings.TrimSpace(item.Environment),
			Status:      strings.TrimSpace(item.Status),
			ObservedAt:  normalizeMetadataTimestamp(item.ObservedAt),
			ProviderURL: strings.TrimSpace(item.ProviderURL),
			GateState:   strings.TrimSpace(item.GateState),
		})
	}
	return out
}

func normalizeProvenanceBranchProtections(in []provenanceBranchProtectionPayload) []ProvenanceBranchProtection {
	out := make([]ProvenanceBranchProtection, 0, len(in))
	for _, item := range in {
		out = append(out, ProvenanceBranchProtection{
			Branch:            strings.TrimSpace(item.Branch),
			Status:            strings.TrimSpace(item.Status),
			RequiredApprovals: item.RequiredApprovals,
			RequiredChecks:    uniqueSortedStrings(item.RequiredChecks),
			EvidenceRefs:      uniqueSortedStrings(item.EvidenceRefs),
		})
	}
	return out
}

func normalizeProvenanceEnvironmentGates(in []provenanceEnvironmentGatePayload) []ProvenanceEnvironmentGate {
	out := make([]ProvenanceEnvironmentGate, 0, len(in))
	for _, item := range in {
		out = append(out, ProvenanceEnvironmentGate{
			Environment:       strings.TrimSpace(item.Environment),
			Status:            strings.TrimSpace(item.Status),
			RequiredReviewers: uniqueSortedStrings(item.RequiredReviewers),
			DeploymentIDs:     uniqueSortedStrings(item.DeploymentIDs),
		})
	}
	return out
}

func normalizeProvenanceActorList(in []ProvenanceActor) []ProvenanceActor {
	if len(in) == 0 {
		return nil
	}
	out := append([]ProvenanceActor(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Role != out[j].Role {
			return out[i].Role < out[j].Role
		}
		if out[i].State != out[j].State {
			return out[i].State < out[j].State
		}
		return out[i].ObservedAt < out[j].ObservedAt
	})
	return out
}

func mergeProvenanceChecks(in []ProvenanceCheck, missing *[]string) []ProvenanceCheck {
	if len(in) == 0 {
		return nil
	}
	byName := map[string]ProvenanceCheck{}
	conflicts := map[string]struct{}{}
	for _, item := range in {
		key := strings.TrimSpace(item.Name)
		if key == "" {
			key = "unnamed_check"
		}
		current, ok := byName[key]
		if !ok {
			byName[key] = item
			continue
		}
		if current.Status != item.Status || current.Conclusion != item.Conclusion {
			conflicts[key] = struct{}{}
			current.Status = "conflict"
			current.Conclusion = "conflict"
		}
		current.Required = current.Required || item.Required
		current.ObservedAt = maxString(current.ObservedAt, item.ObservedAt)
		current.ProviderURL = firstNonEmpty(current.ProviderURL, item.ProviderURL)
		current.Category = firstNonEmpty(current.Category, item.Category)
		byName[key] = current
	}
	for key := range conflicts {
		*missing = append(*missing, "conflicting_check:"+key)
	}
	keys := make([]string, 0, len(byName))
	for key := range byName {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]ProvenanceCheck, 0, len(keys))
	for _, key := range keys {
		out = append(out, byName[key])
	}
	return out
}

func mergeProvenanceDeployments(in []ProvenanceDeployment, missing *[]string) []ProvenanceDeployment {
	if len(in) == 0 {
		return nil
	}
	byEnvironment := map[string]ProvenanceDeployment{}
	conflicts := map[string]struct{}{}
	for _, item := range in {
		key := strings.TrimSpace(item.Environment)
		if key == "" {
			key = "unknown_environment"
		}
		current, ok := byEnvironment[key]
		if !ok {
			byEnvironment[key] = item
			continue
		}
		if current.Status != item.Status || current.GateState != item.GateState {
			conflicts[key] = struct{}{}
			current.Status = "conflict"
		}
		current.ObservedAt = maxString(current.ObservedAt, item.ObservedAt)
		current.ProviderURL = firstNonEmpty(current.ProviderURL, item.ProviderURL)
		current.GateState = firstNonEmpty(current.GateState, item.GateState)
		byEnvironment[key] = current
	}
	for key := range conflicts {
		*missing = append(*missing, "conflicting_deployment:"+key)
	}
	keys := make([]string, 0, len(byEnvironment))
	for key := range byEnvironment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]ProvenanceDeployment, 0, len(keys))
	for _, key := range keys {
		out = append(out, byEnvironment[key])
	}
	return out
}

func mergeProvenanceBranchProtections(in []ProvenanceBranchProtection, missing *[]string) []ProvenanceBranchProtection {
	if len(in) == 0 {
		return nil
	}
	byBranch := map[string]ProvenanceBranchProtection{}
	conflicts := map[string]struct{}{}
	for _, item := range in {
		key := strings.TrimSpace(item.Branch)
		if key == "" {
			key = "unknown_branch"
		}
		current, ok := byBranch[key]
		if !ok {
			byBranch[key] = item
			continue
		}
		if current.Status != item.Status || current.RequiredApprovals != item.RequiredApprovals || strings.Join(current.RequiredChecks, ",") != strings.Join(item.RequiredChecks, ",") {
			conflicts[key] = struct{}{}
			current.Status = "conflict"
		}
		current.RequiredApprovals = maxInt(current.RequiredApprovals, item.RequiredApprovals)
		current.RequiredChecks = uniqueSortedStrings(append(current.RequiredChecks, item.RequiredChecks...))
		current.EvidenceRefs = uniqueSortedStrings(append(current.EvidenceRefs, item.EvidenceRefs...))
		byBranch[key] = current
	}
	for key := range conflicts {
		*missing = append(*missing, "conflicting_branch_protection:"+key)
	}
	keys := make([]string, 0, len(byBranch))
	for key := range byBranch {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]ProvenanceBranchProtection, 0, len(keys))
	for _, key := range keys {
		out = append(out, byBranch[key])
	}
	return out
}

func mergeProvenanceEnvironmentGates(in []ProvenanceEnvironmentGate, missing *[]string) []ProvenanceEnvironmentGate {
	if len(in) == 0 {
		return nil
	}
	byEnvironment := map[string]ProvenanceEnvironmentGate{}
	conflicts := map[string]struct{}{}
	for _, item := range in {
		key := strings.TrimSpace(item.Environment)
		if key == "" {
			key = "unknown_environment"
		}
		current, ok := byEnvironment[key]
		if !ok {
			byEnvironment[key] = item
			continue
		}
		if current.Status != item.Status || strings.Join(current.RequiredReviewers, ",") != strings.Join(item.RequiredReviewers, ",") {
			conflicts[key] = struct{}{}
			current.Status = "conflict"
		}
		current.RequiredReviewers = uniqueSortedStrings(append(current.RequiredReviewers, item.RequiredReviewers...))
		current.DeploymentIDs = uniqueSortedStrings(append(current.DeploymentIDs, item.DeploymentIDs...))
		byEnvironment[key] = current
	}
	for key := range conflicts {
		*missing = append(*missing, "conflicting_environment_gate:"+key)
	}
	keys := make([]string, 0, len(byEnvironment))
	for key := range byEnvironment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]ProvenanceEnvironmentGate, 0, len(keys))
	for _, key := range keys {
		out = append(out, byEnvironment[key])
	}
	return out
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[filepath.ToSlash(trimmed)] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func maxString(current, incoming string) string {
	current = strings.TrimSpace(current)
	incoming = strings.TrimSpace(incoming)
	if incoming > current {
		return incoming
	}
	return current
}

func maxInt(current, incoming int) int {
	if incoming > current {
		return incoming
	}
	return current
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
