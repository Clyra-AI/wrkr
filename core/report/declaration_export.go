package report

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	"github.com/Clyra-AI/wrkr/core/config"
	"github.com/Clyra-AI/wrkr/core/resolution"
	"github.com/Clyra-AI/wrkr/core/risk"
	"gopkg.in/yaml.v3"
)

const (
	DeclarationExportModeRepoLocal      = "repo_local"
	DeclarationExportModeGovernanceRepo = "governance_repo"
)

type DeclarationSnippet struct {
	Mode                   string   `json:"mode"`
	TargetPath             string   `json:"target_path"`
	ActionType             string   `json:"action_type"`
	DeclarationKind        string   `json:"declaration_kind"`
	ReviewDispositionState string   `json:"review_disposition_state,omitempty"`
	CorrelationKind        string   `json:"correlation_kind,omitempty"`
	DirectlyApplicable     bool     `json:"directly_applicable"`
	Warnings               []string `json:"warnings,omitempty"`
	Content                string   `json:"content"`
}

type declarationExportSource struct {
	PathID                   string
	ResolutionKey            string
	ResolutionSelector       *resolution.Selector
	SourceFindingKeys        []string
	Repo                     string
	Location                 string
	Owner                    string
	TargetClass              string
	TargetEvidenceState      string
	ReviewScope              string
	ReviewOwner              string
	ReviewSource             string
	ReviewRationale          string
	ReviewObservedAt         string
	ReviewValidUntil         string
	ReviewEvidenceRefs       []string
	ControlEvidenceRefs      []string
	PolicyEvidenceRefs       []string
	ProductionWrite          bool
	MatchedProductionTargets []string
	ClosureActions           []risk.ClosureAction
}

func BuildDeclarationSnippetFromBOM(item AgentActionBOMItem, shareProfile ShareProfile, actionType string, mode string, generatedAt time.Time) (DeclarationSnippet, error) {
	return buildDeclarationSnippet(declarationExportSource{
		PathID:                   strings.TrimSpace(item.PathID),
		ResolutionKey:            strings.TrimSpace(item.ResolutionKey),
		ResolutionSelector:       resolution.CloneSelector(item.ResolutionSelector),
		SourceFindingKeys:        append([]string(nil), item.SourceFindingKeys...),
		Repo:                     strings.TrimSpace(item.Repo),
		Location:                 strings.TrimSpace(item.Location),
		Owner:                    firstNonEmptyValue(strings.TrimSpace(item.Owner), strings.TrimSpace(item.ReviewOwner)),
		TargetClass:              strings.TrimSpace(item.TargetClass),
		TargetEvidenceState:      strings.TrimSpace(item.TargetEvidenceState),
		ReviewScope:              strings.TrimSpace(item.ReviewScope),
		ReviewOwner:              strings.TrimSpace(item.ReviewOwner),
		ReviewSource:             strings.TrimSpace(item.ReviewSource),
		ReviewRationale:          strings.TrimSpace(item.ReviewRationale),
		ReviewObservedAt:         strings.TrimSpace(item.ReviewObservedAt),
		ReviewValidUntil:         strings.TrimSpace(item.ReviewValidUntil),
		ReviewEvidenceRefs:       reviewAuditContextEvidenceRefs(item.ReviewAuditContext),
		ControlEvidenceRefs:      append([]string(nil), item.ControlEvidenceRefs...),
		PolicyEvidenceRefs:       append([]string(nil), item.PolicyEvidenceRefs...),
		ProductionWrite:          item.ProductionWrite,
		MatchedProductionTargets: append([]string(nil), item.MatchedProductionTargets...),
		ClosureActions:           risk.CloneClosureActions(item.ClosureActions),
	}, shareProfile, actionType, mode, generatedAt)
}

func BuildDeclarationSnippetFromBacklog(item controlbacklog.Item, shareProfile ShareProfile, actionType string, mode string, generatedAt time.Time) (DeclarationSnippet, error) {
	return buildDeclarationSnippet(declarationExportSource{
		PathID:              strings.TrimSpace(item.LinkedActionPathID),
		ResolutionKey:       strings.TrimSpace(item.ResolutionKey),
		ResolutionSelector:  resolution.CloneSelector(item.ResolutionSelector),
		Repo:                strings.TrimSpace(item.Repo),
		Location:            strings.TrimSpace(item.Path),
		Owner:               firstNonEmptyValue(strings.TrimSpace(item.Owner), strings.TrimSpace(item.ReviewOwner)),
		TargetClass:         strings.TrimSpace(item.TargetClass),
		TargetEvidenceState: strings.TrimSpace(item.TargetEvidenceState),
		ReviewScope:         strings.TrimSpace(item.ReviewScope),
		ReviewOwner:         strings.TrimSpace(item.ReviewOwner),
		ReviewSource:        strings.TrimSpace(item.ReviewSource),
		ReviewRationale:     strings.TrimSpace(item.ReviewRationale),
		ReviewObservedAt:    strings.TrimSpace(item.ReviewObservedAt),
		ReviewValidUntil:    strings.TrimSpace(item.ReviewValidUntil),
		ReviewEvidenceRefs:  reviewAuditContextEvidenceRefs(item.ReviewAuditContext),
		ControlEvidenceRefs: append([]string(nil), item.ControlEvidenceRefs...),
		PolicyEvidenceRefs:  append([]string(nil), item.PolicyEvidenceRefs...),
		ProductionWrite:     strings.TrimSpace(item.TargetClass) == risk.TargetClassProductionImpacting || strings.TrimSpace(item.TargetClass) == risk.TargetClassReleaseAdjacent,
		ClosureActions:      risk.CloneClosureActions(item.ClosureActions),
	}, shareProfile, actionType, mode, generatedAt)
}

func buildDeclarationSnippet(source declarationExportSource, shareProfile ShareProfile, actionType string, mode string, generatedAt time.Time) (DeclarationSnippet, error) {
	mode = normalizeDeclarationExportMode(mode)
	if mode == "" {
		mode = DeclarationExportModeRepoLocal
	}
	action, err := selectDeclarationClosureAction(source.ClosureActions, actionType)
	if err != nil {
		return DeclarationSnippet{}, err
	}

	directlyApplicable := true
	warnings := []string{}
	shareableProfile := shareProfile != ShareProfileInternal
	if shareableProfile {
		switch strings.TrimSpace(action.DeclarationKind) {
		case risk.ClosureActionDeclarationKindOwner, risk.ClosureActionDeclarationKindTarget:
			directlyApplicable = false
			warnings = append(warnings, "shareable artifacts pseudonymize repo and path fields; use an internal artifact or saved state to generate a directly applicable declaration")
		case risk.ClosureActionDeclarationKindReviewDisposition:
			if strings.TrimSpace(source.ResolutionKey) == "" && !resolution.HasSelectorFields(firstSelectorValue(source.ResolutionSelector)) {
				directlyApplicable = false
				warnings = append(warnings, "shareable artifacts without a resolution_key or selector fallback cannot emit a directly applicable review disposition")
			}
		}
	}

	doc, correlationKind := declarationDocumentForAction(source, action, mode, shareableProfile, generatedAt)
	if err := config.ValidateControlDeclarations(doc); err != nil {
		return DeclarationSnippet{}, fmt.Errorf("build declaration snippet: %w", err)
	}
	payload, err := yaml.Marshal(doc)
	if err != nil {
		return DeclarationSnippet{}, fmt.Errorf("marshal declaration snippet: %w", err)
	}

	return DeclarationSnippet{
		Mode:                   mode,
		TargetPath:             declarationTargetPath(mode),
		ActionType:             strings.TrimSpace(action.ActionType),
		DeclarationKind:        strings.TrimSpace(action.DeclarationKind),
		ReviewDispositionState: strings.TrimSpace(action.ReviewDispositionState),
		CorrelationKind:        correlationKind,
		DirectlyApplicable:     directlyApplicable,
		Warnings:               dedupeSortedStrings(warnings),
		Content:                string(payload),
	}, nil
}

func declarationDocumentForAction(source declarationExportSource, action risk.ClosureAction, mode string, shareable bool, generatedAt time.Time) (config.ControlDeclarations, string) {
	doc := config.ControlDeclarations{
		SchemaVersion: config.ControlDeclarationsVersion,
		Issuer:        firstNonEmptyValue(strings.TrimSpace(source.ReviewSource), "customer_review_export"),
	}
	switch strings.TrimSpace(action.DeclarationKind) {
	case risk.ClosureActionDeclarationKindOwner:
		doc.Owners = []config.ControlDeclarationOwner{{
			Repo:         scopedRepoForMode(source.Repo, mode, shareable),
			Path:         scopedPathValue(source.Location, shareable),
			Owner:        firstNonEmptyValue(redactedSafeValue(source.Owner, "owner-review-required", shareable), "owner-review-required"),
			ObservedAt:   declarationObservedAt(firstNonEmptyValue(source.ReviewObservedAt, generatedAt.Format(time.RFC3339))),
			EvidenceRefs: ownerEvidenceRefs(source),
			Issuer:       firstNonEmptyValue(strings.TrimSpace(source.ReviewOwner), "customer-review-owner"),
		}}
		return doc, "repo_path"
	case risk.ClosureActionDeclarationKindTarget:
		doc.Targets = []config.ControlDeclarationTarget{{
			Repo:          scopedRepoForMode(source.Repo, mode, shareable),
			Path:          scopedPathValue(source.Location, shareable),
			TargetClass:   declarationTargetClass(source.TargetClass),
			NonProduction: true,
			ObservedAt:    declarationObservedAt(firstNonEmptyValue(source.ReviewObservedAt, generatedAt.Format(time.RFC3339))),
			EvidenceRefs:  targetEvidenceRefs(source),
			Issuer:        firstNonEmptyValue(strings.TrimSpace(source.ReviewOwner), "customer-review-owner"),
		}}
		return doc, "repo_path"
	default:
		disposition, correlationKind := reviewDispositionForAction(source, action, mode, shareable, generatedAt)
		doc.ReviewDispositions = []config.ControlDeclarationReviewDisposition{disposition}
		return doc, correlationKind
	}
}

func reviewDispositionForAction(source declarationExportSource, action risk.ClosureAction, mode string, shareable bool, generatedAt time.Time) (config.ControlDeclarationReviewDisposition, string) {
	observedAt := declarationObservedAt(firstNonEmptyValue(source.ReviewObservedAt, generatedAt.Format(time.RFC3339)))
	scope := declarationScope(source)
	rationale := firstNonEmptyValue(source.ReviewRationale, defaultReviewRationale(action))
	out := config.ControlDeclarationReviewDisposition{
		State:        strings.TrimSpace(action.ReviewDispositionState),
		Source:       firstNonEmptyValue(strings.TrimSpace(source.ReviewSource), "customer_review"),
		Issuer:       firstNonEmptyValue(strings.TrimSpace(source.ReviewOwner), "customer-review-owner"),
		Rationale:    redactedSafeValue(rationale, defaultReviewRationale(action), shareable),
		ObservedAt:   observedAt,
		Scope:        scope,
		EvidenceRefs: reviewDispositionEvidenceRefs(source, action),
	}
	if strings.TrimSpace(action.ReviewDispositionState) == risk.ReviewLifecycleStateAcceptedRisk {
		out.ValidUntil = declarationObservedAt(generatedAt.Add(90 * 24 * time.Hour).Format(time.RFC3339))
	} else if strings.TrimSpace(source.ReviewValidUntil) != "" {
		out.ValidUntil = declarationObservedAt(source.ReviewValidUntil)
	}
	if resolutionKey := strings.TrimSpace(source.ResolutionKey); resolutionKey != "" {
		out.ResolutionKey = resolutionKey
		return out, "resolution_key"
	}
	if selector := reviewDispositionSelector(source, mode, shareable); resolution.HasSelectorFields(selector) {
		out.Selector = selector
		return out, "selector"
	}
	if pathID := strings.TrimSpace(source.PathID); pathID != "" {
		out.PathID = pathID
		return out, "path_id"
	}
	if len(source.SourceFindingKeys) > 0 {
		out.FindingKey = strings.TrimSpace(source.SourceFindingKeys[0])
		return out, "finding_key"
	}
	return out, ""
}

func selectDeclarationClosureAction(actions []risk.ClosureAction, actionType string) (risk.ClosureAction, error) {
	trimmed := strings.TrimSpace(actionType)
	if trimmed != "" {
		for _, action := range actions {
			if strings.TrimSpace(action.ActionType) == trimmed {
				if strings.TrimSpace(action.DeclarationKind) == "" {
					return risk.ClosureAction{}, fmt.Errorf("closure action %q is not declaration-capable", trimmed)
				}
				return action, nil
			}
		}
		return risk.ClosureAction{}, fmt.Errorf("closure action %q was not found on the selected item", trimmed)
	}
	for _, action := range actions {
		if strings.TrimSpace(action.DeclarationKind) != "" {
			return action, nil
		}
	}
	return risk.ClosureAction{}, fmt.Errorf("selected item does not expose a declaration-capable closure action")
}

func normalizeDeclarationExportMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case DeclarationExportModeGovernanceRepo:
		return DeclarationExportModeGovernanceRepo
	case "", DeclarationExportModeRepoLocal:
		return DeclarationExportModeRepoLocal
	default:
		return ""
	}
}

func declarationTargetPath(mode string) string {
	if normalizeDeclarationExportMode(mode) == DeclarationExportModeGovernanceRepo {
		return "wrkr-control-declarations.yaml"
	}
	return filepath.ToSlash(filepath.Join(".wrkr", "control-declarations.yaml"))
}

func declarationObservedAt(value string) string {
	if strings.TrimSpace(value) == "" {
		return "2026-06-25T00:00:00Z"
	}
	return strings.TrimSpace(value)
}

func reviewDispositionSelector(source declarationExportSource, mode string, shareable bool) resolution.Selector {
	selector := resolution.NormalizeSelector(firstSelectorValue(source.ResolutionSelector))
	if strings.TrimSpace(selector.Repo) == "" && normalizeDeclarationExportMode(mode) == DeclarationExportModeGovernanceRepo {
		selector.Repo = scopedRepoForMode(source.Repo, mode, shareable)
	}
	if len(selector.Locations) == 0 {
		location := scopedPathValue(source.Location, shareable)
		if location != "" {
			selector.Locations = []string{location}
		}
	}
	if strings.TrimSpace(selector.TargetClass) == "" && strings.TrimSpace(source.TargetClass) != "" {
		selector.TargetClass = strings.TrimSpace(source.TargetClass)
	}
	return selector
}

func declarationScope(source declarationExportSource) string {
	if strings.TrimSpace(source.ReviewScope) != "" {
		return strings.TrimSpace(source.ReviewScope)
	}
	if source.ProductionWrite || len(source.MatchedProductionTargets) > 0 {
		return "production"
	}
	return "non_production"
}

func declarationTargetClass(value string) string {
	switch strings.TrimSpace(value) {
	case "":
		return "developer_productivity"
	default:
		return strings.TrimSpace(value)
	}
}

func defaultReviewRationale(action risk.ClosureAction) string {
	switch strings.TrimSpace(action.ActionType) {
	case risk.ClosureActionAcceptRiskWithExpiry:
		return "Operator reviewed the path and accepted the remaining risk for a bounded period."
	case risk.ClosureActionMarkNotApplicable:
		return "Operator reviewed the path and confirmed the finding is not applicable in its current scope."
	case risk.ClosureActionMarkFalsePositive:
		return "Operator reviewed the path and confirmed the finding was a false positive."
	case risk.ClosureActionRequestRuntimeEvidence:
		return "Operator reviewed the path and needs runtime evidence before making a stronger control claim."
	case risk.ClosureActionConfirmReviewedPath:
		return "Operator reviewed and confirmed the path context for future reruns."
	default:
		return "Operator reviewed the path and recorded the current control context."
	}
}

func ownerEvidenceRefs(source declarationExportSource) []string {
	return firstNonEmptyStringSlice(
		supportedEvidenceRefs(append(append([]string(nil), source.ControlEvidenceRefs...), source.ReviewEvidenceRefs...)),
		[]string{"evidence://todo/owner-review"},
	)
}

func targetEvidenceRefs(source declarationExportSource) []string {
	return firstNonEmptyStringSlice(
		supportedEvidenceRefs(append(append([]string(nil), source.ControlEvidenceRefs...), source.PolicyEvidenceRefs...)),
		[]string{"evidence://todo/target-scope-review"},
	)
}

func reviewDispositionEvidenceRefs(source declarationExportSource, action risk.ClosureAction) []string {
	values := supportedEvidenceRefs(append(append(append([]string(nil), source.ReviewEvidenceRefs...), source.ControlEvidenceRefs...), source.PolicyEvidenceRefs...))
	if len(values) > 0 {
		return values
	}
	switch strings.TrimSpace(action.ActionType) {
	case risk.ClosureActionAcceptRiskWithExpiry:
		return []string{"evidence://todo/accepted-risk-review"}
	case risk.ClosureActionRequestRuntimeEvidence:
		return []string{"evidence://todo/runtime-evidence-request"}
	default:
		return []string{"evidence://todo/customer-review"}
	}
}

func firstNonEmptyStringSlice(value []string, fallback []string) []string {
	if len(value) > 0 {
		return value
	}
	return append([]string(nil), fallback...)
}

func supportedEvidenceRefs(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		switch {
		case strings.HasPrefix(trimmed, "evidence://"),
			strings.HasPrefix(trimmed, "proof://"),
			strings.HasPrefix(trimmed, "policy://"),
			strings.HasPrefix(trimmed, "file://"):
			out = append(out, trimmed)
		}
	}
	return uniqueSortedStrings(out)
}

func scopedRepoForMode(repo string, mode string, shareable bool) string {
	repo = redactedSafeValue(strings.TrimSpace(repo), "repo-review-required", shareable)
	if normalizeDeclarationExportMode(mode) == DeclarationExportModeGovernanceRepo {
		return repo
	}
	return ""
}

func scopedPathValue(path string, shareable bool) string {
	return redactedSafeValue(strings.TrimSpace(path), "path-review-required", shareable)
}

func redactedSafeValue(value string, fallback string, shareable bool) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	if shareable && looksLikeRedactionPlaceholder(value) {
		return fallback
	}
	return strings.TrimSpace(value)
}

func looksLikeRedactionPlaceholder(value string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	for _, prefix := range []string{"owner-", "repo-", "org-", "loc-", "path-", "fs-", "provider-", "credential-", "proof-"} {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

func firstSelectorValue(selector *resolution.Selector) resolution.Selector {
	if selector == nil {
		return resolution.Selector{}
	}
	return *resolution.CloneSelector(selector)
}

func reviewAuditContextEvidenceRefs(ctx *risk.ReviewAuditContext) []string {
	if ctx == nil {
		return nil
	}
	return append([]string(nil), ctx.EvidenceRefs...)
}
