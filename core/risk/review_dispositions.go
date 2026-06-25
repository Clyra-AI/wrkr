package risk

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/resolution"
)

type reviewDispositionProjection struct {
	ResolutionSelector        *resolution.Selector
	ResolutionMatchConfidence string
	ResolutionMismatchReasons []string
	ReviewLifecycleState      string
	ReviewLifecycleReasons    []string
	ReviewRationale           string
	ReviewOwner               string
	ReviewSource              string
	ReviewObservedAt          string
	ReviewValidUntil          string
	ReviewScope               string
}

func decorateReviewDispositions(paths []ActionPath, repoContexts map[string]attribution.Context) []ActionPath {
	if len(paths) == 0 {
		return nil
	}
	out := append([]ActionPath(nil), paths...)
	byRepo := map[string][]int{}
	for idx, path := range out {
		byRepo[repoKey(path.Org, path.Repo)] = append(byRepo[repoKey(path.Org, path.Repo)], idx)
	}

	for repoKeyValue, indexes := range byRepo {
		if len(indexes) == 0 {
			continue
		}
		ctx := repoContextForPath(out[indexes[0]], repoContexts)
		if len(ctx.ReviewDispositions) == 0 {
			continue
		}
		pathsForRepo := make([]ActionPath, 0, len(indexes))
		for _, idx := range indexes {
			pathsForRepo = append(pathsForRepo, ProjectActionPath(out[idx]))
		}
		for _, disposition := range ctx.ReviewDispositions {
			matches, ambiguous := matchReviewDisposition(disposition, pathsForRepo)
			if len(matches) == 0 {
				continue
			}
			for _, match := range matches {
				projection := buildReviewDispositionProjection(ctx, disposition, match.path, ambiguous, match.confidence, match.reasons)
				targetKey := reviewDispositionPathKey(match.path)
				for _, idx := range indexes {
					if reviewDispositionPathKey(out[idx]) != targetKey {
						continue
					}
					out[idx] = mergeReviewDispositionProjection(out[idx], projection)
				}
			}
		}
		_ = repoKeyValue
	}
	return out
}

type reviewDispositionMatch struct {
	path       ActionPath
	confidence string
	reasons    []string
}

func matchReviewDisposition(disposition attribution.ReviewDisposition, paths []ActionPath) ([]reviewDispositionMatch, bool) {
	if len(paths) == 0 {
		return nil, false
	}
	if direct := directReviewDispositionMatches(disposition, paths); len(direct) > 0 {
		return direct, len(direct) > 1
	}

	selector := resolution.NormalizeSelector(disposition.Selector)
	if !resolution.HasSelectorFields(selector) {
		return nil, false
	}

	baseReasons := selectorFallbackReasons(disposition)
	matches := []reviewDispositionMatch{}
	for _, path := range paths {
		result := resolution.Match(selector, resolutionCandidateForActionPath(path))
		if !result.Matched {
			continue
		}
		matches = append(matches, reviewDispositionMatch{
			path:       path,
			confidence: result.Confidence,
			reasons:    dedupeSortedStrings(append(append([]string(nil), baseReasons...), result.MismatchReasons...)),
		})
	}
	if len(matches) <= 1 {
		return matches, false
	}
	for idx := range matches {
		matches[idx].confidence = resolution.MatchConfidenceAmbiguous
		matches[idx].reasons = dedupeSortedStrings(append(matches[idx].reasons, "selector:ambiguous_match"))
	}
	return matches, true
}

func directReviewDispositionMatches(disposition attribution.ReviewDisposition, paths []ActionPath) []reviewDispositionMatch {
	out := []reviewDispositionMatch{}
	seen := map[string]struct{}{}
	for _, path := range paths {
		matched := false
		if strings.TrimSpace(disposition.PathID) != "" && strings.TrimSpace(path.PathID) == strings.TrimSpace(disposition.PathID) {
			matched = true
		}
		if strings.TrimSpace(disposition.ResolutionKey) != "" && strings.TrimSpace(path.ResolutionKey) == strings.TrimSpace(disposition.ResolutionKey) {
			matched = true
		}
		if strings.TrimSpace(disposition.FindingKey) != "" && reviewDispositionContains(path.SourceFindingKeys, strings.TrimSpace(disposition.FindingKey)) {
			matched = true
		}
		if !matched {
			continue
		}
		key := reviewDispositionPathKey(path)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, reviewDispositionMatch{path: path})
	}
	return out
}

func selectorFallbackReasons(disposition attribution.ReviewDisposition) []string {
	reasons := []string{}
	if strings.TrimSpace(disposition.PathID) != "" {
		reasons = append(reasons, "selector:path_id_stale")
	}
	if strings.TrimSpace(disposition.ResolutionKey) != "" {
		reasons = append(reasons, "selector:resolution_key_stale")
	}
	if strings.TrimSpace(disposition.FindingKey) != "" {
		reasons = append(reasons, "selector:finding_key_stale")
	}
	return dedupeSortedStrings(reasons)
}

func buildReviewDispositionProjection(ctx attribution.Context, disposition attribution.ReviewDisposition, path ActionPath, ambiguous bool, confidence string, reasons []string) reviewDispositionProjection {
	var selectorPtr *resolution.Selector
	if resolution.HasSelectorFields(disposition.Selector) {
		selectorPtr = resolution.CloneSelector(&disposition.Selector)
	}
	projection := reviewDispositionProjection{
		ResolutionSelector:        selectorPtr,
		ResolutionMatchConfidence: strings.TrimSpace(confidence),
		ResolutionMismatchReasons: dedupeSortedStrings(reasons),
		ReviewLifecycleReasons:    []string{"review_declaration:matched"},
		ReviewRationale:           strings.TrimSpace(disposition.Rationale),
		ReviewOwner:               firstNonEmptyString(strings.TrimSpace(disposition.Owner), strings.TrimSpace(disposition.Issuer)),
		ReviewSource:              strings.TrimSpace(disposition.Source),
		ReviewObservedAt:          strings.TrimSpace(disposition.ObservedAt),
		ReviewValidUntil:          strings.TrimSpace(disposition.ValidUntil),
		ReviewScope:               strings.TrimSpace(disposition.Scope),
	}
	if ambiguous {
		projection.ReviewLifecycleReasons = dedupeSortedStrings(append(projection.ReviewLifecycleReasons, "review_declaration:ambiguous_selector"))
		return projection
	}

	freshness, _, err := evidencepolicy.EvaluateFreshness(ctx.GeneratedAt, disposition.ObservedAt, disposition.ValidUntil, disposition.MaxAge, "")
	if err == nil && freshness == evidencepolicy.FreshnessStateExpired {
		projection.ReviewLifecycleReasons = dedupeSortedStrings(append(projection.ReviewLifecycleReasons, "review_declaration:expired"))
		return projection
	}
	if reviewDispositionContradictsScope(disposition.Scope, path) {
		projection.ReviewLifecycleReasons = dedupeSortedStrings(append(projection.ReviewLifecycleReasons, "review_declaration:scope_contradiction"))
		return projection
	}

	projection.ReviewLifecycleState = strings.TrimSpace(disposition.State)
	return projection
}

func mergeReviewDispositionProjection(path ActionPath, projection reviewDispositionProjection) ActionPath {
	out := path
	if out.ResolutionSelector == nil && projection.ResolutionSelector != nil {
		out.ResolutionSelector = resolution.CloneSelector(projection.ResolutionSelector)
	}
	if strings.TrimSpace(out.ResolutionMatchConfidence) == "" {
		out.ResolutionMatchConfidence = strings.TrimSpace(projection.ResolutionMatchConfidence)
	}
	out.ResolutionMismatchReasons = dedupeSortedStrings(append(append([]string(nil), out.ResolutionMismatchReasons...), projection.ResolutionMismatchReasons...))
	if strings.TrimSpace(out.ReviewLifecycleState) == "" {
		out.ReviewLifecycleState = strings.TrimSpace(projection.ReviewLifecycleState)
	}
	out.ReviewLifecycleReasons = dedupeSortedStrings(append(append([]string(nil), out.ReviewLifecycleReasons...), projection.ReviewLifecycleReasons...))
	out.ReviewRationale = firstNonEmptyString(out.ReviewRationale, projection.ReviewRationale)
	out.ReviewOwner = firstNonEmptyString(out.ReviewOwner, projection.ReviewOwner)
	out.ReviewSource = firstNonEmptyString(out.ReviewSource, projection.ReviewSource)
	out.ReviewObservedAt = firstNonEmptyString(out.ReviewObservedAt, projection.ReviewObservedAt)
	out.ReviewValidUntil = firstNonEmptyString(out.ReviewValidUntil, projection.ReviewValidUntil)
	out.ReviewScope = firstNonEmptyString(out.ReviewScope, projection.ReviewScope)
	return out
}

func reviewDispositionContradictsScope(scope string, path ActionPath) bool {
	switch strings.TrimSpace(scope) {
	case "non_production":
		return path.ProductionWrite ||
			len(path.MatchedProductionTargets) > 0 ||
			strings.TrimSpace(path.TargetClass) == TargetClassProductionImpacting ||
			strings.TrimSpace(path.TargetClass) == TargetClassReleaseAdjacent
	case "production":
		return !path.ProductionWrite &&
			len(path.MatchedProductionTargets) == 0 &&
			strings.TrimSpace(path.TargetClass) != TargetClassProductionImpacting &&
			strings.TrimSpace(path.TargetClass) != TargetClassReleaseAdjacent
	default:
		return false
	}
}

func reviewDispositionPathKey(path ActionPath) string {
	return firstNonEmptyString(strings.TrimSpace(path.PathID), strings.TrimSpace(path.ResolutionKey), strings.TrimSpace(path.Repo)+"@"+strings.TrimSpace(path.Location))
}

func reviewDispositionContains(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(want) {
			return true
		}
	}
	return false
}
