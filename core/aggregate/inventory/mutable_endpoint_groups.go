package inventory

import (
	"sort"
	"strings"
)

const (
	mutableEndpointGroupRefPrefix     = "meg-"
	endpointRefSampleLimit            = 8
	endpointRouteGroupLimit           = 8
	endpointOperationClassLimit       = 8
	endpointSemanticSampleLimit       = 12
	endpointRouteDynamicSegmentMarker = "*"
)

type EndpointRefGroupProjection struct {
	EndpointRefGroupID      string                        `json:"endpoint_ref_group_id,omitempty" yaml:"endpoint_ref_group_id,omitempty"`
	EndpointRefCount        int                           `json:"endpoint_ref_count,omitempty" yaml:"endpoint_ref_count,omitempty"`
	EndpointRouteGroups     []string                      `json:"endpoint_route_groups,omitempty" yaml:"endpoint_route_groups,omitempty"`
	EndpointOperationCounts []EndpointOperationClassCount `json:"endpoint_operation_counts,omitempty" yaml:"endpoint_operation_counts,omitempty"`
	EndpointRefSamples      []EndpointRefSample           `json:"endpoint_ref_samples,omitempty" yaml:"endpoint_ref_samples,omitempty"`
}

type EndpointOperationClassCount struct {
	Class string `json:"class" yaml:"class"`
	Count int    `json:"count" yaml:"count"`
}

type EndpointRefSample struct {
	RefID     string   `json:"ref_id,omitempty" yaml:"ref_id,omitempty"`
	Operation string   `json:"operation,omitempty" yaml:"operation,omitempty"`
	Surface   string   `json:"surface,omitempty" yaml:"surface,omitempty"`
	Semantics []string `json:"semantics,omitempty" yaml:"semantics,omitempty"`
}

type MutableEndpointGroupRecord struct {
	GroupID         string                        `json:"group_id" yaml:"group_id"`
	RefIDs          []string                      `json:"ref_ids,omitempty" yaml:"ref_ids,omitempty"`
	RefCount        int                           `json:"ref_count,omitempty" yaml:"ref_count,omitempty"`
	RouteGroups     []string                      `json:"route_groups,omitempty" yaml:"route_groups,omitempty"`
	OperationCounts []EndpointOperationClassCount `json:"operation_counts,omitempty" yaml:"operation_counts,omitempty"`
	RefSamples      []EndpointRefSample           `json:"ref_samples,omitempty" yaml:"ref_samples,omitempty"`
}

func BuildMutableEndpointGroupProjection(refs []string, semantics []MutableEndpointSemantic) EndpointRefGroupProjection {
	return buildMutableEndpointGroup(refs, semantics).projection
}

func BoundedMutableEndpointSemanticRefs(refs []string, semantics []MutableEndpointSemantic) []string {
	group := buildMutableEndpointGroup(refs, semantics)
	if len(group.sampleRefs) > 0 {
		return append([]string(nil), group.sampleRefs...)
	}
	if len(group.refs) <= endpointRefSampleLimit {
		return append([]string(nil), group.refs...)
	}
	return append([]string(nil), group.refs[:endpointRefSampleLimit]...)
}

func BoundedMutableEndpointSemantics(semantics []MutableEndpointSemantic) []MutableEndpointSemantic {
	normalized := NormalizeMutableEndpointSemantics(semantics)
	if len(normalized) <= endpointSemanticSampleLimit {
		return normalized
	}
	return append([]MutableEndpointSemantic(nil), normalized[:endpointSemanticSampleLimit]...)
}

type mutableEndpointGroupBuildResult struct {
	projection EndpointRefGroupProjection
	record     MutableEndpointGroupRecord
	refs       []string
	sampleRefs []string
}

func buildMutableEndpointGroup(refs []string, semantics []MutableEndpointSemantic) mutableEndpointGroupBuildResult {
	normalized := NormalizeMutableEndpointSemantics(semantics)
	resolvedRefs := uniqueSortedEndpointRefs(refs)
	if len(resolvedRefs) == 0 && len(normalized) > 0 {
		resolvedRefs = CanonicalMutableEndpointRefs(normalized)
	}
	if len(resolvedRefs) == 0 && len(normalized) == 0 {
		return mutableEndpointGroupBuildResult{}
	}

	samples, sampleRefs := buildEndpointRefSamples(resolvedRefs, normalized)
	routeGroups := buildEndpointRouteGroups(normalized)
	operationCounts := buildEndpointOperationCounts(normalized)
	groupID := stableCanonicalRefID(mutableEndpointGroupRefPrefix, append([]string(nil), resolvedRefs...))
	projection := EndpointRefGroupProjection{
		EndpointRefGroupID:      groupID,
		EndpointRefCount:        len(resolvedRefs),
		EndpointRouteGroups:     routeGroups,
		EndpointOperationCounts: operationCounts,
		EndpointRefSamples:      samples,
	}
	return mutableEndpointGroupBuildResult{
		projection: projection,
		record: MutableEndpointGroupRecord{
			GroupID:         groupID,
			RefIDs:          append([]string(nil), resolvedRefs...),
			RefCount:        len(resolvedRefs),
			RouteGroups:     append([]string(nil), routeGroups...),
			OperationCounts: cloneEndpointOperationCounts(operationCounts),
			RefSamples:      cloneEndpointRefSamples(samples),
		},
		refs:       resolvedRefs,
		sampleRefs: sampleRefs,
	}
}

func uniqueSortedEndpointRefs(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

type endpointOperationSample struct {
	refIDs    []string
	operation string
	surface   string
	semantics []string
	sortKey   string
}

func buildEndpointRefSamples(refs []string, semantics []MutableEndpointSemantic) ([]EndpointRefSample, []string) {
	if len(semantics) == 0 {
		out := make([]EndpointRefSample, 0, minInt(len(refs), endpointRefSampleLimit))
		sampleRefs := make([]string, 0, minInt(len(refs), endpointRefSampleLimit))
		for idx, refID := range refs {
			if idx >= endpointRefSampleLimit {
				break
			}
			out = append(out, EndpointRefSample{RefID: refID})
			sampleRefs = append(sampleRefs, refID)
		}
		return out, sampleRefs
	}

	byOperation := map[string]*endpointOperationSample{}
	for idx, item := range semantics {
		refID := ""
		if idx < len(refs) {
			refID = refs[idx]
		}
		operation := firstNonEmptyEndpointValue(strings.TrimSpace(item.Operation), strings.TrimSpace(item.Semantic), "declared_mutation")
		sample, ok := byOperation[operation]
		if !ok {
			sample = &endpointOperationSample{
				operation: operation,
				surface:   strings.TrimSpace(item.Surface),
				sortKey:   strings.ToLower(operation),
			}
			byOperation[operation] = sample
		}
		if refID != "" {
			sample.refIDs = append(sample.refIDs, refID)
		}
		if semantic := strings.TrimSpace(item.Semantic); semantic != "" {
			sample.semantics = append(sample.semantics, semantic)
		}
		if sample.surface == "" {
			sample.surface = strings.TrimSpace(item.Surface)
		}
	}

	ordered := make([]*endpointOperationSample, 0, len(byOperation))
	for _, sample := range byOperation {
		sample.refIDs = uniqueSortedEndpointRefs(sample.refIDs)
		sample.semantics = uniqueSortedEndpointRefs(sample.semantics)
		ordered = append(ordered, sample)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].sortKey != ordered[j].sortKey {
			return ordered[i].sortKey < ordered[j].sortKey
		}
		return ordered[i].operation < ordered[j].operation
	})

	out := make([]EndpointRefSample, 0, minInt(len(ordered), endpointRefSampleLimit))
	sampleRefs := make([]string, 0, minInt(len(ordered), endpointRefSampleLimit))
	for idx, sample := range ordered {
		if idx >= endpointRefSampleLimit {
			break
		}
		refID := ""
		if len(sample.refIDs) > 0 {
			refID = sample.refIDs[0]
		}
		if refID != "" {
			sampleRefs = append(sampleRefs, refID)
		}
		out = append(out, EndpointRefSample{
			RefID:     refID,
			Operation: sample.operation,
			Surface:   sample.surface,
			Semantics: append([]string(nil), sample.semantics...),
		})
	}
	return out, sampleRefs
}

func buildEndpointRouteGroups(semantics []MutableEndpointSemantic) []string {
	if len(semantics) == 0 {
		return nil
	}
	values := make([]string, 0, len(semantics))
	for _, item := range semantics {
		group := normalizeEndpointRouteGroup(item.Operation)
		if group == "" {
			continue
		}
		values = append(values, group)
	}
	values = uniqueSortedEndpointRefs(values)
	if len(values) <= endpointRouteGroupLimit {
		return values
	}
	return append([]string(nil), values[:endpointRouteGroupLimit]...)
}

func buildEndpointOperationCounts(semantics []MutableEndpointSemantic) []EndpointOperationClassCount {
	if len(semantics) == 0 {
		return nil
	}
	counts := map[string]int{}
	for _, item := range semantics {
		class := strings.TrimSpace(item.Semantic)
		if class == "" {
			continue
		}
		counts[class]++
	}
	if len(counts) == 0 {
		return nil
	}
	out := make([]EndpointOperationClassCount, 0, len(counts))
	for class, count := range counts {
		out = append(out, EndpointOperationClassCount{Class: class, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Class < out[j].Class
	})
	if len(out) <= endpointOperationClassLimit {
		return out
	}
	return append([]EndpointOperationClassCount(nil), out[:endpointOperationClassLimit]...)
}

func normalizeEndpointRouteGroup(operation string) string {
	trimmed := strings.TrimSpace(operation)
	if trimmed == "" {
		return ""
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return ""
	}
	method := strings.ToUpper(fields[0])
	if len(fields) == 1 {
		return method
	}
	route := strings.Join(fields[1:], " ")
	if idx := strings.Index(route, "?"); idx >= 0 {
		route = route[:idx]
	}
	segments := strings.Split(strings.TrimSpace(route), "/")
	normalized := make([]string, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		switch {
		case strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}"):
			normalized = append(normalized, endpointRouteDynamicSegmentMarker)
		case strings.HasPrefix(segment, ":"):
			normalized = append(normalized, endpointRouteDynamicSegmentMarker)
		case looksDynamicEndpointSegment(segment):
			normalized = append(normalized, endpointRouteDynamicSegmentMarker)
		default:
			normalized = append(normalized, segment)
		}
	}
	if len(normalized) == 0 {
		return method
	}
	return method + " /" + strings.Join(normalized, "/")
}

func looksDynamicEndpointSegment(segment string) bool {
	if segment == "" {
		return false
	}
	allDigits := true
	allHexish := true
	for _, r := range segment {
		switch {
		case r >= '0' && r <= '9':
		default:
			allDigits = false
		}
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		case r == '-':
		default:
			allHexish = false
		}
	}
	if allDigits {
		return true
	}
	return len(segment) >= 8 && allHexish
}

func cloneEndpointOperationCounts(in []EndpointOperationClassCount) []EndpointOperationClassCount {
	if len(in) == 0 {
		return nil
	}
	return append([]EndpointOperationClassCount(nil), in...)
}

func cloneEndpointRefSamples(in []EndpointRefSample) []EndpointRefSample {
	if len(in) == 0 {
		return nil
	}
	out := make([]EndpointRefSample, 0, len(in))
	for _, item := range in {
		out = append(out, EndpointRefSample{
			RefID:     strings.TrimSpace(item.RefID),
			Operation: strings.TrimSpace(item.Operation),
			Surface:   strings.TrimSpace(item.Surface),
			Semantics: uniqueSortedEndpointRefs(item.Semantics),
		})
	}
	return out
}

func firstNonEmptyEndpointValue(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
