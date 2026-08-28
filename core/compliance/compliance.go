package compliance

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/core/framework"
)

type Input struct {
	Framework *proof.Framework
	Chain     *proof.Chain
}

type Result struct {
	FrameworkID  string         `json:"framework_id"`
	Version      string         `json:"version"`
	Title        string         `json:"title"`
	ControlCount int            `json:"control_count"`
	CoveredCount int            `json:"covered_count"`
	Coverage     float64        `json:"coverage_percent"`
	Controls     []ControlCheck `json:"controls"`
	Gaps         []ControlCheck `json:"gaps"`
}

type ControlCheck struct {
	ID                  string   `json:"id"`
	Title               string   `json:"title"`
	Status              string   `json:"status"`
	MatchedRecords      int      `json:"matched_records"`
	MappedRuleIDs       []string `json:"mapped_rule_ids,omitempty"`
	MissingRecordTypes  []string `json:"missing_record_types,omitempty"`
	MissingFields       []string `json:"missing_fields,omitempty"`
	RequiredRecordTypes []string `json:"required_record_types"`
	RequiredFields      []string `json:"required_fields"`
}

type evidenceSetCoverage struct {
	ID                  string
	Title               string
	Covered             bool
	SourceProducts      []string
	RequiredRecordTypes []string
	RequiredFields      []string
	MatchingRecordIDs   []string
}

type controlCoverage struct {
	ID                    string
	Title                 string
	Covered               bool
	MatchedEvidenceSetIDs []string
	EvidenceSets          []evidenceSetCoverage
	Children              []controlCoverage
}

func Evaluate(in Input) (Result, error) {
	if in.Framework == nil {
		return Result{}, fmt.Errorf("framework is required")
	}
	if in.Chain == nil {
		return Result{}, fmt.Errorf("chain is required")
	}
	controls := flatten(in.Framework.Controls)
	var coverageControls []controlCoverage
	if controlsUseEvidenceSets(controls) {
		coverageControls = flattenCoverage(evaluateCoverage(in.Framework.Controls, in.Chain.Records))
		if len(coverageControls) != len(controls) {
			return Result{}, fmt.Errorf("framework control coverage mismatch: controls=%d coverage=%d", len(controls), len(coverageControls))
		}
	}
	matchedRuleIDs := collectRuleIDs(in.Chain.Records)
	checks := make([]ControlCheck, 0, len(controls))
	gaps := make([]ControlCheck, 0)
	covered := 0
	for index, control := range controls {
		var coverageControl controlCoverage
		if len(control.EvidenceSets) > 0 {
			coverageControl = coverageControls[index]
			if coverageControl.ID != control.ID {
				return Result{}, fmt.Errorf("framework control coverage order mismatch: control=%q coverage=%q", control.ID, coverageControl.ID)
			}
		}
		check := evaluateControl(in.Framework.Framework.ID, control, coverageControl, in.Chain.Records, matchedRuleIDs)
		checks = append(checks, check)
		if check.Status == "covered" {
			covered++
		} else {
			gaps = append(gaps, check)
		}
	}
	coverage := 100.0
	if len(checks) > 0 {
		coverage = round2(float64(covered) / float64(len(checks)) * 100)
	}
	return Result{
		FrameworkID:  in.Framework.Framework.ID,
		Version:      in.Framework.Framework.Version,
		Title:        in.Framework.Framework.Title,
		ControlCount: len(checks),
		CoveredCount: covered,
		Coverage:     coverage,
		Controls:     checks,
		Gaps:         gaps,
	}, nil
}

func evaluateControl(frameworkID string, control framework.Control, evidenceCoverage controlCoverage, records []proof.Record, matchedRuleIDs map[string]struct{}) ControlCheck {
	if len(control.EvidenceSets) > 0 {
		return evaluateEvidenceSetControl(frameworkID, control, evidenceCoverage, records, matchedRuleIDs)
	}
	return evaluateLegacyControl(frameworkID, control, records, matchedRuleIDs)
}

func evaluateLegacyControl(frameworkID string, control framework.Control, records []proof.Record, matchedRuleIDs map[string]struct{}) ControlCheck {
	requiredTypes := uniqueSortedStrings(control.RequiredRecordTypes)
	requiredFields := uniqueSortedStrings(control.RequiredFields)
	missingTypes := make([]string, 0)
	matchedByType := map[string][]proof.Record{}
	for _, requiredType := range requiredTypes {
		for _, record := range records {
			if strings.TrimSpace(record.RecordType) == requiredType {
				matchedByType[requiredType] = append(matchedByType[requiredType], record)
			}
		}
		if len(matchedByType[requiredType]) == 0 {
			missingTypes = append(missingTypes, requiredType)
		}
	}

	missingFields := make([]string, 0)
	for _, requiredField := range requiredFields {
		if !fieldCovered(requiredField, matchedByType) {
			missingFields = append(missingFields, requiredField)
		}
	}

	status := "covered"
	if len(missingTypes) > 0 || len(missingFields) > 0 {
		status = "gap"
	}
	mappedRules := mappedRuleIDs(frameworkID, control.ID, matchedRuleIDs)

	matchedCount := 0
	for _, items := range matchedByType {
		matchedCount += len(items)
	}
	matchedCount += len(mappedRules)

	return ControlCheck{
		ID:                  control.ID,
		Title:               control.Title,
		Status:              status,
		MatchedRecords:      matchedCount,
		MappedRuleIDs:       mappedRules,
		MissingRecordTypes:  missingTypes,
		MissingFields:       missingFields,
		RequiredRecordTypes: requiredTypes,
		RequiredFields:      requiredFields,
	}
}

func evaluateEvidenceSetControl(frameworkID string, control framework.Control, evidenceCoverage controlCoverage, records []proof.Record, matchedRuleIDs map[string]struct{}) ControlCheck {
	selected, ok := selectEvidenceSetCoverage(evidenceCoverage.EvidenceSets, records)
	mappedRules := mappedRuleIDs(frameworkID, control.ID, matchedRuleIDs)
	if !ok {
		return ControlCheck{
			ID:             control.ID,
			Title:          control.Title,
			Status:         "gap",
			MappedRuleIDs:  mappedRules,
			MatchedRecords: len(mappedRules),
		}
	}

	status := "gap"
	if selected.Covered {
		status = "covered"
	}
	missingRecordTypes, missingFields := evidenceSetGaps(selected, records)
	return ControlCheck{
		ID:                  control.ID,
		Title:               control.Title,
		Status:              status,
		MatchedRecords:      len(selected.MatchingRecordIDs) + len(mappedRules),
		MappedRuleIDs:       mappedRules,
		MissingRecordTypes:  missingRecordTypes,
		MissingFields:       missingFields,
		RequiredRecordTypes: uniqueSortedStrings(selected.RequiredRecordTypes),
		RequiredFields:      uniqueSortedStrings(selected.RequiredFields),
	}
}

func selectEvidenceSetCoverage(sets []evidenceSetCoverage, records []proof.Record) (evidenceSetCoverage, bool) {
	if len(sets) == 0 {
		return evidenceSetCoverage{}, false
	}
	type candidate struct {
		coverage           evidenceSetCoverage
		wrkrMatched        bool
		missingRecordTypes int
		missingFields      int
		key                string
	}
	ordered := make([]candidate, 0, len(sets))
	for _, set := range sets {
		if !evidenceSetAppliesToWrkr(set.SourceProducts) {
			continue
		}
		missingRecordTypes, missingFields := evidenceSetGaps(set, records)
		wrkrMatched := evidenceSetHasMatchingWrkrRecord(set, records)
		projectedCoverage := set
		projectedCoverage.Covered = set.Covered && wrkrMatched
		ordered = append(ordered, candidate{
			coverage:           projectedCoverage,
			wrkrMatched:        wrkrMatched,
			missingRecordTypes: len(missingRecordTypes),
			missingFields:      len(missingFields),
			key: strings.Join([]string{
				strings.TrimSpace(set.ID),
				strings.Join(uniqueSortedStrings(set.SourceProducts), ","),
				strings.Join(uniqueSortedStrings(set.RequiredRecordTypes), ","),
				strings.Join(uniqueSortedStrings(set.RequiredFields), ","),
			}, "|"),
		})
	}
	if len(ordered) == 0 {
		return evidenceSetCoverage{}, false
	}
	sort.Slice(ordered, func(i, j int) bool {
		left, right := ordered[i], ordered[j]
		if left.coverage.Covered != right.coverage.Covered {
			return left.coverage.Covered
		}
		if left.wrkrMatched != right.wrkrMatched {
			return left.wrkrMatched
		}
		if left.missingRecordTypes != right.missingRecordTypes {
			return left.missingRecordTypes < right.missingRecordTypes
		}
		if left.missingFields != right.missingFields {
			return left.missingFields < right.missingFields
		}
		return left.key < right.key
	})
	return ordered[0].coverage, true
}

func evidenceSetHasMatchingWrkrRecord(set evidenceSetCoverage, records []proof.Record) bool {
	for _, requiredType := range uniqueSortedStrings(set.RequiredRecordTypes) {
		for _, record := range records {
			if !strings.EqualFold(strings.TrimSpace(record.SourceProduct), "wrkr") {
				continue
			}
			if strings.TrimSpace(record.RecordType) != requiredType {
				continue
			}
			if len(missingEvidenceFields(record, set.RequiredFields)) == 0 {
				return true
			}
		}
	}
	return false
}

func evidenceSetGaps(set evidenceSetCoverage, records []proof.Record) ([]string, []string) {
	missingRecordTypes := make([]string, 0)
	missingFields := make([]string, 0)
	for _, requiredType := range uniqueSortedStrings(set.RequiredRecordTypes) {
		candidates := evidenceSetCandidates(requiredType, set.SourceProducts, records)
		if len(candidates) == 0 {
			missingRecordTypes = append(missingRecordTypes, requiredType)
			continue
		}

		bestMissing := missingEvidenceFields(candidates[0], set.RequiredFields)
		bestKey := evidenceRecordKey(candidates[0])
		for _, candidate := range candidates[1:] {
			candidateMissing := missingEvidenceFields(candidate, set.RequiredFields)
			candidateKey := evidenceRecordKey(candidate)
			if len(candidateMissing) < len(bestMissing) || (len(candidateMissing) == len(bestMissing) && candidateKey < bestKey) {
				bestMissing = candidateMissing
				bestKey = candidateKey
			}
		}
		missingFields = append(missingFields, bestMissing...)
	}
	return uniqueSortedStrings(missingRecordTypes), uniqueSortedStrings(missingFields)
}

func evidenceSetCandidates(requiredType string, sourceProducts []string, records []proof.Record) []proof.Record {
	out := make([]proof.Record, 0)
	for _, record := range records {
		if strings.TrimSpace(record.RecordType) != strings.TrimSpace(requiredType) {
			continue
		}
		if !evidenceSourceProductAllowed(record.SourceProduct, sourceProducts) {
			continue
		}
		out = append(out, record)
	}
	return out
}

func evidenceSourceProductAllowed(sourceProduct string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimSpace(sourceProduct), strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func missingEvidenceFields(record proof.Record, requiredFields []string) []string {
	root, ok := evidenceRecordObject(record)
	if !ok {
		return uniqueSortedStrings(requiredFields)
	}
	missing := make([]string, 0)
	for _, requiredField := range uniqueSortedStrings(requiredFields) {
		if !evidenceFieldPresent(root, requiredField) {
			missing = append(missing, requiredField)
		}
	}
	return missing
}

func evidenceRecordObject(record proof.Record) (map[string]any, bool) {
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, false
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, false
	}
	return root, true
}

func evidenceFieldPresent(root map[string]any, field string) bool {
	value, ok := nestedEvidenceField(root, field)
	return ok && evidenceValuePresent(value)
}

func nestedEvidenceField(root map[string]any, field string) (any, bool) {
	current := any(root)
	for _, part := range strings.Split(field, ".") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, false
		}
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		next, exists := object[part]
		if !exists {
			return nil, false
		}
		current = next
	}
	return current, true
}

func evidenceValuePresent(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	case []any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	default:
		return true
	}
}

func evidenceRecordKey(record proof.Record) string {
	return strings.Join([]string{
		strings.TrimSpace(record.RecordID),
		strings.TrimSpace(record.SourceProduct),
		strings.TrimSpace(record.Source),
		strings.TrimSpace(record.RecordType),
		strings.TrimSpace(record.Integrity.RecordHash),
	}, "|")
}

func evidenceSetAppliesToWrkr(sourceProducts []string) bool {
	if len(sourceProducts) == 0 {
		return true
	}
	for _, sourceProduct := range sourceProducts {
		if strings.EqualFold(strings.TrimSpace(sourceProduct), "wrkr") {
			return true
		}
	}
	return false
}

func fieldCovered(requiredField string, matchedByType map[string][]proof.Record) bool {
	for _, records := range matchedByType {
		for _, record := range records {
			if hasField(record, requiredField) {
				return true
			}
		}
	}
	return false
}

func hasField(record proof.Record, field string) bool {
	switch strings.TrimSpace(field) {
	case "record_id":
		return strings.TrimSpace(record.RecordID) != ""
	case "timestamp":
		return !record.Timestamp.IsZero()
	case "source":
		return strings.TrimSpace(record.Source) != ""
	case "source_product":
		return strings.TrimSpace(record.SourceProduct) != ""
	case "record_type":
		return strings.TrimSpace(record.RecordType) != ""
	case "event":
		return record.Event != nil
	case "integrity.record_hash":
		return strings.TrimSpace(record.Integrity.RecordHash) != ""
	default:
		if strings.HasPrefix(field, "event.") {
			key := strings.TrimSpace(strings.TrimPrefix(field, "event."))
			if key == "" {
				return false
			}
			_, ok := record.Event[key]
			return ok
		}
		if strings.HasPrefix(field, "metadata.") {
			key := strings.TrimSpace(strings.TrimPrefix(field, "metadata."))
			if key == "" || record.Metadata == nil {
				return false
			}
			_, ok := record.Metadata[key]
			return ok
		}
		return false
	}
}

func flatten(controls []framework.Control) []framework.Control {
	out := make([]framework.Control, 0)
	for _, control := range controls {
		out = append(out, control)
		children := flatten(control.Children)
		out = append(out, children...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID == out[j].ID {
			return out[i].Title < out[j].Title
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func flattenCoverage(controls []controlCoverage) []controlCoverage {
	out := make([]controlCoverage, 0)
	for _, control := range controls {
		out = append(out, control)
		children := flattenCoverage(control.Children)
		out = append(out, children...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID == out[j].ID {
			return out[i].Title < out[j].Title
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func controlsUseEvidenceSets(controls []framework.Control) bool {
	for _, control := range controls {
		if len(control.EvidenceSets) > 0 {
			return true
		}
	}
	return false
}

// evaluateCoverage computes only the deterministic evidence-path projection
// needed by Wrkr's compliance report. Proof v0.7 keeps its former evaluator as
// a deprecated compatibility API; this product-owned projection avoids making
// compliance semantics depend on that legacy API.
func evaluateCoverage(controls []framework.Control, records []proof.Record) []controlCoverage {
	out := make([]controlCoverage, 0, len(controls))
	for _, control := range controls {
		out = append(out, evaluateControlCoverage(control, records))
	}
	return out
}

func evaluateControlCoverage(control framework.Control, records []proof.Record) controlCoverage {
	sets := control.EvidenceSets
	if len(sets) == 0 {
		sets = []framework.EvidenceSet{{
			ID:                  "legacy",
			Title:               control.Title,
			RequiredRecordTypes: append([]string(nil), control.RequiredRecordTypes...),
			MinimumFrequency:    control.MinimumFrequency,
			RequiredFields:      append([]string(nil), control.RequiredFields...),
		}}
	}
	setCoverage := make([]evidenceSetCoverage, 0, len(sets))
	matched := make([]string, 0, len(sets))
	for _, set := range sets {
		coverage := evaluateEvidenceSetCoverage(set, records)
		setCoverage = append(setCoverage, coverage)
		if coverage.Covered {
			matched = append(matched, coverage.ID)
		}
	}
	children := make([]controlCoverage, 0, len(control.Children))
	for _, child := range control.Children {
		children = append(children, evaluateControlCoverage(child, records))
	}
	return controlCoverage{
		ID:                    control.ID,
		Title:                 control.Title,
		Covered:               len(matched) > 0,
		MatchedEvidenceSetIDs: matched,
		EvidenceSets:          setCoverage,
		Children:              children,
	}
}

func evaluateEvidenceSetCoverage(set framework.EvidenceSet, records []proof.Record) evidenceSetCoverage {
	matching := make([]string, 0, len(set.RequiredRecordTypes))
	for _, requiredType := range set.RequiredRecordTypes {
		bestRecordID := ""
		for _, candidate := range evidenceSetCandidates(requiredType, set.SourceProducts, records) {
			if len(missingEvidenceFields(candidate, set.RequiredFields)) != 0 {
				continue
			}
			if bestRecordID == "" || candidate.RecordID < bestRecordID {
				bestRecordID = candidate.RecordID
			}
		}
		if bestRecordID != "" {
			matching = append(matching, bestRecordID)
		}
	}
	matching = uniqueSortedStrings(matching)
	return evidenceSetCoverage{
		ID:                  set.ID,
		Title:               set.Title,
		Covered:             len(matching) == len(set.RequiredRecordTypes),
		SourceProducts:      append([]string(nil), set.SourceProducts...),
		RequiredRecordTypes: append([]string(nil), set.RequiredRecordTypes...),
		RequiredFields:      append([]string(nil), set.RequiredFields...),
		MatchingRecordIDs:   matching,
	}
}

func uniqueSortedStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func round2(value float64) float64 {
	return float64(int(value*100+0.5)) / 100
}

func collectRuleIDs(records []proof.Record) map[string]struct{} {
	out := map[string]struct{}{}
	for _, record := range records {
		for _, ruleID := range recordRuleIDs(record) {
			out[ruleID] = struct{}{}
		}
	}
	return out
}

func recordRuleIDs(record proof.Record) []string {
	set := map[string]struct{}{}
	if ruleID := eventRuleID(record.Event); ruleID != "" {
		set[ruleID] = struct{}{}
	}
	if record.Relationship != nil && record.Relationship.PolicyRef != nil {
		for _, ruleID := range record.Relationship.PolicyRef.MatchedRuleIDs {
			trimmed := strings.TrimSpace(ruleID)
			if trimmed == "" {
				continue
			}
			set[trimmed] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for ruleID := range set {
		out = append(out, ruleID)
	}
	sort.Strings(out)
	return out
}

func eventRuleID(event map[string]any) string {
	if event == nil {
		return ""
	}
	if ruleID, ok := event["rule_id"].(string); ok && strings.TrimSpace(ruleID) != "" {
		return strings.TrimSpace(ruleID)
	}
	finding, ok := event["finding"].(map[string]any)
	if !ok {
		return ""
	}
	ruleID, _ := finding["rule_id"].(string)
	return strings.TrimSpace(ruleID)
}

func mappedRuleIDs(frameworkID, controlID string, matchedRuleIDs map[string]struct{}) []string {
	ruleIDs := configuredControlRuleIDs(strings.TrimSpace(frameworkID), strings.TrimSpace(controlID))
	if len(ruleIDs) == 0 {
		return nil
	}
	out := make([]string, 0, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		if _, ok := matchedRuleIDs[ruleID]; ok {
			out = append(out, ruleID)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}
