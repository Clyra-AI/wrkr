package compliance

import (
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

func Evaluate(in Input) (Result, error) {
	if in.Framework == nil {
		return Result{}, fmt.Errorf("framework is required")
	}
	if in.Chain == nil {
		return Result{}, fmt.Errorf("chain is required")
	}
	controls := flatten(in.Framework.Controls)
	matchedRuleIDs := collectRuleIDs(in.Chain.Records)
	checks := make([]ControlCheck, 0, len(controls))
	gaps := make([]ControlCheck, 0)
	covered := 0
	for _, control := range controls {
		check := evaluateControl(in.Framework.Framework.ID, control, in.Chain.Records, matchedRuleIDs)
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

func evaluateControl(frameworkID string, control framework.Control, records []proof.Record, matchedRuleIDs map[string]struct{}) ControlCheck {
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
	if len(mappedRules) > 0 {
		status = "covered"
		missingTypes = nil
		missingFields = nil
	}

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
	controls := frameworkControlRuleMap[strings.TrimSpace(frameworkID)]
	if len(controls) == 0 {
		return nil
	}
	ruleIDs := controls[strings.TrimSpace(controlID)]
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
