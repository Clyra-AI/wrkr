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
	checks := make([]ControlCheck, 0, len(controls))
	gaps := make([]ControlCheck, 0)
	covered := 0
	for _, control := range controls {
		check := evaluateControl(control, in.Chain.Records)
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

func evaluateControl(control framework.Control, records []proof.Record) ControlCheck {
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

	matchedCount := 0
	for _, items := range matchedByType {
		matchedCount += len(items)
	}

	return ControlCheck{
		ID:                  control.ID,
		Title:               control.Title,
		Status:              status,
		MatchedRecords:      matchedCount,
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
