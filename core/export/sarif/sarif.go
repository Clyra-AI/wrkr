package sarif

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/model"
)

const (
	schemaURL = "https://json.schemastore.org/sarif-2.1.0.json"
	version   = "2.1.0"
)

type Report struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results,omitempty"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []Rule `json:"rules,omitempty"`
}

type Rule struct {
	ID               string  `json:"id"`
	ShortDescription Message `json:"shortDescription,omitempty"`
}

type Result struct {
	RuleID    string     `json:"ruleId,omitempty"`
	Level     string     `json:"level,omitempty"`
	Message   Message    `json:"message"`
	Locations []Location `json:"locations,omitempty"`
}

type Message struct {
	Text string `json:"text"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Build maps Wrkr findings to a deterministic SARIF report.
func Build(findings []model.Finding, wrkrVersion string) Report {
	sorted := append([]model.Finding(nil), findings...)
	model.SortFindings(sorted)

	rulesByID := map[string]Rule{}
	results := make([]Result, 0, len(sorted))
	for _, finding := range sorted {
		ruleID := sarifRuleID(finding)
		rulesByID[ruleID] = Rule{
			ID: ruleID,
			ShortDescription: Message{
				Text: strings.TrimSpace(finding.FindingType),
			},
		}
		results = append(results, Result{
			RuleID: ruleID,
			Level:  severityToSARIFLevel(finding.Severity),
			Message: Message{
				Text: findingMessage(finding),
			},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI: fallbackLocation(finding.Location),
						},
					},
				},
			},
		})
	}

	ruleIDs := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)

	rules := make([]Rule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, rulesByID[id])
	}

	return Report{
		Schema:  schemaURL,
		Version: version,
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           "wrkr",
						Version:        strings.TrimSpace(wrkrVersion),
						InformationURI: "https://github.com/Clyra-AI/wrkr",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}
}

// Write persists a SARIF report at path.
func Write(path string, report Report) error {
	file, err := os.Create(path) // #nosec G304 -- output path is caller-controlled and validated by CLI path guards before write.
	if err != nil {
		return fmt.Errorf("create sarif output: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode sarif output: %w", err)
	}
	return nil
}

func findingMessage(finding model.Finding) string {
	parts := []string{strings.TrimSpace(finding.FindingType)}
	if detector := strings.TrimSpace(finding.Detector); detector != "" {
		parts = append(parts, "detector="+detector)
	}
	if repo := strings.TrimSpace(finding.Repo); repo != "" {
		parts = append(parts, "repo="+repo)
	}
	return strings.Join(parts, " ")
}

func fallbackLocation(location string) string {
	value := strings.TrimSpace(location)
	if value == "" {
		return "unknown"
	}
	return value
}

func sarifRuleID(finding model.Finding) string {
	if id := strings.TrimSpace(finding.RuleID); id != "" {
		return id
	}
	if findingType := strings.TrimSpace(finding.FindingType); findingType != "" {
		return findingType
	}
	return "wrkr_finding"
}

func severityToSARIFLevel(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium, model.SeverityLow:
		return "warning"
	default:
		return "note"
	}
}
