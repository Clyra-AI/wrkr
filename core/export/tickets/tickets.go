package tickets

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
)

const TicketExportVersion = "1"

type Export struct {
	TicketExportVersion string   `json:"ticket_export_version"`
	Format              string   `json:"format"`
	DryRun              bool     `json:"dry_run"`
	Tickets             []Ticket `json:"tickets"`
}

type Ticket struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Owner             string   `json:"owner,omitempty"`
	Repo              string   `json:"repo,omitempty"`
	Path              string   `json:"path,omitempty"`
	ControlPathType   string   `json:"control_path_type,omitempty"`
	Capability        string   `json:"capability,omitempty"`
	Evidence          []string `json:"evidence,omitempty"`
	RecommendedAction string   `json:"recommended_action"`
	SLA               string   `json:"sla"`
	ClosureCriteria   string   `json:"closure_criteria"`
	Confidence        string   `json:"confidence,omitempty"`
	ProofRequirements []string `json:"proof_requirements,omitempty"`
	Body              string   `json:"body"`
}

func ValidFormat(format string) bool {
	switch strings.TrimSpace(format) {
	case "jira", "github", "servicenow":
		return true
	default:
		return false
	}
}

func Build(backlog *controlbacklog.Backlog, format string, top int) Export {
	items := []controlbacklog.Item{}
	if backlog != nil {
		items = append(items, backlog.Items...)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if actionPriority(items[i].RecommendedAction) != actionPriority(items[j].RecommendedAction) {
			return actionPriority(items[i].RecommendedAction) < actionPriority(items[j].RecommendedAction)
		}
		if items[i].Repo != items[j].Repo {
			return items[i].Repo < items[j].Repo
		}
		if items[i].Path != items[j].Path {
			return items[i].Path < items[j].Path
		}
		return items[i].ID < items[j].ID
	})
	if top > 0 && top < len(items) {
		items = items[:top]
	}
	tickets := make([]Ticket, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		key := ticketGroupKey(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		tickets = append(tickets, ticketFromBacklogItem(item, format, key))
	}
	return Export{
		TicketExportVersion: TicketExportVersion,
		Format:              strings.TrimSpace(format),
		DryRun:              true,
		Tickets:             tickets,
	}
}

func ticketFromBacklogItem(item controlbacklog.Item, format string, key string) Ticket {
	title := fmt.Sprintf("[%s] %s %s", strings.TrimSpace(item.RecommendedAction), strings.TrimSpace(item.Repo), strings.TrimSpace(item.Path))
	body := strings.Join([]string{
		"Owner: " + strings.TrimSpace(item.Owner),
		"Recommended action: " + strings.TrimSpace(item.RecommendedAction),
		"SLA: " + strings.TrimSpace(item.SLA),
		"Closure criteria: " + strings.TrimSpace(item.ClosureCriteria),
		"Evidence: " + strings.Join(item.EvidenceBasis, ", "),
	}, "\n")
	return Ticket{
		ID:                "tkt-" + hashKey(format+"|"+key),
		Title:             title,
		Owner:             strings.TrimSpace(item.Owner),
		Repo:              strings.TrimSpace(item.Repo),
		Path:              strings.TrimSpace(item.Path),
		ControlPathType:   strings.TrimSpace(item.ControlPathType),
		Capability:        strings.TrimSpace(item.Capability),
		Evidence:          append([]string(nil), item.EvidenceBasis...),
		RecommendedAction: strings.TrimSpace(item.RecommendedAction),
		SLA:               strings.TrimSpace(item.SLA),
		ClosureCriteria:   strings.TrimSpace(item.ClosureCriteria),
		Confidence:        strings.TrimSpace(item.Confidence),
		ProofRequirements: proofRequirements(item),
		Body:              body,
	}
}

func ticketGroupKey(item controlbacklog.Item) string {
	return strings.Join([]string{
		strings.TrimSpace(item.Owner),
		strings.TrimSpace(item.Repo),
		strings.TrimSpace(item.ControlPathType),
		strings.TrimSpace(item.Path),
	}, "|")
}

func proofRequirements(item controlbacklog.Item) []string {
	values := []string{"owner", "approval", "review_cadence"}
	if strings.Contains(strings.ToLower(item.ClosureCriteria), "proof") || strings.TrimSpace(item.RecommendedAction) == "attach_evidence" {
		values = append(values, "proof")
	}
	sort.Strings(values)
	return values
}

func actionPriority(action string) int {
	switch strings.TrimSpace(action) {
	case "remediate":
		return 0
	case "approve":
		return 1
	case "attach_evidence":
		return 2
	case "inventory_review":
		return 3
	default:
		return 4
	}
}

func hashKey(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum[:6])
}
