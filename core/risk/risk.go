package risk

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk/autonomy"
	"github.com/Clyra-AI/wrkr/core/risk/classify"
)

type ScoredFinding struct {
	CanonicalKey  string        `json:"canonical_key"`
	Score         float64       `json:"risk_score"`
	BlastRadius   float64       `json:"blast_radius"`
	Privilege     float64       `json:"privilege_level"`
	TrustDeficit  float64       `json:"trust_deficit"`
	EndpointClass string        `json:"endpoint_class"`
	DataClass     string        `json:"data_class"`
	AutonomyLevel string        `json:"autonomy_level"`
	Reasons       []string      `json:"reasons"`
	Finding       model.Finding `json:"finding"`
}

type RepoAggregate struct {
	Org      string  `json:"org"`
	Repo     string  `json:"repo"`
	Score    float64 `json:"combined_risk_score"`
	Autonomy string  `json:"highest_autonomy"`
}

type Report struct {
	GeneratedAt string          `json:"generated_at"`
	TopN        []ScoredFinding `json:"top_findings"`
	Ranked      []ScoredFinding `json:"ranked_findings"`
	Repos       []RepoAggregate `json:"repo_risk"`
}

func Score(findings []model.Finding, topN int, now time.Time) Report {
	items := make([]ScoredFinding, 0, len(findings))
	for _, finding := range findings {
		items = append(items, scoreFinding(finding))
	}
	items = correlateSkillConflicts(items)
	sortRanked(items)

	if topN <= 0 || topN > len(items) {
		topN = len(items)
	}
	top := append([]ScoredFinding(nil), items[:topN]...)

	repoScores := aggregateRepos(items)
	sort.Slice(repoScores, func(i, j int) bool {
		if repoScores[i].Score != repoScores[j].Score {
			return repoScores[i].Score > repoScores[j].Score
		}
		if repoScores[i].Org != repoScores[j].Org {
			return repoScores[i].Org < repoScores[j].Org
		}
		return repoScores[i].Repo < repoScores[j].Repo
	})

	generatedAt := now.UTC()
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC().Truncate(time.Second)
	}

	return Report{
		GeneratedAt: generatedAt.Format(time.RFC3339),
		TopN:        top,
		Ranked:      items,
		Repos:       repoScores,
	}
}

func scoreFinding(finding model.Finding) ScoredFinding {
	endpointClass := classify.EndpointClass(finding)
	dataClass := classify.DataClass(finding)
	autonomyLevel := classify.AutonomyLevel(finding)

	blast := blastRadius(finding, endpointClass)
	privilege := privilegeLevel(finding)
	trustDeficit := trustDeficit(finding, dataClass)
	score := blast + privilege + trustDeficit

	reasons := []string{
		fmt.Sprintf("blast_radius=%.2f", blast),
		fmt.Sprintf("privilege_level=%.2f", privilege),
		fmt.Sprintf("trust_deficit=%.2f", trustDeficit),
	}

	if autonomyMultiplier := autonomyFactor(autonomyLevel); autonomyMultiplier > 1 {
		score = score * autonomyMultiplier
		reasons = append(reasons, fmt.Sprintf("autonomy_multiplier=%.2f", autonomyMultiplier))
	}

	if finding.FindingType == "compiled_action" {
		score = score * compiledActionFactor(finding)
		reasons = append(reasons, "compiled_action_amplification")
	}

	if finding.FindingType == "policy_violation" {
		contribution := severityBase(finding.Severity) * 0.6
		score += contribution
		reasons = append(reasons, fmt.Sprintf("policy_violation_contribution=%.2f", contribution))
	}

	if finding.FindingType == "skill_policy_conflict" {
		if score < 8.5 {
			score = 8.5
		}
		reasons = append(reasons, "skill_policy_conflict_high_severity")
	}

	if finding.FindingType == "skill_metrics" {
		if hasPermission(finding.Permissions, "proc.exec") {
			score += 1.5
			reasons = append(reasons, "skill_ceiling_exec_present")
		}
		ratio := evidenceFloat(finding, "skill_privilege_concentration.exec_write_ratio")
		score += ratio * 2
		reasons = append(reasons, fmt.Sprintf("skill_concentration=%.2f", ratio))

		exec := evidenceFloat(finding, "skill_sprawl.exec")
		write := evidenceFloat(finding, "skill_sprawl.write")
		total := evidenceFloat(finding, "skill_sprawl.total")
		if total > 0 && (exec+write)/total > 0.5 {
			score += 1.2
			reasons = append(reasons, "skill_sprawl_exec_write_over_50_percent")
		}
	}

	if score > 10 {
		score = 10
	}

	return ScoredFinding{
		CanonicalKey:  canonicalKey(finding),
		Score:         round2(score),
		BlastRadius:   round2(blast),
		Privilege:     round2(privilege),
		TrustDeficit:  round2(trustDeficit),
		EndpointClass: endpointClass,
		DataClass:     dataClass,
		AutonomyLevel: autonomyLevel,
		Reasons:       reasons,
		Finding:       finding,
	}
}

func correlateSkillConflicts(in []ScoredFinding) []ScoredFinding {
	byKey := map[string]ScoredFinding{}
	for _, item := range in {
		existing, exists := byKey[item.CanonicalKey]
		if !exists {
			byKey[item.CanonicalKey] = item
			continue
		}
		if item.Score > existing.Score {
			existing = item
		}
		existing.Reasons = mergeReasons(existing.Reasons, item.Reasons)
		byKey[item.CanonicalKey] = existing
	}
	out := make([]ScoredFinding, 0, len(byKey))
	for _, item := range byKey {
		out = append(out, item)
	}
	return out
}

func mergeReasons(a, b []string) []string {
	set := map[string]struct{}{}
	for _, item := range a {
		set[item] = struct{}{}
	}
	for _, item := range b {
		set[item] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func sortRanked(items []ScoredFinding) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Score != items[j].Score {
			return items[i].Score > items[j].Score
		}
		if autonomyRank(items[i].AutonomyLevel) != autonomyRank(items[j].AutonomyLevel) {
			return autonomyRank(items[i].AutonomyLevel) > autonomyRank(items[j].AutonomyLevel)
		}
		a := items[i].Finding
		b := items[j].Finding
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) < severityRank(b.Severity)
		}
		if a.FindingType != b.FindingType {
			return a.FindingType < b.FindingType
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.ToolType != b.ToolType {
			return a.ToolType < b.ToolType
		}
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		if a.Repo != b.Repo {
			return a.Repo < b.Repo
		}
		return a.Org < b.Org
	})
}

func aggregateRepos(items []ScoredFinding) []RepoAggregate {
	type stat struct {
		total    float64
		count    float64
		max      float64
		autonomy string
	}
	stats := map[string]stat{}
	for _, item := range items {
		repo := strings.TrimSpace(item.Finding.Repo)
		org := strings.TrimSpace(item.Finding.Org)
		if repo == "" {
			continue
		}
		key := org + "::" + repo
		current := stats[key]
		current.total += item.Score
		current.count++
		if item.Score > current.max {
			current.max = item.Score
		}
		if autonomyRank(item.AutonomyLevel) > autonomyRank(current.autonomy) {
			current.autonomy = item.AutonomyLevel
		}
		stats[key] = current
	}

	out := make([]RepoAggregate, 0, len(stats))
	for key, current := range stats {
		parts := strings.SplitN(key, "::", 2)
		avg := 0.0
		if current.count > 0 {
			avg = current.total / current.count
		}
		score := current.max + (avg * 0.25)
		score = score * autonomyFactor(current.autonomy)
		if score > 10 {
			score = 10
		}
		out = append(out, RepoAggregate{Org: parts[0], Repo: parts[1], Score: round2(score), Autonomy: current.autonomy})
	}
	return out
}

func canonicalKey(finding model.Finding) string {
	if (finding.FindingType == "policy_violation" || finding.FindingType == "policy_check") && finding.RuleID == "WRKR-014" {
		return "skill_policy_conflict:" + finding.Org + ":" + finding.Repo
	}
	if finding.FindingType == "skill_policy_conflict" {
		return "skill_policy_conflict:" + finding.Org + ":" + finding.Repo
	}
	return strings.Join([]string{finding.FindingType, finding.RuleID, finding.ToolType, finding.Location, finding.Repo, finding.Org}, "|")
}

func blastRadius(finding model.Finding, endpointClass string) float64 {
	base := severityBase(finding.Severity)
	if endpointClass == "ci_pipeline" {
		base += 1.8
	}
	if endpointClass == "network_service" {
		base += 1.2
	}
	if finding.FindingType == "compiled_action" {
		base += 0.8
	}
	return base
}

func privilegeLevel(finding model.Finding) float64 {
	level := 1.0
	for _, permission := range finding.Permissions {
		normalized := strings.ToLower(strings.TrimSpace(permission))
		switch {
		case strings.Contains(normalized, "proc.exec"):
			level += 2.4
		case strings.Contains(normalized, "filesystem.write"):
			level += 1.8
		case strings.Contains(normalized, "db.write"):
			level += 2.1
		case strings.Contains(normalized, "secret.read"):
			level += 2.0
		case strings.Contains(normalized, "headless.execute"):
			level += 1.3
		default:
			level += 0.4
		}
	}
	if finding.FindingType == "secret_presence" {
		level += 2.0
	}
	return level
}

func trustDeficit(finding model.Finding, dataClass string) float64 {
	deficit := 0.8
	if finding.FindingType == "parse_error" {
		deficit += 1.2
	}
	if finding.FindingType == "policy_violation" {
		deficit += 1.8
	}
	if finding.FindingType == "skill_policy_conflict" {
		deficit += 2.4
	}
	if finding.FindingType == "mcp_server" {
		trust := evidenceFloat(finding, "trust_score")
		if trust > 0 {
			deficit += (10 - trust) / 3
		}
	}
	if coverage := evidenceString(finding, "coverage"); coverage != "" {
		switch coverage {
		case "unprotected":
			deficit += 1.8
		case "unknown":
			deficit += 1.0
		case "protected":
			deficit -= 0.4
		}
	}
	if posture := evidenceString(finding, "policy_posture"); posture == "allow" {
		deficit += 0.6
	}
	if dataClass == "credentials" {
		deficit += 1.4
	}
	if hasFindingTypeHint(finding, "gait_policy") {
		deficit -= 0.6
	}
	if deficit < 0.2 {
		deficit = 0.2
	}
	return deficit
}

func hasFindingTypeHint(finding model.Finding, hint string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(finding.ToolType)), strings.ToLower(strings.TrimSpace(hint)))
}

func compiledActionFactor(finding model.Finding) float64 {
	sequence := evidenceString(finding, "tool_sequence")
	if strings.Contains(sequence, "gait.eval.script") || strings.Contains(sequence, "mcp") {
		return 1.35
	}
	if strings.Contains(sequence, "claude") || strings.Contains(sequence, "codex") {
		return 1.2
	}
	return 1.1
}

func autonomyFactor(level string) float64 {
	switch level {
	case autonomy.LevelHeadlessAuto:
		return 1.7
	case autonomy.LevelHeadlessGate:
		return 1.35
	case autonomy.LevelCopilot:
		return 1.1
	default:
		return 1
	}
}

func autonomyRank(level string) int {
	switch level {
	case autonomy.LevelHeadlessAuto:
		return 4
	case autonomy.LevelHeadlessGate:
		return 3
	case autonomy.LevelCopilot:
		return 2
	case autonomy.LevelInteractive:
		return 1
	default:
		return 0
	}
}

func severityBase(severity string) float64 {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case model.SeverityCritical:
		return 4.8
	case model.SeverityHigh:
		return 3.8
	case model.SeverityMedium:
		return 2.8
	case model.SeverityLow:
		return 1.8
	default:
		return 1.0
	}
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case model.SeverityCritical:
		return 0
	case model.SeverityHigh:
		return 1
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 3
	default:
		return 4
	}
}

func hasPermission(permissions []string, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	for _, permission := range permissions {
		if strings.ToLower(strings.TrimSpace(permission)) == needle {
			return true
		}
	}
	return false
}

func evidenceString(finding model.Finding, key string) string {
	needle := strings.ToLower(strings.TrimSpace(key))
	for _, item := range finding.Evidence {
		if strings.ToLower(strings.TrimSpace(item.Key)) == needle {
			return strings.ToLower(strings.TrimSpace(item.Value))
		}
	}
	return ""
}

func evidenceFloat(finding model.Finding, key string) float64 {
	value := evidenceString(finding, key)
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func round2(in float64) float64 {
	parsed, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", in), 64)
	return parsed
}
