package risk

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/model"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
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
	GeneratedAt              string                    `json:"generated_at"`
	TopN                     []ScoredFinding           `json:"top_findings"`
	Ranked                   []ScoredFinding           `json:"ranked_findings"`
	Repos                    []RepoAggregate           `json:"repo_risk"`
	AttackPaths              []riskattack.ScoredPath   `json:"attack_paths,omitempty"`
	TopAttackPaths           []riskattack.ScoredPath   `json:"top_attack_paths,omitempty"`
	ActionPaths              []ActionPath              `json:"action_paths,omitempty"`
	ActionPathToControlFirst *ActionPathToControlFirst `json:"action_path_to_control_first,omitempty"`
}

type promptCooccurrence struct {
	HeadlessCIAutonomy bool
	SecretPresence     bool
	ProductionWrite    bool
}

func Score(findings []model.Finding, topN int, now time.Time) Report {
	cooccurrenceByRepo := buildPromptCooccurrence(findings)

	items := make([]ScoredFinding, 0, len(findings))
	for _, finding := range findings {
		items = append(items, scoreFinding(finding, cooccurrenceByRepo[repoKey(finding.Org, finding.Repo)]))
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

	attackGraphs := aggattack.Build(findings)
	attackPaths := riskattack.Score(attackGraphs)
	topAttackPaths := append([]riskattack.ScoredPath(nil), attackPaths...)
	if topN > 0 && topN < len(topAttackPaths) {
		topAttackPaths = topAttackPaths[:topN]
	}

	return Report{
		GeneratedAt:    generatedAt.Format(time.RFC3339),
		TopN:           top,
		Ranked:         items,
		Repos:          repoScores,
		AttackPaths:    attackPaths,
		TopAttackPaths: topAttackPaths,
	}
}

func scoreFinding(finding model.Finding, cooccurrence promptCooccurrence) ScoredFinding {
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
	if finding.FindingType == "mcp_server" && evidenceString(finding, "enrich_mode") == "true" {
		enrichQuality := normalizedEnrichQuality(evidenceString(finding, "enrich_quality"))
		reasons = append(reasons, fmt.Sprintf("mcp_enrich_quality=%s", enrichQuality))
		if enrichQuality != "unavailable" {
			advisoryCount := evidenceFloat(finding, "advisory_count")
			if advisoryCount > 0 {
				reasons = append(reasons, fmt.Sprintf("mcp_enrich_advisory_count=%.0f", advisoryCount))
			}
			registryStatus := evidenceString(finding, "registry_status")
			if registryStatus != "" {
				reasons = append(reasons, fmt.Sprintf("mcp_enrich_registry_status=%s", registryStatus))
			}
		}
	}
	if isPromptChannelFinding(finding) {
		promptMultiplier := 1.0
		if cooccurrence.HeadlessCIAutonomy {
			promptMultiplier += 0.35
			reasons = append(reasons, "prompt_channel_with_ci_autonomy")
		}
		if cooccurrence.SecretPresence {
			promptMultiplier += 0.30
			reasons = append(reasons, "prompt_channel_with_secret_presence")
		}
		if cooccurrence.ProductionWrite {
			promptMultiplier += 0.35
			reasons = append(reasons, "prompt_channel_with_production_write")
		}
		if promptMultiplier > 1 {
			score = score * promptMultiplier
			reasons = append(reasons, fmt.Sprintf("prompt_channel_correlation_multiplier=%.2f", promptMultiplier))
		}
	}
	if agentMultiplier, agentReasons := agentAmplification(finding); agentMultiplier > 1 {
		score = score * agentMultiplier
		reasons = append(reasons, agentReasons...)
		reasons = append(reasons, fmt.Sprintf("agent_context_multiplier=%.2f", agentMultiplier))
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

func buildPromptCooccurrence(findings []model.Finding) map[string]promptCooccurrence {
	out := map[string]promptCooccurrence{}
	for _, finding := range findings {
		key := repoKey(finding.Org, finding.Repo)
		current := out[key]
		if finding.FindingType == "ci_autonomy" {
			switch classify.AutonomyLevel(finding) {
			case autonomy.LevelHeadlessAuto, autonomy.LevelHeadlessGate:
				current.HeadlessCIAutonomy = true
			}
		}
		if finding.FindingType == "secret_presence" {
			current.SecretPresence = true
		}
		if hasPermission(finding.Permissions, "filesystem.write") || hasPermission(finding.Permissions, "db.write") || hasPermission(finding.Permissions, "production.write") || evidenceString(finding, "production_write") == "true" {
			current.ProductionWrite = true
		}
		out[key] = current
	}
	return out
}

func repoKey(org string, repo string) string {
	return strings.TrimSpace(org) + "::" + strings.TrimSpace(repo)
}

func isPromptChannelFinding(finding model.Finding) bool {
	if strings.TrimSpace(finding.ToolType) == "prompt_channel" {
		return true
	}
	switch strings.TrimSpace(finding.FindingType) {
	case "prompt_channel_hidden_text", "prompt_channel_override", "prompt_channel_untrusted_context":
		return true
	default:
		return false
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
	parts := []string{finding.FindingType, finding.RuleID, finding.ToolType, finding.Location, finding.Repo, finding.Org}
	if identityComponent := agentIdentityComponent(finding); identityComponent != "" {
		parts = append(parts[:4], append([]string{identityComponent}, parts[4:]...)...)
	}
	return strings.Join(parts, "|")
}

func agentIdentityComponent(finding model.Finding) string {
	if strings.TrimSpace(finding.FindingType) != "agent_framework" {
		return ""
	}
	symbol := evidenceString(finding, "symbol")
	startLine := 0
	endLine := 0
	if finding.LocationRange != nil {
		startLine = finding.LocationRange.StartLine
		endLine = finding.LocationRange.EndLine
	}
	if symbol == "" && startLine == 0 && endLine == 0 {
		return ""
	}
	return identity.AgentInstanceID(finding.ToolType, finding.Location, symbol, startLine, endLine)
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
		if evidenceString(finding, "enrich_mode") == "true" {
			qualityWeight := enrichQualityWeight(normalizedEnrichQuality(evidenceString(finding, "enrich_quality")))
			advisoryCount := evidenceFloat(finding, "advisory_count")
			if advisoryCount > 0 {
				deficit += advisoryCount * 0.2 * qualityWeight
			}
			switch evidenceString(finding, "registry_status") {
			case "listed":
				deficit -= 0.4 * qualityWeight
			case "unlisted":
				deficit += 0.7 * qualityWeight
			case "lookup_error":
				deficit += 0.3 * qualityWeight
			case "unknown":
				deficit += 0.2 * qualityWeight
			}
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

func normalizedEnrichQuality(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ok", "partial", "stale", "unavailable":
		return strings.ToLower(strings.TrimSpace(value))
	case "":
		return "ok"
	default:
		return "partial"
	}
}

func enrichQualityWeight(quality string) float64 {
	switch normalizedEnrichQuality(quality) {
	case "ok":
		return 1.0
	case "partial":
		return 0.6
	case "stale":
		return 0.4
	case "unavailable":
		return 0.0
	default:
		return 0.6
	}
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

func agentAmplification(finding model.Finding) (float64, []string) {
	if strings.TrimSpace(finding.FindingType) != "agent_framework" {
		return 1, nil
	}

	multiplier := 1.0
	reasons := make([]string, 0, 7)

	deploymentStatus := evidenceString(finding, "deployment_status")
	switch deploymentStatus {
	case "deployed":
		multiplier += 0.20
		reasons = append(reasons, "agent_deployment_scope=deployed")
	case "ambiguous":
		multiplier += 0.10
		reasons = append(reasons, "agent_deployment_scope=ambiguous")
	}

	if hasAgentProductionWrite(finding) {
		multiplier += 0.25
		reasons = append(reasons, "agent_production_write")
	}
	if hasAgentDelegation(finding) {
		multiplier += 0.15
		reasons = append(reasons, "agent_delegation_enabled")
	}
	if evidenceBool(finding, "dynamic_discovery") {
		multiplier += 0.15
		reasons = append(reasons, "agent_dynamic_tool_discovery")
	}
	if approval := evidenceString(finding, "approval_status"); approval != "approved" && approval != "valid" {
		multiplier += 0.20
		reasons = append(reasons, "agent_approval_missing")
	}
	if deploymentStatus == "deployed" && !evidenceBool(finding, "kill_switch") {
		multiplier += 0.15
		reasons = append(reasons, "agent_kill_switch_missing")
	}

	if len(reasons) == 0 {
		return 1, nil
	}
	return multiplier, reasons
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

func hasAgentProductionWrite(finding model.Finding) bool {
	return hasPermission(finding.Permissions, "deploy.write") ||
		hasPermission(finding.Permissions, "production.write") ||
		evidenceBool(finding, "auto_deploy") ||
		evidenceString(finding, "deployment_gate") == "open"
}

func hasAgentDelegation(finding model.Finding) bool {
	return evidenceBool(finding, "delegation") || evidenceString(finding, "delegate_to") != ""
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

func evidenceBool(finding model.Finding, key string) bool {
	value := evidenceString(finding, key)
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false
	}
	return parsed
}

func round2(in float64) float64 {
	parsed, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", in), 64)
	return parsed
}
