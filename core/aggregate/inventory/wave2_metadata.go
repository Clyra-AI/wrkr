package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/source"
)

type purposeCandidate struct {
	value      string
	source     string
	confidence string
	rank       int
}

type entityMetadata struct {
	purpose           purposeCandidate
	version           string
	versionSource     string
	configSource      string
	configFingerprint string
}

func applyWave2Metadata(manifest source.Manifest, tools []Tool, agents []Agent, findings []model.Finding) ([]Tool, []Agent) {
	toolMetadata := map[string]entityMetadata{}
	agentMetadata := map[string]entityMetadata{}

	for _, finding := range findings {
		metadata := metadataForFinding(manifest, finding)
		if metadata.empty() {
			continue
		}

		toolID := identity.ToolID(finding.ToolType, finding.Location)
		toolMetadata[toolID] = mergeEntityMetadata(toolMetadata[toolID], metadata)

		startLine, endLine := findingRangeLines(finding)
		instanceID := identity.AgentInstanceID(
			finding.ToolType,
			finding.Location,
			findingAgentSymbol(finding),
			startLine,
			endLine,
		)
		if strings.TrimSpace(instanceID) != "" {
			agentMetadata[instanceID] = mergeEntityMetadata(agentMetadata[instanceID], metadata)
		}
	}

	for idx := range tools {
		if metadata, ok := toolMetadata[strings.TrimSpace(tools[idx].ToolID)]; ok {
			applyEntityMetadataToTool(&tools[idx], metadata)
		}
	}
	for idx := range agents {
		if metadata, ok := agentMetadata[strings.TrimSpace(agents[idx].AgentInstanceID)]; ok {
			applyEntityMetadataToAgent(&agents[idx], metadata)
		}
	}
	return tools, agents
}

func metadataForFinding(manifest source.Manifest, finding model.Finding) entityMetadata {
	evidence := findingEvidenceMap(finding)
	configSource := metadataConfigSource(finding, evidence)
	if annotatedPurpose := purposeAnnotationForFinding(manifest, finding, configSource); annotatedPurpose != "" {
		evidence["purpose"] = append([]string{annotatedPurpose}, evidence["purpose"]...)
	}
	return entityMetadata{
		purpose:           purposeFromFinding(finding, evidence),
		version:           metadataVersion(evidence),
		versionSource:     metadataVersionSource(evidence),
		configSource:      configSource,
		configFingerprint: configFingerprintForFinding(manifest, finding, configSource),
	}
}

func (m entityMetadata) empty() bool {
	return strings.TrimSpace(m.purpose.value) == "" &&
		strings.TrimSpace(m.version) == "" &&
		strings.TrimSpace(m.configSource) == "" &&
		strings.TrimSpace(m.configFingerprint) == ""
}

func mergeEntityMetadata(current, incoming entityMetadata) entityMetadata {
	current.purpose = mergePurposeCandidate(current.purpose, incoming.purpose)
	current.version, current.versionSource = mergeMetadataValue(current.version, current.versionSource, incoming.version, incoming.versionSource)
	if strings.TrimSpace(current.configSource) == "" {
		current.configSource = strings.TrimSpace(incoming.configSource)
		current.configFingerprint = strings.TrimSpace(incoming.configFingerprint)
		return current
	}
	if strings.TrimSpace(incoming.configSource) == "" {
		return current
	}
	if strings.TrimSpace(current.configSource) == strings.TrimSpace(incoming.configSource) {
		if strings.TrimSpace(current.configFingerprint) == "" {
			current.configFingerprint = strings.TrimSpace(incoming.configFingerprint)
		}
		return current
	}
	candidates := []string{strings.TrimSpace(current.configSource), strings.TrimSpace(incoming.configSource)}
	sort.Strings(candidates)
	switch candidates[0] {
	case strings.TrimSpace(current.configSource):
		return current
	default:
		return incoming
	}
}

func mergePurposeCandidate(current, incoming purposeCandidate) purposeCandidate {
	if strings.TrimSpace(current.value) == "" {
		return incoming
	}
	if strings.TrimSpace(incoming.value) == "" {
		return current
	}
	if incoming.rank < current.rank {
		return incoming
	}
	if current.rank < incoming.rank {
		return current
	}
	if strings.EqualFold(strings.TrimSpace(current.value), strings.TrimSpace(incoming.value)) {
		if confidencePriority(incoming.confidence) > confidencePriority(current.confidence) {
			return incoming
		}
		return current
	}
	values := []string{strings.TrimSpace(current.value), strings.TrimSpace(incoming.value)}
	sort.Strings(values)
	return purposeCandidate{
		value:      values[0],
		source:     "conflicting_sources",
		confidence: "low",
		rank:       current.rank,
	}
}

func mergeMetadataValue(currentValue, currentSource, incomingValue, incomingSource string) (string, string) {
	currentValue = strings.TrimSpace(currentValue)
	incomingValue = strings.TrimSpace(incomingValue)
	if currentValue == "" {
		return incomingValue, strings.TrimSpace(incomingSource)
	}
	if incomingValue == "" {
		return currentValue, strings.TrimSpace(currentSource)
	}
	if strings.EqualFold(currentValue, incomingValue) {
		if strings.TrimSpace(currentSource) != "" {
			return currentValue, strings.TrimSpace(currentSource)
		}
		return incomingValue, strings.TrimSpace(incomingSource)
	}
	values := []string{currentValue, incomingValue}
	sort.Strings(values)
	return values[0], "conflicting_sources"
}

func applyEntityMetadataToTool(tool *Tool, metadata entityMetadata) {
	if tool == nil {
		return
	}
	tool.Purpose = strings.TrimSpace(metadata.purpose.value)
	tool.PurposeSource = strings.TrimSpace(metadata.purpose.source)
	tool.PurposeConfidence = strings.TrimSpace(metadata.purpose.confidence)
	tool.Version = strings.TrimSpace(metadata.version)
	tool.VersionSource = strings.TrimSpace(metadata.versionSource)
	tool.ConfigSource = strings.TrimSpace(metadata.configSource)
	tool.ConfigFingerprint = strings.TrimSpace(metadata.configFingerprint)
}

func applyEntityMetadataToAgent(agent *Agent, metadata entityMetadata) {
	if agent == nil {
		return
	}
	agent.Purpose = strings.TrimSpace(metadata.purpose.value)
	agent.PurposeSource = strings.TrimSpace(metadata.purpose.source)
	agent.PurposeConfidence = strings.TrimSpace(metadata.purpose.confidence)
	agent.Version = strings.TrimSpace(metadata.version)
	agent.VersionSource = strings.TrimSpace(metadata.versionSource)
	agent.ConfigSource = strings.TrimSpace(metadata.configSource)
	agent.ConfigFingerprint = strings.TrimSpace(metadata.configFingerprint)
}

func findingEvidenceMap(finding model.Finding) map[string][]string {
	out := map[string][]string{}
	for _, item := range finding.Evidence {
		key := strings.ToLower(strings.TrimSpace(item.Key))
		value := strings.TrimSpace(item.Value)
		if key == "" || value == "" {
			continue
		}
		out[key] = append(out[key], value)
	}
	for key, values := range out {
		out[key] = dedupeMetadataValues(values)
	}
	return out
}

func purposeFromFinding(finding model.Finding, evidence map[string][]string) purposeCandidate {
	candidates := []purposeCandidate{}
	add := func(value string, source string, confidence string, rank int) {
		value = normalizePurposeValue(value)
		if value == "" {
			return
		}
		candidates = append(candidates, purposeCandidate{value: value, source: source, confidence: confidence, rank: rank})
	}

	add(firstMetadataValue(evidence, "purpose"), "annotation", "high", 0)
	add(firstMetadataValue(evidence, "workflow_name"), "workflow_name", "high", 1)
	add(firstMetadataValue(evidence, "server_description"), "server_description", "high", 1)
	add(firstMetadataValue(evidence, "name"), "name", "medium", 2)
	add(firstMetadataValue(evidence, "server"), "server_name", "medium", 2)
	add(firstWorkflowJob(evidence), "workflow_job", "medium", 3)
	add(findingAgentSymbol(finding), "symbol", "medium", 3)
	add(locationPurpose(finding.Location), "location_heuristic", "low", 4)

	if len(candidates) == 0 {
		return purposeCandidate{}
	}
	chosen := candidates[0]
	for _, candidate := range candidates[1:] {
		chosen = mergePurposeCandidate(chosen, candidate)
	}
	return chosen
}

func firstWorkflowJob(evidence map[string][]string) string {
	values := evidence["workflow_jobs"]
	if len(values) == 0 {
		return ""
	}
	jobs := []string{}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				jobs = append(jobs, trimmed)
			}
		}
	}
	jobs = dedupeMetadataValues(jobs)
	if len(jobs) == 0 {
		return ""
	}
	return jobs[0]
}

func normalizePurposeValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.EqualFold(trimmed, "unknown") {
		return ""
	}
	trimmed = strings.Trim(trimmed, "\"'`")
	replacer := strings.NewReplacer("_", " ", "-", " ", ".yml", "", ".yaml", "", ".json", "", ".toml", "", ".md", "")
	trimmed = strings.TrimSpace(replacer.Replace(trimmed))
	trimmed = strings.Join(strings.Fields(trimmed), " ")
	return trimmed
}

func purposeAnnotationForFinding(manifest source.Manifest, finding model.Finding, configSource string) string {
	rel := strings.TrimSpace(configSource)
	if before, _, ok := strings.Cut(rel, "#"); ok {
		rel = strings.TrimSpace(before)
	}
	if rel == "" {
		rel = strings.TrimSpace(finding.Location)
	}
	root := repoRoot(manifest, finding.Repo)
	path, ok := safeRepoRelativePath(root, rel)
	if !ok {
		return ""
	}
	// #nosec G304 -- safeRepoRelativePath confines rel under the repository root before reading.
	payload, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return purposeAnnotationFromText(string(payload))
}

func purposeAnnotationFromText(content string) string {
	const marker = "wrkr:purpose"
	for _, line := range strings.Split(content, "\n") {
		idx := strings.Index(strings.ToLower(line), marker)
		if idx < 0 {
			continue
		}
		value := strings.TrimSpace(line[idx+len(marker):])
		value = strings.TrimLeft(value, " \t:=#-/")
		value = normalizePurposeValue(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func locationPurpose(location string) string {
	lower := strings.ToLower(strings.TrimSpace(location))
	switch {
	case strings.Contains(lower, "release"):
		return "release automation"
	case strings.Contains(lower, "deploy"):
		return "deployment automation"
	case strings.Contains(lower, "migrate"):
		return "database migration"
	case strings.Contains(lower, ".github/workflows"):
		return "workflow automation"
	case strings.Contains(lower, "mcp"):
		return "mcp integration"
	case strings.Contains(lower, "skill"):
		return "skill automation"
	default:
		return ""
	}
}

func metadataVersion(evidence map[string][]string) string {
	version := firstMetadataValue(evidence, "version")
	if strings.EqualFold(version, "unknown") {
		return ""
	}
	return strings.TrimSpace(version)
}

func metadataVersionSource(evidence map[string][]string) string {
	source := firstMetadataValue(evidence, "version_source")
	if strings.TrimSpace(source) != "" {
		return strings.TrimSpace(source)
	}
	if firstMetadataValue(evidence, "version") != "" {
		return "detector_evidence"
	}
	return ""
}

func metadataConfigSource(finding model.Finding, evidence map[string][]string) string {
	if value := firstMetadataValue(evidence, "declaration_path"); value != "" {
		return strings.TrimSpace(value)
	}
	location := strings.TrimSpace(finding.Location)
	if location == "" {
		return ""
	}
	if server := firstMetadataValue(evidence, "server"); server != "" && strings.TrimSpace(finding.ToolType) == "mcp" {
		return location + "#server:" + strings.TrimSpace(server)
	}
	return location
}

func configFingerprintForFinding(manifest source.Manifest, finding model.Finding, configSource string) string {
	configSource = strings.TrimSpace(configSource)
	if configSource == "" {
		return ""
	}
	rel := configSource
	if before, _, ok := strings.Cut(configSource, "#"); ok {
		rel = before
	}
	root := repoRoot(manifest, finding.Repo)
	return configFingerprintForFile(root, rel)
}

func configFingerprintForFile(root string, rel string) string {
	path, ok := safeRepoRelativePath(root, rel)
	if !ok {
		return ""
	}
	// #nosec G304 -- safeRepoRelativePath confines rel under the repository root before reading.
	payload, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return configFingerprintForBytes(payload)
}

func safeRepoRelativePath(root string, rel string) (string, bool) {
	root = filepath.Clean(strings.TrimSpace(root))
	if root == "." || root == "" {
		return "", false
	}
	cleaned := filepath.Clean(filepath.FromSlash(strings.TrimSpace(rel)))
	if cleaned == "." || cleaned == "" || filepath.IsAbs(cleaned) {
		return "", false
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", false
	}
	candidate := filepath.Join(root, cleaned)
	relativeToRoot, err := filepath.Rel(root, candidate)
	if err != nil {
		return "", false
	}
	relativeToRoot = filepath.Clean(relativeToRoot)
	if relativeToRoot == ".." || strings.HasPrefix(relativeToRoot, ".."+string(filepath.Separator)) {
		return "", false
	}
	return candidate, true
}

func configFingerprintForBytes(payload []byte) string {
	normalized := strings.ReplaceAll(string(payload), "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	sum := sha256.Sum256([]byte(normalized))
	return "cfg-" + hex.EncodeToString(sum[:6])
}

func dedupeMetadataValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := set[trimmed]; ok {
			continue
		}
		set[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func firstMetadataValue(evidence map[string][]string, key string) string {
	values := evidence[strings.ToLower(strings.TrimSpace(key))]
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func confidencePriority(value string) int {
	switch strings.TrimSpace(value) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
