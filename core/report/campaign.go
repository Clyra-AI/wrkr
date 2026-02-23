package report

import (
	"fmt"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/source"
)

type CampaignScanInput struct {
	Path            string
	Target          source.Target
	SourceManifest  source.Manifest
	Inventory       *agginventory.Inventory
	PrivilegeBudget agginventory.PrivilegeBudget
	Findings        []source.Finding
}

type CampaignOptions struct {
	SegmentMetadata map[string]SegmentMetadata
}

type SegmentMetadata struct {
	Industry string
	SizeBand string
}

type CampaignArtifact struct {
	SchemaVersion string               `json:"schema_version"`
	GeneratedAt   string               `json:"generated_at"`
	InputGlob     string               `json:"input_glob,omitempty"`
	Methodology   CampaignMethodology  `json:"methodology"`
	Metrics       CampaignMetrics      `json:"metrics"`
	Segments      CampaignSegments     `json:"segments"`
	Scans         []CampaignScanResult `json:"scans"`
}

type CampaignMethodology struct {
	WrkrVersion        string             `json:"wrkr_version"`
	ScanCount          int                `json:"scan_count"`
	RepoCount          int                `json:"repo_count"`
	FileCountProcessed int                `json:"file_count_processed"`
	Detectors          []CampaignDetector `json:"detectors"`
}

type CampaignDetector struct {
	ID           string `json:"id"`
	Version      string `json:"version"`
	FindingCount int    `json:"finding_count"`
}

type CampaignMetrics struct {
	ReposScanned          int      `json:"repos_scanned"`
	ToolsDetectedTotal    int      `json:"tools_detected_total"`
	WriteCapableTools     int      `json:"write_capable_tools"`
	CredentialAccessTools int      `json:"credential_access_tools"`
	ExecCapableTools      int      `json:"exec_capable_tools"`
	ApprovedTools         int      `json:"approved_tools"`
	UnapprovedTools       int      `json:"unapproved_tools"`
	UnknownTools          int      `json:"unknown_tools"`
	ApprovedPercent       float64  `json:"approved_percent"`
	UnapprovedPercent     float64  `json:"unapproved_percent"`
	UnknownPercent        float64  `json:"unknown_percent"`
	UnapprovedPerApproved *float64 `json:"unapproved_per_approved"`
	ProductionWriteStatus string   `json:"production_write_status"`
	ProductionWriteTools  *int     `json:"production_write_tools"`
}

type CampaignScanResult struct {
	Path                 string `json:"path"`
	TargetMode           string `json:"target_mode"`
	TargetValue          string `json:"target_value"`
	RepoCount            int    `json:"repo_count"`
	ToolsDetected        int    `json:"tools_detected"`
	WriteCapableTools    int    `json:"write_capable_tools"`
	CredentialAccessTool int    `json:"credential_access_tools"`
	ExecCapableTools     int    `json:"exec_capable_tools"`
}

type CampaignSegments struct {
	OrgSizeBands  []CampaignSegmentBucket `json:"org_size_bands"`
	IndustryBands []CampaignSegmentBucket `json:"industry_bands"`
}

type CampaignSegmentBucket struct {
	Segment   string `json:"segment"`
	OrgCount  int    `json:"org_count"`
	ToolCount int    `json:"tool_count"`
}

func AggregateCampaign(inputs []CampaignScanInput, generatedAt time.Time) CampaignArtifact {
	return AggregateCampaignWithOptions(inputs, generatedAt, CampaignOptions{})
}

func AggregateCampaignWithOptions(inputs []CampaignScanInput, generatedAt time.Time, opts CampaignOptions) CampaignArtifact {
	sortedInputs := append([]CampaignScanInput(nil), inputs...)
	sort.Slice(sortedInputs, func(i, j int) bool {
		return sortedInputs[i].Path < sortedInputs[j].Path
	})
	now := generatedAt.UTC().Truncate(time.Second)
	segmentMetadata := normalizeSegmentMetadata(opts.SegmentMetadata)

	repos := map[string]struct{}{}
	files := map[string]struct{}{}
	detectorCounts := map[string]int{}
	scans := make([]CampaignScanResult, 0, len(sortedInputs))

	totalTools := 0
	writeCapable := 0
	credentialAccess := 0
	execCapable := 0
	approvedTools := 0
	unapprovedTools := 0
	unknownTools := 0
	productionStatus := agginventory.ProductionTargetsStatusConfigured
	productionSum := 0
	orgStats := map[string]*campaignOrgStats{}

	for _, in := range sortedInputs {
		for _, repo := range in.SourceManifest.Repos {
			if strings.TrimSpace(repo.Repo) == "" {
				continue
			}
			repos[repo.Repo] = struct{}{}
		}
		for _, finding := range in.Findings {
			key := strings.TrimSpace(finding.Repo) + "::" + strings.TrimSpace(finding.Location)
			if strings.TrimSpace(finding.Location) != "" && strings.TrimSpace(finding.Repo) != "" {
				files[key] = struct{}{}
			}
			detector := strings.TrimSpace(finding.Detector)
			if detector == "" {
				detector = "unknown"
			}
			detectorCounts[detector]++
		}

		toolCount := in.PrivilegeBudget.TotalTools
		if in.Inventory != nil {
			toolCount = len(in.Inventory.Tools)
		}
		totalTools += toolCount
		writeCapable += in.PrivilegeBudget.WriteCapableTools
		credentialAccess += in.PrivilegeBudget.CredentialAccessTools
		execCapable += in.PrivilegeBudget.ExecCapableTools
		if in.Inventory != nil {
			approvedTools += in.Inventory.ApprovalSummary.ApprovedTools
			unapprovedTools += in.Inventory.ApprovalSummary.UnapprovedTools
			unknownTools += in.Inventory.ApprovalSummary.UnknownTools
		}
		accumulateOrgStats(orgStats, in, toolCount)

		status := normalizeCampaignProductionStatus(in.PrivilegeBudget)
		switch status {
		case agginventory.ProductionTargetsStatusConfigured:
			if in.PrivilegeBudget.ProductionWrite.Count != nil {
				productionSum += *in.PrivilegeBudget.ProductionWrite.Count
			}
		case agginventory.ProductionTargetsStatusInvalid:
			productionStatus = agginventory.ProductionTargetsStatusInvalid
		default:
			if productionStatus != agginventory.ProductionTargetsStatusInvalid {
				productionStatus = agginventory.ProductionTargetsStatusNotConfigured
			}
		}

		scans = append(scans, CampaignScanResult{
			Path:                 filepath.ToSlash(filepath.Clean(in.Path)),
			TargetMode:           strings.TrimSpace(in.Target.Mode),
			TargetValue:          strings.TrimSpace(in.Target.Value),
			RepoCount:            len(in.SourceManifest.Repos),
			ToolsDetected:        toolCount,
			WriteCapableTools:    in.PrivilegeBudget.WriteCapableTools,
			CredentialAccessTool: in.PrivilegeBudget.CredentialAccessTools,
			ExecCapableTools:     in.PrivilegeBudget.ExecCapableTools,
		})
	}

	detectors := make([]CampaignDetector, 0, len(detectorCounts))
	for id, count := range detectorCounts {
		detectors = append(detectors, CampaignDetector{ID: id, Version: "v1", FindingCount: count})
	}
	sort.Slice(detectors, func(i, j int) bool { return detectors[i].ID < detectors[j].ID })

	var productionWriteTools *int
	if productionStatus == agginventory.ProductionTargetsStatusConfigured {
		value := productionSum
		productionWriteTools = &value
	}
	approvedPercent, unapprovedPercent, unknownPercent, unapprovedPerApproved := approvalRatios(approvedTools, unapprovedTools, unknownTools)
	segments := buildSegments(orgStats, segmentMetadata)

	return CampaignArtifact{
		SchemaVersion: SummaryVersion,
		GeneratedAt:   now.Format(time.RFC3339),
		Methodology: CampaignMethodology{
			WrkrVersion:        wrkrVersion(),
			ScanCount:          len(sortedInputs),
			RepoCount:          len(repos),
			FileCountProcessed: len(files),
			Detectors:          detectors,
		},
		Metrics: CampaignMetrics{
			ReposScanned:          len(repos),
			ToolsDetectedTotal:    totalTools,
			WriteCapableTools:     writeCapable,
			CredentialAccessTools: credentialAccess,
			ExecCapableTools:      execCapable,
			ApprovedTools:         approvedTools,
			UnapprovedTools:       unapprovedTools,
			UnknownTools:          unknownTools,
			ApprovedPercent:       approvedPercent,
			UnapprovedPercent:     unapprovedPercent,
			UnknownPercent:        unknownPercent,
			UnapprovedPerApproved: unapprovedPerApproved,
			ProductionWriteStatus: productionStatus,
			ProductionWriteTools:  productionWriteTools,
		},
		Segments: segments,
		Scans:    scans,
	}
}

func approvalRatios(approved, unapproved, unknown int) (float64, float64, float64, *float64) {
	total := approved + unapproved + unknown
	if total <= 0 {
		return 0, 0, 0, nil
	}
	approvedPercent := round2Campaign(float64(approved) / float64(total) * 100)
	unapprovedPercent := round2Campaign(float64(unapproved) / float64(total) * 100)
	unknownPercent := round2Campaign(float64(unknown) / float64(total) * 100)
	var unapprovedPerApproved *float64
	if approved > 0 {
		value := round2Campaign(float64(unapproved) / float64(approved))
		unapprovedPerApproved = &value
	}
	return approvedPercent, unapprovedPercent, unknownPercent, unapprovedPerApproved
}

func round2Campaign(value float64) float64 {
	return float64(int(value*100+0.5)) / 100
}

func normalizeCampaignProductionStatus(budget agginventory.PrivilegeBudget) string {
	status := strings.TrimSpace(budget.ProductionWrite.Status)
	switch status {
	case agginventory.ProductionTargetsStatusConfigured, agginventory.ProductionTargetsStatusNotConfigured, agginventory.ProductionTargetsStatusInvalid:
		return status
	default:
		if budget.ProductionWrite.Configured {
			return agginventory.ProductionTargetsStatusConfigured
		}
		return agginventory.ProductionTargetsStatusNotConfigured
	}
}

func wrkrVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "devel"
	}
	version := strings.TrimSpace(info.Main.Version)
	if version == "" || version == "(devel)" {
		return "devel"
	}
	return version
}

type campaignOrgStats struct {
	Repos map[string]struct{}
	Tools int
}

func accumulateOrgStats(store map[string]*campaignOrgStats, in CampaignScanInput, toolCount int) {
	org := deriveOrgKey(in)
	entry, ok := store[org]
	if !ok {
		entry = &campaignOrgStats{Repos: map[string]struct{}{}}
		store[org] = entry
	}
	for _, repo := range in.SourceManifest.Repos {
		normalized := strings.TrimSpace(repo.Repo)
		if normalized == "" {
			continue
		}
		entry.Repos[normalized] = struct{}{}
	}
	entry.Tools += toolCount
}

func deriveOrgKey(in CampaignScanInput) string {
	if strings.EqualFold(strings.TrimSpace(in.Target.Mode), "org") && strings.TrimSpace(in.Target.Value) != "" {
		return strings.ToLower(strings.TrimSpace(in.Target.Value))
	}
	for _, repo := range in.SourceManifest.Repos {
		parts := strings.Split(strings.TrimSpace(repo.Repo), "/")
		if len(parts) >= 2 && strings.TrimSpace(parts[0]) != "" {
			return strings.ToLower(strings.TrimSpace(parts[0]))
		}
	}
	target := strings.TrimSpace(in.Target.Value)
	if strings.Contains(target, "/") {
		return strings.ToLower(strings.TrimSpace(strings.Split(target, "/")[0]))
	}
	if target != "" {
		return strings.ToLower(target)
	}
	return "local"
}

func buildSegments(stats map[string]*campaignOrgStats, metadata map[string]SegmentMetadata) CampaignSegments {
	sizeBuckets := map[string]*CampaignSegmentBucket{}
	industryBuckets := map[string]*CampaignSegmentBucket{}

	orgKeys := make([]string, 0, len(stats))
	for org := range stats {
		orgKeys = append(orgKeys, org)
	}
	sort.Strings(orgKeys)
	for _, org := range orgKeys {
		entry := stats[org]
		repoCount := len(entry.Repos)
		size := sizeBand(repoCount)
		industry := inferIndustry(org)
		if configured, ok := metadata[org]; ok {
			if strings.TrimSpace(configured.SizeBand) != "" {
				size = configured.SizeBand
			}
			if strings.TrimSpace(configured.Industry) != "" {
				industry = configured.Industry
			}
		}

		sizeEntry := ensureSegmentBucket(sizeBuckets, size)
		sizeEntry.OrgCount++
		sizeEntry.ToolCount += entry.Tools

		industryEntry := ensureSegmentBucket(industryBuckets, industry)
		industryEntry.OrgCount++
		industryEntry.ToolCount += entry.Tools
	}

	return CampaignSegments{
		OrgSizeBands:  sortedBuckets(sizeBuckets),
		IndustryBands: sortedBuckets(industryBuckets),
	}
}

func ensureSegmentBucket(store map[string]*CampaignSegmentBucket, name string) *CampaignSegmentBucket {
	entry, ok := store[name]
	if !ok {
		entry = &CampaignSegmentBucket{Segment: name}
		store[name] = entry
	}
	return entry
}

func sortedBuckets(in map[string]*CampaignSegmentBucket) []CampaignSegmentBucket {
	out := make([]CampaignSegmentBucket, 0, len(in))
	for _, item := range in {
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Segment < out[j].Segment
	})
	return out
}

func sizeBand(repoCount int) string {
	switch {
	case repoCount <= 0:
		return "unknown"
	case repoCount <= 5:
		return "small"
	case repoCount <= 20:
		return "medium"
	default:
		return "large"
	}
}

func normalizeSegmentMetadata(in map[string]SegmentMetadata) map[string]SegmentMetadata {
	out := map[string]SegmentMetadata{}
	for org, item := range in {
		normalizedOrg := strings.ToLower(strings.TrimSpace(org))
		if normalizedOrg == "" {
			continue
		}
		industry := strings.ToLower(strings.TrimSpace(item.Industry))
		size := strings.ToLower(strings.TrimSpace(item.SizeBand))
		out[normalizedOrg] = SegmentMetadata{
			Industry: industry,
			SizeBand: size,
		}
	}
	return out
}

func inferIndustry(org string) string {
	normalized := strings.ToLower(strings.TrimSpace(org))
	switch {
	case strings.Contains(normalized, "fin"), strings.Contains(normalized, "bank"), strings.Contains(normalized, "pay"):
		return "fintech"
	case strings.Contains(normalized, "health"), strings.Contains(normalized, "med"), strings.Contains(normalized, "clinic"):
		return "healthcare"
	case strings.Contains(normalized, "gov"), strings.Contains(normalized, "state"), strings.Contains(normalized, "city"):
		return "public_sector"
	case strings.Contains(normalized, "edu"), strings.Contains(normalized, "uni"), strings.Contains(normalized, "school"):
		return "education"
	default:
		return "unknown"
	}
}

func RenderCampaignPublicMarkdown(artifact CampaignArtifact) string {
	var builder strings.Builder
	builder.WriteString("# The State of AI Tool Sprawl\n\n")
	builder.WriteString("## 1. Headline Findings\n\n")
	builder.WriteString(fmt.Sprintf("- %d tools discovered across %d repositories scanned.\n", artifact.Metrics.ToolsDetectedTotal, artifact.Metrics.ReposScanned))
	builder.WriteString(fmt.Sprintf("- %d write-capable tools and %d credential-capable tools detected.\n", artifact.Metrics.WriteCapableTools, artifact.Metrics.CredentialAccessTools))
	builder.WriteString(fmt.Sprintf("- %d approved, %d unapproved, %d unknown governance classifications.\n", artifact.Metrics.ApprovedTools, artifact.Metrics.UnapprovedTools, artifact.Metrics.UnknownTools))
	if artifact.Metrics.ProductionWriteTools != nil {
		builder.WriteString(fmt.Sprintf("- %d tools matched configured production-write targets.\n", *artifact.Metrics.ProductionWriteTools))
	} else {
		builder.WriteString("- Production-write subset is not configured for this campaign.\n")
	}

	builder.WriteString("\n## 2. Methodology\n\n")
	builder.WriteString(fmt.Sprintf("- Wrkr version: %s\n", artifact.Methodology.WrkrVersion))
	builder.WriteString(fmt.Sprintf("- Scan count: %d\n", artifact.Methodology.ScanCount))
	builder.WriteString(fmt.Sprintf("- Repo count: %d\n", artifact.Methodology.RepoCount))
	builder.WriteString(fmt.Sprintf("- Files processed: %d\n", artifact.Methodology.FileCountProcessed))
	builder.WriteString("- Detection method: deterministic static parsing and policy evaluation.\n")
	builder.WriteString("- Exclusions: no live endpoint probing, no runtime execution telemetry, no secret-value extraction.\n")

	builder.WriteString("\n## 3. Segmentation\n\n")
	for _, bucket := range artifact.Segments.OrgSizeBands {
		builder.WriteString(fmt.Sprintf("- Org size `%s`: orgs=%d tools=%d\n", bucket.Segment, bucket.OrgCount, bucket.ToolCount))
	}
	for _, bucket := range artifact.Segments.IndustryBands {
		builder.WriteString(fmt.Sprintf("- Industry `%s`: orgs=%d tools=%d\n", bucket.Segment, bucket.OrgCount, bucket.ToolCount))
	}

	builder.WriteString("\n## 4. Reproducibility\n\n")
	builder.WriteString("- Command: `wrkr campaign aggregate --input-glob <glob> --json`\n")
	builder.WriteString("- Source artifacts: deterministic `wrkr scan --json` outputs.\n")
	builder.WriteString("- Method contract: no probabilistic scoring paths.\n")
	builder.WriteString("\n")
	return builder.String()
}
