package report

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/regress"
)

const (
	repeatUsageStatusFirstRun          = "first_run"
	repeatUsageStatusFollowUpReady     = "follow_up_ready"
	repeatUsageStatusRepeatUseDetected = "repeat_use_detected"
	repeatUsageWalkMaxDepth            = 4
)

func BuildRepeatUsageSignals(statePath string) *RepeatUsageSignals {
	trimmed := strings.TrimSpace(statePath)
	if trimmed == "" {
		return nil
	}

	signals := &RepeatUsageSignals{}
	assessRuns := map[string]struct{}{}
	regressRuns := map[string]struct{}{}
	driftRuns := map[string]struct{}{}
	evidenceRuns := map[string]struct{}{}
	ticketExports := map[string]struct{}{}
	actionContractExports := map[string]struct{}{}
	reasons := map[string]struct{}{}

	for _, root := range repeatUsageSearchRoots(trimmed) {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return nil
			}
			depth := repeatUsageDepth(rel)
			if d.IsDir() {
				if depth > repeatUsageWalkMaxDepth {
					return filepath.SkipDir
				}
				return nil
			}
			if depth > repeatUsageWalkMaxDepth {
				return nil
			}

			base := strings.TrimSpace(filepath.Base(path))
			switch {
			case base == regress.DefaultBaselineFilename:
				signals.BaselinePresent = true
				reasons["baseline_present"] = struct{}{}
			case base == "export-pack.json":
				actionContractExports[filepath.Clean(path)] = struct{}{}
				assessRuns[repeatUsageArtifactRoot(root, rel, "export", "export-pack.json")] = struct{}{}
				reasons["action_contract_exported"] = struct{}{}
			case strings.HasPrefix(base, "tickets-") && strings.HasSuffix(base, ".json"):
				ticketExports[filepath.Clean(path)] = struct{}{}
				reasons["ticket_exported"] = struct{}{}
			case base == regress.DefaultSummaryMDFilename:
				regressRuns[repeatUsageArtifactRoot(root, rel, "regress", regress.DefaultSummaryMDFilename)] = struct{}{}
				reasons["regress_artifact_present"] = struct{}{}
			case base == "drift.json":
				key := repeatUsageArtifactRoot(root, rel, "regress", "drift.json")
				regressRuns[key] = struct{}{}
				driftRuns[key] = struct{}{}
				reasons["drift_artifact_present"] = struct{}{}
			case base == ".wrkr-evidence-managed":
				evidenceRuns[filepath.Dir(path)] = struct{}{}
				reasons["evidence_exported"] = struct{}{}
			case base == "artifact-manifest.json" && repeatUsageEvidenceManifest(path):
				evidenceRuns[filepath.Dir(path)] = struct{}{}
				reasons["evidence_exported"] = struct{}{}
			}
			return nil
		})
	}

	signals.AssessRuns = len(assessRuns)
	signals.AssessRerunDetected = len(assessRuns) > 1
	signals.RegressArtifacts = len(regressRuns)
	signals.DriftArtifacts = len(driftRuns)
	signals.EvidenceExports = len(evidenceRuns)
	signals.TicketExports = len(ticketExports)
	signals.ActionContractExports = len(actionContractExports)
	if signals.AssessRerunDetected {
		reasons["assess_rerun_detected"] = struct{}{}
	} else if signals.AssessRuns == 1 {
		reasons["assess_run_present"] = struct{}{}
	}

	signals.ReasonCodes = sortedReasonCodes(reasons)
	signals.Status = repeatUsageStatus(signals)
	if signals.Status == repeatUsageStatusFirstRun &&
		!signals.BaselinePresent &&
		signals.AssessRuns == 0 &&
		signals.RegressArtifacts == 0 &&
		signals.DriftArtifacts == 0 &&
		signals.EvidenceExports == 0 &&
		signals.TicketExports == 0 &&
		signals.ActionContractExports == 0 {
		signals.ReasonCodes = nil
	}
	return signals
}

func cloneRepeatUsageSignals(in *RepeatUsageSignals) *RepeatUsageSignals {
	if in == nil {
		return nil
	}
	out := *in
	out.ReasonCodes = append([]string(nil), in.ReasonCodes...)
	return &out
}

func repeatUsageStatus(signals *RepeatUsageSignals) string {
	if signals == nil {
		return repeatUsageStatusFirstRun
	}
	if signals.AssessRerunDetected ||
		signals.RegressArtifacts > 0 ||
		signals.DriftArtifacts > 0 ||
		signals.EvidenceExports > 0 ||
		signals.TicketExports > 0 ||
		signals.ActionContractExports > 0 {
		return repeatUsageStatusRepeatUseDetected
	}
	if signals.BaselinePresent || signals.AssessRuns > 0 {
		return repeatUsageStatusFollowUpReady
	}
	return repeatUsageStatusFirstRun
}

func repeatUsageSearchRoots(statePath string) []string {
	roots := []string{}
	seen := map[string]struct{}{}
	add := func(path string) {
		cleaned := filepath.Clean(strings.TrimSpace(path))
		if cleaned == "" {
			return
		}
		info, err := os.Stat(cleaned)
		if err != nil || !info.IsDir() {
			return
		}
		if _, ok := seen[cleaned]; ok {
			return
		}
		seen[cleaned] = struct{}{}
		roots = append(roots, cleaned)
	}

	stateDir := filepath.Dir(statePath)
	add(stateDir)

	root := repeatUsageRoot(statePath)
	add(root)
	add(filepath.Join(root, ".wrkr"))

	entries, err := os.ReadDir(root)
	if err != nil {
		sort.Strings(roots)
		return roots
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(entry.Name()))
		if name == "" {
			continue
		}
		if name == ".git" || name == "node_modules" || name == "vendor" {
			continue
		}
		if strings.HasPrefix(name, "wrkr") ||
			strings.Contains(name, "assessment") ||
			strings.Contains(name, "evidence") ||
			strings.Contains(name, "output") ||
			strings.Contains(name, "artifact") ||
			name == ".tmp" ||
			name == "tmp" ||
			name == "out" {
			add(filepath.Join(root, entry.Name()))
		}
	}
	sort.Strings(roots)
	return roots
}

func repeatUsageRoot(statePath string) string {
	cleaned := filepath.Clean(strings.TrimSpace(statePath))
	if cleaned == "" {
		return ""
	}
	dir := filepath.Dir(cleaned)
	switch filepath.Base(dir) {
	case ".wrkr":
		return filepath.Dir(dir)
	case "internal":
		if strings.EqualFold(filepath.Base(cleaned), "scan-state.json") {
			return filepath.Dir(dir)
		}
	}
	return dir
}

func repeatUsageDepth(rel string) int {
	trimmed := filepath.ToSlash(strings.TrimSpace(rel))
	if trimmed == "." || trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, "/") + 1
}

func repeatUsageArtifactRoot(root string, rel string, markerDir string, markerFile string) string {
	trimmed := filepath.ToSlash(strings.TrimSpace(rel))
	suffix := filepath.ToSlash(filepath.Join(markerDir, markerFile))
	if strings.HasSuffix(trimmed, suffix) {
		prefix := strings.TrimSuffix(trimmed, suffix)
		prefix = strings.TrimSuffix(prefix, "/")
		if prefix == "" {
			return filepath.Clean(root)
		}
		return filepath.Clean(filepath.Join(root, filepath.FromSlash(prefix)))
	}
	return filepath.Clean(filepath.Join(root, filepath.FromSlash(filepath.Dir(rel))))
}

func repeatUsageEvidenceManifest(path string) bool {
	payload, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var manifest struct {
		GeneratorVersion string `json:"generator_version"`
	}
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return false
	}
	return strings.TrimSpace(manifest.GeneratorVersion) == "wrkr-evidence-v1"
}

func sortedReasonCodes(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
