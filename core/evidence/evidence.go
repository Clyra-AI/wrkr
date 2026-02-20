package evidence

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/wrkr/core/compliance"
	"github.com/Clyra-AI/wrkr/core/proofemit"
	"github.com/Clyra-AI/wrkr/core/state"
)

type BuildInput struct {
	StatePath   string
	Frameworks  []string
	OutputDir   string
	GeneratedAt time.Time
}

type BuildResult struct {
	OutputDir         string             `json:"output_dir"`
	Frameworks        []string           `json:"frameworks"`
	ManifestPath      string             `json:"manifest_path"`
	ChainPath         string             `json:"chain_path"`
	FrameworkCoverage map[string]float64 `json:"framework_coverage"`
}

const outputDirMarkerFile = ".wrkr-evidence-managed"
const outputDirMarkerContent = "managed by wrkr evidence build\n"

func Build(in BuildInput) (BuildResult, error) {
	resolvedStatePath := state.ResolvePath(strings.TrimSpace(in.StatePath))
	snapshot, err := state.Load(resolvedStatePath)
	if err != nil {
		return BuildResult{}, fmt.Errorf("load state snapshot: %w", err)
	}
	chainPath := proofemit.ChainPath(resolvedStatePath)
	if _, err := os.Stat(chainPath); err != nil {
		if os.IsNotExist(err) {
			return BuildResult{}, fmt.Errorf("load proof chain: proof chain file does not exist: %s", chainPath)
		}
		return BuildResult{}, fmt.Errorf("load proof chain: stat chain file: %w", err)
	}
	chain, err := proofemit.LoadChain(chainPath)
	if err != nil {
		return BuildResult{}, fmt.Errorf("load proof chain: %w", err)
	}
	if !hasScanEvidenceRecords(chain.Records) {
		return BuildResult{}, fmt.Errorf("load proof chain: proof chain has no scan evidence records")
	}
	frameworks := normalizeFrameworks(in.Frameworks)
	if len(frameworks) == 0 {
		return BuildResult{}, fmt.Errorf("at least one framework is required")
	}
	if err := validateSnapshot(snapshot); err != nil {
		return BuildResult{}, err
	}
	outputDir := strings.TrimSpace(in.OutputDir)
	if outputDir == "" {
		outputDir = "wrkr-evidence"
	}
	if err := resetOutputDir(outputDir); err != nil {
		return BuildResult{}, err
	}

	generatedAt := in.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC().Truncate(time.Second)
	} else {
		generatedAt = generatedAt.UTC().Truncate(time.Second)
	}

	if err := writeJSON(filepath.Join(outputDir, "inventory.json"), snapshot.Inventory); err != nil {
		return BuildResult{}, err
	}
	if err := writeJSON(filepath.Join(outputDir, "inventory-snapshot.json"), snapshot.Inventory); err != nil {
		return BuildResult{}, err
	}
	if err := writeJSON(filepath.Join(outputDir, "risk-report.json"), snapshot.RiskReport); err != nil {
		return BuildResult{}, err
	}
	if err := writeJSON(filepath.Join(outputDir, "profile-compliance.json"), snapshot.Profile); err != nil {
		return BuildResult{}, err
	}
	if err := writeJSON(filepath.Join(outputDir, "posture-score.json"), snapshot.PostureScore); err != nil {
		return BuildResult{}, err
	}
	if err := writeJSON(filepath.Join(outputDir, "scan-metadata.json"), map[string]any{
		"generated_at": generatedAt.Format(time.RFC3339),
		"frameworks":   frameworks,
		"state_path":   resolvedStatePath,
	}); err != nil {
		return BuildResult{}, err
	}

	proofRecordsDir := filepath.Join(outputDir, "proof-records")
	if err := os.MkdirAll(proofRecordsDir, 0o750); err != nil {
		return BuildResult{}, fmt.Errorf("mkdir proof-records dir: %w", err)
	}
	if err := writeJSON(filepath.Join(proofRecordsDir, "chain.json"), chain); err != nil {
		return BuildResult{}, err
	}
	if err := writeJSONL(filepath.Join(proofRecordsDir, "scan-findings.jsonl"), filterRecords(chain.Records, "scan_finding", "")); err != nil {
		return BuildResult{}, err
	}
	if err := writeJSONL(filepath.Join(proofRecordsDir, "risk-assessments.jsonl"), filterRecords(chain.Records, "risk_assessment", "")); err != nil {
		return BuildResult{}, err
	}
	if err := writeJSONL(filepath.Join(proofRecordsDir, "approvals.jsonl"), filterRecords(chain.Records, "approval", "")); err != nil {
		return BuildResult{}, err
	}
	if err := writeJSONL(filepath.Join(proofRecordsDir, "lifecycle-transitions.jsonl"), filterRecords(chain.Records, "decision", "lifecycle_transition")); err != nil {
		return BuildResult{}, err
	}

	mappingsDir := filepath.Join(outputDir, "mappings")
	gapsDir := filepath.Join(outputDir, "gaps")
	if err := os.MkdirAll(mappingsDir, 0o750); err != nil {
		return BuildResult{}, fmt.Errorf("mkdir mappings dir: %w", err)
	}
	if err := os.MkdirAll(gapsDir, 0o750); err != nil {
		return BuildResult{}, fmt.Errorf("mkdir gaps dir: %w", err)
	}

	coverage := map[string]float64{}
	for _, frameworkID := range frameworks {
		framework, err := proof.LoadFramework(frameworkID)
		if err != nil {
			return BuildResult{}, fmt.Errorf("load framework %s: %w", frameworkID, err)
		}
		result, err := compliance.Evaluate(compliance.Input{Framework: framework, Chain: chain})
		if err != nil {
			return BuildResult{}, fmt.Errorf("evaluate framework %s: %w", frameworkID, err)
		}
		coverage[frameworkID] = result.Coverage
		if err := writeJSON(filepath.Join(mappingsDir, frameworkID+".json"), result); err != nil {
			return BuildResult{}, err
		}
		if err := writeJSON(filepath.Join(gapsDir, frameworkID+".json"), map[string]any{
			"framework_id":     result.FrameworkID,
			"coverage_percent": result.Coverage,
			"gaps":             result.Gaps,
		}); err != nil {
			return BuildResult{}, err
		}
	}

	signingKeyPath := proofemit.SigningKeyPath(resolvedStatePath)
	if _, err := os.Stat(signingKeyPath); err != nil {
		if os.IsNotExist(err) {
			return BuildResult{}, fmt.Errorf("load signing material: signing key file does not exist: %s", signingKeyPath)
		}
		return BuildResult{}, fmt.Errorf("load signing material: stat signing key file: %w", err)
	}
	signingMaterial, signingErr := proofemit.LoadSigningMaterial(resolvedStatePath)
	if signingErr != nil {
		return BuildResult{}, fmt.Errorf("load signing material: %w", signingErr)
	}
	if err := os.MkdirAll(filepath.Join(outputDir, "signatures"), 0o750); err != nil {
		return BuildResult{}, fmt.Errorf("mkdir signatures dir: %w", err)
	}
	publicKeyBase64 := base64.StdEncoding.EncodeToString(signingMaterial.Public)
	if err := os.WriteFile(filepath.Join(outputDir, "signatures", "public-key.base64"), []byte(publicKeyBase64+"\n"), 0o600); err != nil {
		return BuildResult{}, fmt.Errorf("write public key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "signatures", "key-id.txt"), []byte(strings.TrimSpace(signingMaterial.KeyID)+"\n"), 0o600); err != nil {
		return BuildResult{}, fmt.Errorf("write key id: %w", err)
	}

	entries, err := buildManifestEntries(outputDir)
	if err != nil {
		return BuildResult{}, err
	}
	manifest := proof.BundleManifest{
		Files:  entries,
		AlgoID: "sha256",
		SaltID: "wrkr-evidence-v1",
	}
	if err := writeJSON(filepath.Join(outputDir, "manifest.json"), manifest); err != nil {
		return BuildResult{}, err
	}

	if _, err := proof.SignBundle(outputDir, signingMaterial); err != nil {
		return BuildResult{}, fmt.Errorf("sign bundle manifest: %w", err)
	}
	if _, err := proof.VerifyBundle(outputDir, proof.BundleVerifyOpts{}); err != nil {
		return BuildResult{}, fmt.Errorf("verify bundle integrity: %w", err)
	}

	return BuildResult{
		OutputDir:         outputDir,
		Frameworks:        frameworks,
		ManifestPath:      filepath.Join(outputDir, "manifest.json"),
		ChainPath:         chainPath,
		FrameworkCoverage: coverage,
	}, nil
}

func normalizeFrameworks(in []string) []string {
	set := map[string]struct{}{}
	for _, value := range in {
		for _, part := range strings.Split(value, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			set[trimmed] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func validateSnapshot(snapshot state.Snapshot) error {
	missing := make([]string, 0, 4)
	if snapshot.Inventory == nil {
		missing = append(missing, "inventory")
	}
	if snapshot.RiskReport == nil {
		missing = append(missing, "risk_report")
	}
	if snapshot.Profile == nil {
		missing = append(missing, "profile")
	}
	if snapshot.PostureScore == nil {
		missing = append(missing, "posture_score")
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("load state snapshot: missing required sections: %s", strings.Join(missing, ", "))
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir json dir: %w", err)
	}
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func writeJSONL(path string, records []proof.Record) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir jsonl dir: %w", err)
	}
	file, err := os.Create(path) // #nosec G304 -- path is a deterministic local evidence output path assembled by wrkr.
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() {
		_ = file.Close()
	}()
	writer := bufio.NewWriter(file)
	for _, record := range records {
		payload, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("marshal jsonl record: %w", err)
		}
		if _, err := writer.Write(payload); err != nil {
			return fmt.Errorf("write jsonl record: %w", err)
		}
		if err := writer.WriteByte('\n'); err != nil {
			return fmt.Errorf("write jsonl newline: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush jsonl writer: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

func resetOutputDir(path string) error {
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(path, 0o750); err != nil {
				return fmt.Errorf("mkdir output dir: %w", err)
			}
			return writeOutputDirMarker(path)
		}
		return fmt.Errorf("lstat output dir: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("output dir must not be a symlink: %s", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("output dir is not a directory: %s", path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("read output dir: %w", err)
	}
	if len(entries) == 0 {
		return writeOutputDirMarker(path)
	}

	markerPath := filepath.Join(path, outputDirMarkerFile)
	markerInfo, err := os.Lstat(markerPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("output dir is not empty and not managed by wrkr evidence: %s", path)
		}
		return fmt.Errorf("stat output dir marker: %w", err)
	}
	if !markerInfo.Mode().IsRegular() {
		return fmt.Errorf("output dir marker is not a regular file: %s", markerPath)
	}
	markerPayload, err := os.ReadFile(markerPath) // #nosec G304 -- marker path is deterministic under the selected local output directory.
	if err != nil {
		return fmt.Errorf("read output dir marker: %w", err)
	}
	if string(markerPayload) != outputDirMarkerContent {
		return fmt.Errorf("output dir marker content is invalid: %s", markerPath)
	}

	for _, entry := range entries {
		if entry.Name() == outputDirMarkerFile {
			continue
		}
		entryPath := filepath.Join(path, entry.Name())
		if err := os.RemoveAll(entryPath); err != nil {
			return fmt.Errorf("clear output dir entry %s: %w", entryPath, err)
		}
	}
	return nil
}

func writeOutputDirMarker(path string) error {
	markerPath := filepath.Join(path, outputDirMarkerFile)
	if err := os.WriteFile(markerPath, []byte(outputDirMarkerContent), 0o600); err != nil {
		return fmt.Errorf("write output dir marker: %w", err)
	}
	return nil
}

func filterRecords(records []proof.Record, recordType string, eventType string) []proof.Record {
	out := make([]proof.Record, 0)
	for _, record := range records {
		if strings.TrimSpace(record.RecordType) != strings.TrimSpace(recordType) {
			continue
		}
		if strings.TrimSpace(eventType) != "" {
			value, _ := record.Event["event_type"].(string)
			if strings.TrimSpace(value) != strings.TrimSpace(eventType) {
				continue
			}
		}
		out = append(out, record)
	}
	return out
}

func hasScanEvidenceRecords(records []proof.Record) bool {
	for _, record := range records {
		recordType := strings.TrimSpace(record.RecordType)
		if recordType == "scan_finding" || recordType == "risk_assessment" {
			return true
		}
	}
	return false
}

func buildManifestEntries(outputDir string) ([]proof.BundleManifestEntry, error) {
	entries := make([]proof.BundleManifestEntry, 0)
	err := filepath.WalkDir(outputDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(outputDir, path)
		if err != nil {
			return err
		}
		normalized := filepath.ToSlash(rel)
		if normalized == "manifest.json" || normalized == outputDirMarkerFile {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() {
			return fmt.Errorf("manifest entry is not a regular file: %s", normalized)
		}
		payload, err := os.ReadFile(path) // #nosec G304 -- walk only reads files under deterministic output directory.
		if err != nil {
			return err
		}
		sum := sha256.Sum256(payload)
		entries = append(entries, proof.BundleManifestEntry{Path: normalized, SHA256: "sha256:" + hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("build bundle manifest: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
	return entries, nil
}
