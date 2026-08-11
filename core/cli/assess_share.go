package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

type assessmentShareFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type assessmentShareManifest struct {
	SchemaVersion string                `json:"schema_version"`
	ShareProfile  string                `json:"share_profile"`
	Files         []assessmentShareFile `json:"files"`
	Excluded      []string              `json:"excluded"`
	Notice        string                `json:"notice"`
}

func buildAssessmentCustomerShare(outputDir string, profile reportcore.ShareProfile, paired reportcore.ShareProfile, artifacts assessArtifacts) (string, string, error) {
	if profile == reportcore.ShareProfileInternal && strings.TrimSpace(string(paired)) == "" {
		return "", "", nil
	}
	shareProfile := profile
	sources := map[string]string{
		"wrkr-report.md":            artifacts.ReportMarkdownPath,
		"wrkr-report-appendix.md":   artifacts.ReportAppendixPath,
		"wrkr-report-evidence.json": artifacts.ReportEvidenceJSONPath,
		"wrkr-control-backlog.csv":  artifacts.BacklogCSVPath,
	}
	if profile == reportcore.ShareProfileInternal {
		shareProfile = paired
		suffix := strings.ReplaceAll(string(paired), "-", "_")
		sources = map[string]string{
			"wrkr-report.md":            artifacts.PairedArtifactPaths["markdown_"+suffix],
			"wrkr-report-appendix.md":   artifacts.PairedArtifactPaths["markdown_appendix_"+suffix],
			"wrkr-report-evidence.json": artifacts.PairedArtifactPaths["evidence_json_"+suffix],
			"wrkr-control-backlog.csv":  artifacts.PairedArtifactPaths["backlog_csv_"+suffix],
		}
	}
	shareDir := filepath.Join(outputDir, "customer-share")
	if info, err := os.Lstat(shareDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", "", fmt.Errorf("customer-share path must be a real directory")
		}
		entries, readErr := os.ReadDir(shareDir)
		if readErr != nil {
			return "", "", readErr
		}
		if len(entries) > 0 {
			return "", "", fmt.Errorf("customer-share directory is not empty; use a fresh assessment output directory")
		}
	} else if !os.IsNotExist(err) {
		return "", "", err
	}
	if err := os.MkdirAll(shareDir, 0o750); err != nil {
		return "", "", err
	}
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	files := make([]assessmentShareFile, 0, len(names))
	for _, name := range names {
		sourcePath := strings.TrimSpace(sources[name])
		if sourcePath == "" {
			continue
		}
		if !filepath.IsAbs(sourcePath) {
			sourcePath = filepath.Join(outputDir, sourcePath)
		}
		if err := ensureAssessmentPathWithin(outputDir, sourcePath); err != nil {
			return "", "", err
		}
		payload, err := os.ReadFile(sourcePath) // #nosec G304 -- path is constrained to the assessment output directory.
		if err != nil {
			return "", "", err
		}
		destination := filepath.Join(shareDir, name)
		if err := atomicwrite.WriteFileFunc(destination, 0o600, func(w io.Writer) error {
			_, writeErr := w.Write(payload)
			return writeErr
		}); err != nil {
			return "", "", err
		}
		digest := sha256.Sum256(payload)
		files = append(files, assessmentShareFile{Name: name, SHA256: hex.EncodeToString(digest[:]), Bytes: len(payload)})
	}
	if len(files) == 0 {
		return "", "", fmt.Errorf("no customer-safe report artifacts were available")
	}
	manifest := assessmentShareManifest{
		SchemaVersion: "v1",
		ShareProfile:  string(shareProfile),
		Files:         files,
		Excluded:      []string{"internal scan state", "raw logs", "signing keys", "private join map", "unredacted evidence bundle"},
		Notice:        "Share only this directory. The parent assessment directory contains internal remediation and proof material.",
	}
	manifestPath := filepath.Join(shareDir, "manifest.json")
	if err := atomicwrite.WriteFileFunc(manifestPath, 0o600, func(w io.Writer) error {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(manifest)
	}); err != nil {
		return "", "", err
	}
	return shareDir, manifestPath, nil
}

func ensureAssessmentPathWithin(root string, candidate string) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(rootAbs, candidateAbs)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("customer-share source escapes assessment output: %s", candidate)
	}
	return nil
}
