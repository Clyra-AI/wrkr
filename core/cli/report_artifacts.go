package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/regress"
	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/state"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

type reportArtifactOptions struct {
	StatePath          string
	Snapshot           state.Snapshot
	PreviousSnapshot   *state.Snapshot
	Baseline           *regress.Baseline
	RegressResult      *regress.Result
	Manifest           *manifest.Manifest
	Top                int
	Template           reportcore.Template
	ShareProfile       reportcore.ShareProfile
	PairedShareProfile reportcore.ShareProfile
	RedactionFields    []reportcore.RedactionField
	FocusPreset        string
	FocusPathID        string
	RecentPRReview     *reportcore.RecentPRReviewOptions
	WriteMarkdown      bool
	MarkdownPath       string
	WritePDF           bool
	PDFPath            string
	WriteEvidenceJSON  bool
	EvidenceJSONPath   string
	WriteBacklogCSV    bool
	BacklogCSVPath     string
}

type reportArtifactResult struct {
	Summary             reportcore.Summary
	MarkdownPath        string
	PDFPath             string
	EvidenceJSONPath    string
	BacklogCSVPath      string
	PairedArtifactPaths map[string]string
	PrivateJoinMapPath  string
}

type artifactPathError struct {
	err error
}

func (e artifactPathError) Error() string {
	if e.err == nil {
		return "invalid artifact output path"
	}
	return e.err.Error()
}

func (e artifactPathError) Unwrap() error {
	return e.err
}

func isArtifactPathError(err error) bool {
	var target artifactPathError
	return errors.As(err, &target)
}

func parseReportTemplateShare(templateRaw string, shareProfileRaw string) (reportcore.Template, reportcore.ShareProfile, error) {
	templateValue := strings.TrimSpace(templateRaw)
	if templateValue == "" {
		templateValue = string(reportcore.TemplateOperator)
	}
	template, ok := reportcore.ParseTemplate(templateValue)
	if !ok {
		return "", "", fmt.Errorf("--template must be one of exec|operator|audit|public|ciso|appsec|platform|customer-draft|agent-action-bom|design-partner-summary")
	}

	shareValue := strings.TrimSpace(shareProfileRaw)
	if shareValue == "" {
		shareValue = string(reportcore.DefaultShareProfile(template))
	}
	shareProfile, ok := reportcore.ParseShareProfile(shareValue)
	if !ok {
		return "", "", fmt.Errorf("--share-profile must be one of internal|public|customer-redacted|design-partner|external-redacted|investor-safe")
	}
	return template, shareProfile, nil
}

func generateReportArtifacts(opts reportArtifactOptions) (reportArtifactResult, error) {
	buildSummary := func(shareProfile reportcore.ShareProfile) (reportcore.Summary, error) {
		summary, err := reportcore.BuildSummary(reportcore.BuildInput{
			StatePath:        opts.StatePath,
			Snapshot:         opts.Snapshot,
			PreviousSnapshot: opts.PreviousSnapshot,
			Baseline:         opts.Baseline,
			RegressResult:    opts.RegressResult,
			Manifest:         opts.Manifest,
			Top:              opts.Top,
			Template:         opts.Template,
			ShareProfile:     shareProfile,
			RedactionFields:  opts.RedactionFields,
		})
		if err != nil {
			return reportcore.Summary{}, err
		}
		if opts.RecentPRReview != nil {
			reviewOpts := *opts.RecentPRReview
			summary.RecentPRReview = reportcore.BuildRecentPRReview(summary, reviewOpts)
		}
		if err := reportcore.ApplyAgentActionBOMFocus(&summary, opts.FocusPathID); err != nil {
			return reportcore.Summary{}, err
		}
		if err := reportcore.ApplyFocusPreset(&summary, opts.FocusPreset); err != nil {
			return reportcore.Summary{}, err
		}
		summary = reportcore.FinalizeSummaryForSerialization(summary)
		summary, err = reportcore.ApplyShareableResidualRedaction(opts.Snapshot, summary)
		if err != nil {
			return reportcore.Summary{}, err
		}
		return summary, nil
	}

	summary, err := buildSummary(opts.ShareProfile)
	if err != nil {
		return reportArtifactResult{}, err
	}

	pairedPaths := map[string]string{}
	privateJoinMapPath := ""
	summary.ArtifactMetadata = reportcore.BuildArtifactMetadata(summary, []string{opts.StatePath}, reportcore.ArtifactVariantInternal, "", "")
	pairedSummary := reportcore.Summary{}
	hasPairedSummary := strings.TrimSpace(string(opts.PairedShareProfile)) != ""
	if hasPairedSummary {
		pairedSummary, err = buildSummary(opts.PairedShareProfile)
		if err != nil {
			return reportArtifactResult{}, err
		}
		pairID := reportcore.BuildPairID(summary, opts.PairedShareProfile)
		privateJoinMapPath, err = normalizeManagedArtifactPath(filepath.Join(filepath.Dir(opts.StatePath), ".wrkr-private-join-map-"+pairID+".json"))
		if err != nil {
			return reportArtifactResult{}, artifactPathError{err: err}
		}
		if err := rejectUnsafeExistingManagedFile(privateJoinMapPath, "private join map"); err != nil {
			return reportArtifactResult{}, unsafeManagedArtifactPathError{err: err}
		}
		summary.ArtifactMetadata = reportcore.BuildArtifactMetadata(summary, []string{opts.StatePath}, reportcore.ArtifactVariantInternal, pairID, privateJoinMapPath)
		pairedSummary.ArtifactMetadata = reportcore.BuildArtifactMetadata(pairedSummary, []string{opts.StatePath}, reportcore.ArtifactVariantCustomerRedacted, pairID, privateJoinMapPath)
		joinMap := reportcore.BuildPrivateJoinMap(summary, pairedSummary, pairID)
		if writeErr := atomicwrite.WriteFileFunc(privateJoinMapPath, 0o600, func(w io.Writer) error {
			encoder := json.NewEncoder(w)
			encoder.SetIndent("", "  ")
			return encoder.Encode(joinMap)
		}); writeErr != nil {
			return reportArtifactResult{}, writeErr
		}
	}

	writePaired := func(kind string, primaryPath string, render func(reportcore.Summary) ([]byte, error), internalSummary reportcore.Summary, externalSummary reportcore.Summary) (string, error) {
		path, pathErr := resolveArtifactOutputPath(primaryPath)
		if pathErr != nil {
			return "", artifactPathError{err: pathErr}
		}
		payload, renderErr := render(internalSummary)
		if renderErr != nil {
			return "", renderErr
		}
		if writeErr := os.WriteFile(path, payload, 0o600); writeErr != nil {
			return "", writeErr
		}
		if hasPairedSummary {
			externalPath := reportcore.PairedArtifactPath(path, strings.ReplaceAll(string(opts.PairedShareProfile), " ", "-"))
			externalPayload, externalErr := render(externalSummary)
			if externalErr != nil {
				return "", externalErr
			}
			if writeErr := os.WriteFile(externalPath, externalPayload, 0o600); writeErr != nil {
				return "", writeErr
			}
			pairedPaths[kind+"_"+strings.ReplaceAll(string(opts.PairedShareProfile), "-", "_")] = externalPath
		}
		return path, nil
	}

	markdown := reportcore.RenderMarkdown(summary)
	pairedMarkdown := ""
	if hasPairedSummary && (opts.WriteMarkdown || opts.WritePDF) {
		pairedMarkdown = reportcore.RenderMarkdown(pairedSummary)
	}
	validationMarkdown := ""
	if opts.WriteMarkdown || opts.WritePDF {
		validationMarkdown = markdown
	}
	if err := reportcore.ValidateShareableArtifacts(opts.Snapshot, summary, validationMarkdown, opts.WriteEvidenceJSON); err != nil {
		return reportArtifactResult{}, err
	}
	if hasPairedSummary {
		pairedValidationMarkdown := ""
		if opts.WriteMarkdown || opts.WritePDF {
			pairedValidationMarkdown = pairedMarkdown
		}
		if err := reportcore.ValidateShareableArtifacts(opts.Snapshot, pairedSummary, pairedValidationMarkdown, opts.WriteEvidenceJSON); err != nil {
			return reportArtifactResult{}, err
		}
	}
	mdOutPath := ""
	if opts.WriteMarkdown {
		path, writeErr := writePaired("markdown", opts.MarkdownPath, func(current reportcore.Summary) ([]byte, error) {
			return []byte(reportcore.RenderMarkdown(current)), nil
		}, summary, pairedSummary)
		if writeErr != nil {
			return reportArtifactResult{}, writeErr
		}
		mdOutPath = path
	}

	pdfOutPath := ""
	if opts.WritePDF {
		path, writeErr := writePaired("pdf", opts.PDFPath, func(current reportcore.Summary) ([]byte, error) {
			return []byte(reportcore.RenderMarkdown(current)), nil
		}, summary, pairedSummary)
		if writeErr != nil {
			return reportArtifactResult{}, writeErr
		}
		if writeErr := writeReportPDF(path, reportcore.MarkdownLines(markdown)); writeErr != nil {
			return reportArtifactResult{}, writeErr
		}
		if hasPairedSummary {
			externalPath := pairedPaths["pdf_"+strings.ReplaceAll(string(opts.PairedShareProfile), "-", "_")]
			if externalPath != "" {
				if writeErr := writeReportPDF(externalPath, reportcore.MarkdownLines(pairedMarkdown)); writeErr != nil {
					return reportArtifactResult{}, writeErr
				}
			}
		}
		pdfOutPath = path
	}

	evidenceJSONPath := ""
	if opts.WriteEvidenceJSON {
		evidenceSummary := reportcore.PrepareEvidenceBundleSummary(summary, opts.FocusPathID, opts.FocusPreset)
		path, pathErr := resolveArtifactOutputPath(opts.EvidenceJSONPath)
		if pathErr != nil {
			return reportArtifactResult{}, artifactPathError{err: pathErr}
		}
		if writeErr := reportcore.WriteEvidenceBundleJSON(path, evidenceSummary); writeErr != nil {
			return reportArtifactResult{}, writeErr
		}
		evidenceJSONPath = path
		if hasPairedSummary {
			pairedEvidenceSummary := reportcore.PrepareEvidenceBundleSummary(pairedSummary, opts.FocusPathID, opts.FocusPreset)
			externalPath := reportcore.PairedArtifactPath(path, strings.ReplaceAll(string(opts.PairedShareProfile), " ", "-"))
			if writeErr := reportcore.WriteEvidenceBundleJSON(externalPath, pairedEvidenceSummary); writeErr != nil {
				return reportArtifactResult{}, writeErr
			}
			pairedPaths["evidence_json_"+strings.ReplaceAll(string(opts.PairedShareProfile), "-", "_")] = externalPath
		}
	}

	backlogCSVPath := ""
	if opts.WriteBacklogCSV {
		path, writeErr := writePaired("backlog_csv", opts.BacklogCSVPath, func(current reportcore.Summary) ([]byte, error) {
			return reportcore.RenderBacklogCSV(current.ControlBacklog)
		}, summary, pairedSummary)
		if writeErr != nil {
			return reportArtifactResult{}, writeErr
		}
		backlogCSVPath = path
	}

	return reportArtifactResult{
		Summary:             summary,
		MarkdownPath:        mdOutPath,
		PDFPath:             pdfOutPath,
		EvidenceJSONPath:    evidenceJSONPath,
		BacklogCSVPath:      backlogCSVPath,
		PairedArtifactPaths: pairedPaths,
		PrivateJoinMapPath:  privateJoinMapPath,
	}, nil
}
