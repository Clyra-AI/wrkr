package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/regress"
	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/state"
)

type reportArtifactOptions struct {
	StatePath         string
	Snapshot          state.Snapshot
	PreviousSnapshot  *state.Snapshot
	Baseline          *regress.Baseline
	RegressResult     *regress.Result
	Manifest          *manifest.Manifest
	Top               int
	Template          reportcore.Template
	ShareProfile      reportcore.ShareProfile
	WriteMarkdown     bool
	MarkdownPath      string
	WritePDF          bool
	PDFPath           string
	WriteEvidenceJSON bool
	EvidenceJSONPath  string
	WriteBacklogCSV   bool
	BacklogCSVPath    string
}

type reportArtifactResult struct {
	Summary          reportcore.Summary
	MarkdownPath     string
	PDFPath          string
	EvidenceJSONPath string
	BacklogCSVPath   string
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
		return "", "", fmt.Errorf("--template must be one of exec|operator|audit|public|ciso|appsec|platform|customer-draft")
	}

	shareValue := strings.TrimSpace(shareProfileRaw)
	if shareValue == "" {
		shareValue = string(reportcore.ShareProfileInternal)
		if template == reportcore.TemplateCustomerDraft {
			shareValue = string(reportcore.ShareProfilePublic)
		}
	}
	shareProfile, ok := reportcore.ParseShareProfile(shareValue)
	if !ok {
		return "", "", fmt.Errorf("--share-profile must be one of internal|public")
	}
	return template, shareProfile, nil
}

func generateReportArtifacts(opts reportArtifactOptions) (reportArtifactResult, error) {
	summary, err := reportcore.BuildSummary(reportcore.BuildInput{
		StatePath:        opts.StatePath,
		Snapshot:         opts.Snapshot,
		PreviousSnapshot: opts.PreviousSnapshot,
		Baseline:         opts.Baseline,
		RegressResult:    opts.RegressResult,
		Manifest:         opts.Manifest,
		Top:              opts.Top,
		Template:         opts.Template,
		ShareProfile:     opts.ShareProfile,
	})
	if err != nil {
		return reportArtifactResult{}, err
	}

	markdown := reportcore.RenderMarkdown(summary)
	mdOutPath := ""
	if opts.WriteMarkdown {
		path, pathErr := resolveArtifactOutputPath(opts.MarkdownPath)
		if pathErr != nil {
			return reportArtifactResult{}, artifactPathError{err: pathErr}
		}
		if writeErr := os.WriteFile(path, []byte(markdown), 0o600); writeErr != nil {
			return reportArtifactResult{}, writeErr
		}
		mdOutPath = path
	}

	pdfOutPath := ""
	if opts.WritePDF {
		path, pathErr := resolveArtifactOutputPath(opts.PDFPath)
		if pathErr != nil {
			return reportArtifactResult{}, artifactPathError{err: pathErr}
		}
		if writeErr := writeReportPDF(path, reportcore.MarkdownLines(markdown)); writeErr != nil {
			return reportArtifactResult{}, writeErr
		}
		pdfOutPath = path
	}

	evidenceJSONPath := ""
	if opts.WriteEvidenceJSON {
		path, pathErr := resolveArtifactOutputPath(opts.EvidenceJSONPath)
		if pathErr != nil {
			return reportArtifactResult{}, artifactPathError{err: pathErr}
		}
		payload, marshalErr := reportcore.RenderEvidenceBundleJSON(summary)
		if marshalErr != nil {
			return reportArtifactResult{}, marshalErr
		}
		if writeErr := os.WriteFile(path, payload, 0o600); writeErr != nil {
			return reportArtifactResult{}, writeErr
		}
		evidenceJSONPath = path
	}

	backlogCSVPath := ""
	if opts.WriteBacklogCSV {
		path, pathErr := resolveArtifactOutputPath(opts.BacklogCSVPath)
		if pathErr != nil {
			return reportArtifactResult{}, artifactPathError{err: pathErr}
		}
		payload, csvErr := reportcore.RenderBacklogCSV(summary.ControlBacklog)
		if csvErr != nil {
			return reportArtifactResult{}, csvErr
		}
		if writeErr := os.WriteFile(path, payload, 0o600); writeErr != nil {
			return reportArtifactResult{}, writeErr
		}
		backlogCSVPath = path
	}

	return reportArtifactResult{
		Summary:          summary,
		MarkdownPath:     mdOutPath,
		PDFPath:          pdfOutPath,
		EvidenceJSONPath: evidenceJSONPath,
		BacklogCSVPath:   backlogCSVPath,
	}, nil
}
