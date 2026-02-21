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
	StatePath        string
	Snapshot         state.Snapshot
	PreviousSnapshot *state.Snapshot
	Baseline         *regress.Baseline
	RegressResult    *regress.Result
	Manifest         *manifest.Manifest
	Top              int
	Template         reportcore.Template
	ShareProfile     reportcore.ShareProfile
	WriteMarkdown    bool
	MarkdownPath     string
	WritePDF         bool
	PDFPath          string
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
		return "", "", fmt.Errorf("--template must be one of exec|operator|audit|public")
	}

	shareValue := strings.TrimSpace(shareProfileRaw)
	if shareValue == "" {
		shareValue = string(reportcore.ShareProfileInternal)
	}
	shareProfile, ok := reportcore.ParseShareProfile(shareValue)
	if !ok {
		return "", "", fmt.Errorf("--share-profile must be one of internal|public")
	}
	return template, shareProfile, nil
}

func generateReportArtifacts(opts reportArtifactOptions) (reportcore.Summary, string, string, error) {
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
		return reportcore.Summary{}, "", "", err
	}

	markdown := reportcore.RenderMarkdown(summary)
	mdOutPath := ""
	if opts.WriteMarkdown {
		path, pathErr := resolveArtifactOutputPath(opts.MarkdownPath)
		if pathErr != nil {
			return reportcore.Summary{}, "", "", artifactPathError{err: pathErr}
		}
		if writeErr := os.WriteFile(path, []byte(markdown), 0o600); writeErr != nil {
			return reportcore.Summary{}, "", "", writeErr
		}
		mdOutPath = path
	}

	pdfOutPath := ""
	if opts.WritePDF {
		path, pathErr := resolveArtifactOutputPath(opts.PDFPath)
		if pathErr != nil {
			return reportcore.Summary{}, "", "", artifactPathError{err: pathErr}
		}
		if writeErr := writeReportPDF(path, reportcore.MarkdownLines(markdown)); writeErr != nil {
			return reportcore.Summary{}, "", "", writeErr
		}
		pdfOutPath = path
	}

	return summary, mdOutPath, pdfOutPath, nil
}
