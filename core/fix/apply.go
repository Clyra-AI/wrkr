package fix

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/manifestgen"
	"github.com/Clyra-AI/wrkr/core/state"
	"gopkg.in/yaml.v3"
)

var ErrNoApplyCapableRemediations = errors.New("no apply-capable remediations available")

func ApplyCapablePlan(plan Plan) Plan {
	out := Plan{
		RequestedTop: plan.RequestedTop,
		Skipped:      append([]Skipped(nil), plan.Skipped...),
	}
	for _, item := range plan.Remediations {
		if item.ApplySupported {
			out.Remediations = append(out.Remediations, item)
		}
	}
	out.Fingerprint = planFingerprint(out.Remediations, out.Skipped)
	return out
}

// BuildApplyArtifacts renders deterministic repo files for the explicit apply surface.
// It fails closed when the selected plan has no apply-capable remediations.
func BuildApplyArtifacts(snapshot state.Snapshot, plan Plan) ([]PRArtifact, error) {
	needsManifest := len(ApplyCapablePlan(plan).Remediations) > 0
	if !needsManifest {
		return nil, ErrNoApplyCapableRemediations
	}

	now := resolveApplyGeneratedAt(snapshot)
	generated, err := manifestgen.GenerateUnderReview(snapshot, now)
	if err != nil {
		return nil, fmt.Errorf("generate apply manifest: %w", err)
	}
	payload, err := yaml.Marshal(generated)
	if err != nil {
		return nil, fmt.Errorf("marshal apply manifest: %w", err)
	}
	payload = append(payload, '\n')

	out := []PRArtifact{
		{
			Path:          filepath.ToSlash(manifest.ResolvePath(filepath.Join(".wrkr", "last-scan.json"))),
			Content:       payload,
			CommitMessage: "fix(manifest): apply deterministic under-review manifest",
		},
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func resolveApplyGeneratedAt(snapshot state.Snapshot) time.Time {
	if snapshot.RiskReport != nil && strings.TrimSpace(snapshot.RiskReport.GeneratedAt) != "" {
		if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(snapshot.RiskReport.GeneratedAt)); err == nil {
			return parsed.UTC().Truncate(time.Second)
		}
	}
	return time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
}
