package report

import (
	"fmt"

	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

// ProjectComposedActionPathsForShareProfile returns a share-profile-safe
// projection without applying report presentation caps.
func ProjectComposedActionPathsForShareProfile(snapshot state.Snapshot, compositions []risk.ComposedActionPath, profile ShareProfile) ([]risk.ComposedActionPath, error) {
	if profile == "" {
		profile = ShareProfileInternal
	}
	if _, ok := ParseShareProfile(string(profile)); !ok {
		return nil, fmt.Errorf("unsupported share profile %q", profile)
	}
	if !shareProfileRequiresRedaction(profile) {
		return append([]risk.ComposedActionPath(nil), compositions...), nil
	}
	summary := Summary{
		ShareProfile:        string(profile),
		ComposedActionPaths: sanitizeComposedActionPathsWithConfig(compositions, ResolveRedactionConfig(profile, nil)),
	}
	summary, err := ApplyShareableResidualRedaction(snapshot, summary)
	if err != nil {
		return nil, err
	}
	return append([]risk.ComposedActionPath(nil), summary.ComposedActionPaths...), nil
}
