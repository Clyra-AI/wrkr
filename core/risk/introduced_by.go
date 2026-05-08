package risk

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/attribution"
)

func DecorateIntroducedBy(paths []ActionPath, repoContexts map[string]attribution.Context) []ActionPath {
	if len(paths) == 0 {
		return nil
	}
	out := append([]ActionPath(nil), paths...)
	for i := range out {
		ctx := attribution.Context{}
		if repoContexts != nil {
			ctx = repoContexts[repoKey(out[i].Org, out[i].Repo)]
			if strings.TrimSpace(ctx.RepoRoot) == "" {
				ctx = repoContexts["local::"+strings.TrimSpace(out[i].Repo)]
			}
			if strings.TrimSpace(ctx.RepoRoot) == "" {
				ctx = repoContexts["::"+strings.TrimSpace(out[i].Repo)]
			}
		}
		out[i].IntroducedBy = attribution.Resolve(ctx, out[i].Location, out[i].LocationRange)
	}
	return out
}
