package risk

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/attribution"
)

func DecorateIntroducedBy(paths []ActionPath, repoRoots map[string]string) []ActionPath {
	if len(paths) == 0 {
		return nil
	}
	out := append([]ActionPath(nil), paths...)
	for i := range out {
		root := ""
		if repoRoots != nil {
			root = strings.TrimSpace(repoRoots[repoKey(out[i].Org, out[i].Repo)])
			if root == "" {
				root = strings.TrimSpace(repoRoots["local::"+strings.TrimSpace(out[i].Repo)])
			}
			if root == "" {
				root = strings.TrimSpace(repoRoots["::"+strings.TrimSpace(out[i].Repo)])
			}
		}
		out[i].IntroducedBy = attribution.Local(root, out[i].Location, out[i].LocationRange)
	}
	return out
}
