package productiontargets

import "testing"

func TestMatchBuiltInTargetsCoversDeployAndKubernetesSignals(t *testing.T) {
	t.Parallel()

	matches := MatchBuiltInTargets(BuiltInMatchInput{
		Repos:       []string{"acme/payments"},
		Locations:   []string{".github/workflows/release.yml"},
		Permissions: []string{"deploy.write"},
		Values:      []string{"kubectl", "helm", "ghcr.io"},
		EvidenceKV:  map[string][]string{"env_value": {"production"}},
	})

	for _, want := range []string{
		"built_in:deploy_workflow",
		"built_in:kubernetes",
		"built_in:package_publish",
		"built_in:customer_impacting",
	} {
		found := false
		for _, got := range matches {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected built-in target %q in %+v", want, matches)
		}
	}
}
