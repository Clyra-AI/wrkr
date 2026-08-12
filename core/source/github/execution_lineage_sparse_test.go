package github

import "testing"

func TestSparseExecutionLineageSelection(t *testing.T) {
	t.Parallel()
	tests := map[string]bool{
		".github/actions/release/action.yml":     true,
		"vars/deploy.groovy":                     true,
		"shared/src/acme/Deploy.groovy":          true,
		"jenkins/scripts/release.groovy":         true,
		"proto-spec/service.json":                true,
		"contracts/payments.yaml":                true,
		"ui/swagger-config.js":                   true,
		"build/api/openapi.json":                 true,
		"build/api/service.json":                 true,
		"build/assets/settings.json":             false,
		"config/settings.json":                   false,
		"vendor/vars/deploy.groovy":              false,
		"node_modules/example/dist/openapi.json": false,
	}
	for rel, expected := range tests {
		got := shouldMaterializeBlobWithSource(rel, false)
		if got != expected {
			t.Fatalf("sparse selection for %s = %t, want %t", rel, got, expected)
		}
	}
}
