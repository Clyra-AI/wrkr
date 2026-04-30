package productiontargets

import (
	"sort"
	"strings"
)

type BuiltInMatchInput struct {
	Repos       []string
	Locations   []string
	Permissions []string
	Values      []string
	EvidenceKV  map[string][]string
}

func MatchBuiltInTargets(input BuiltInMatchInput) []string {
	matches := map[string]struct{}{}
	add := func(label string) {
		label = strings.TrimSpace(label)
		if label != "" {
			matches[label] = struct{}{}
		}
	}

	values := make([]string, 0, len(input.Values)+len(input.Permissions)+len(input.Locations))
	values = append(values, input.Values...)
	values = append(values, input.Permissions...)
	values = append(values, input.Locations...)
	values = append(values, input.Repos...)
	for _, items := range input.EvidenceKV {
		values = append(values, items...)
	}

	text := strings.ToLower(strings.Join(values, ","))
	if strings.Contains(text, "deploy.write") || strings.Contains(text, "deploy") {
		add("built_in:deploy_workflow")
	}
	if strings.Contains(text, "terraform") || strings.Contains(text, "iac.write") || strings.Contains(text, "infra.write") {
		add("built_in:terraform_iac")
	}
	if strings.Contains(text, "kubectl") || strings.Contains(text, "kubernetes") || strings.Contains(text, "k8s") || strings.Contains(text, "helm") || strings.Contains(text, "cluster") {
		add("built_in:kubernetes")
	}
	if strings.Contains(text, "packages.write") || strings.Contains(text, "package.publish") || strings.Contains(text, "ghcr.io") || strings.Contains(text, "docker.io") || strings.Contains(text, "pypi") || strings.Contains(text, "npm") {
		add("built_in:package_publish")
	}
	if strings.Contains(text, "release") || strings.Contains(text, "tag") {
		add("built_in:release_automation")
	}
	if strings.Contains(text, "migrate") || strings.Contains(text, "migration") || strings.Contains(text, "flyway") || strings.Contains(text, "liquibase") || strings.Contains(text, "dbmate") || strings.Contains(text, "alembic") || strings.Contains(text, "prisma") {
		add("built_in:database_migration")
	}
	if strings.Contains(text, "production") ||
		strings.Contains(text, "/prod") ||
		strings.Contains(text, "-prod") ||
		strings.Contains(text, "_prod") ||
		strings.Contains(text, "customer") ||
		strings.Contains(text, "live") {
		add("built_in:customer_impacting")
	}

	out := make([]string, 0, len(matches))
	for label := range matches {
		out = append(out, label)
	}
	sort.Strings(out)
	return out
}
