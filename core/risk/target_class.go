package risk

import (
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

const (
	TargetClassProductionImpacting = "production_impacting"
	TargetClassReleaseAdjacent     = "release_adjacent"
	TargetClassCustomerDataAdjacent = "customer_data_adjacent"
	TargetClassInternalTooling     = "internal_tooling"
	TargetClassDeveloperProductivity = "developer_productivity"
	TargetClassTestDemoSandbox     = "test_demo_sandbox"
	TargetClassUnknown             = "unknown"
)

func ValidTargetClass(value string) bool {
	switch strings.TrimSpace(value) {
	case TargetClassProductionImpacting,
		TargetClassReleaseAdjacent,
		TargetClassCustomerDataAdjacent,
		TargetClassInternalTooling,
		TargetClassDeveloperProductivity,
		TargetClassTestDemoSandbox,
		TargetClassUnknown:
		return true
	default:
		return false
	}
}

func deriveTargetClass(path ActionPath) (string, []string, []string) {
	reasons := []string{}
	refs := []string{}
	addReason := func(reason string) {
		if strings.TrimSpace(reason) != "" {
			reasons = append(reasons, strings.TrimSpace(reason))
		}
	}
	addRef := func(ref string) {
		if strings.TrimSpace(ref) != "" {
			refs = append(refs, strings.TrimSpace(ref))
		}
	}

	for _, target := range path.MatchedProductionTargets {
		addRef("matched_target:" + strings.TrimSpace(target))
	}
	for _, reason := range path.ActionReasons {
		if strings.TrimSpace(reason) != "" {
			addRef(reason)
		}
	}
	for _, item := range pathMutableEndpointSemantics(path) {
		addReason("mutable_endpoint:" + strings.TrimSpace(item.Semantic))
		for _, ref := range item.EvidenceRefs {
			addRef(ref)
		}
	}

	location := strings.ToLower(strings.TrimSpace(path.Location))
	repo := strings.ToLower(strings.TrimSpace(path.Repo))
	switch {
	case pathHasSensitiveDataEndpoint(path) || strings.TrimSpace(path.BusinessStateSurface) == "admin_api" || strings.TrimSpace(path.BusinessStateSurface) == "db":
		if pathHasSensitiveDataEndpoint(path) {
			addReason("customer_data_surface:true")
		}
		if strings.TrimSpace(path.BusinessStateSurface) != "" {
			addReason("business_state_surface:" + strings.TrimSpace(path.BusinessStateSurface))
		}
		return TargetClassCustomerDataAdjacent, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	case path.ProductionWrite || len(path.MatchedProductionTargets) > 0 || strings.EqualFold(strings.TrimSpace(path.DeploymentStatus), "deployed"):
		if path.ProductionWrite {
			addReason("production_write:true")
		}
		if strings.TrimSpace(path.DeploymentStatus) != "" {
			addReason("deployment_status:" + strings.TrimSpace(path.DeploymentStatus))
		}
		return TargetClassProductionImpacting, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	case pathIsTestDemoSandbox(path):
		addReason("sandbox_or_test_surface:true")
		return TargetClassTestDemoSandbox, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	case pathIsDeveloperProductivity(path):
		addReason("developer_productivity_surface:true")
		return TargetClassDeveloperProductivity, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	case pathIsInternalTooling(path):
		addReason("internal_tooling_surface:true")
		return TargetClassInternalTooling, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	case containsAnyPathClass(path.WritePathClasses, agginventory.WritePathReleaseWrite, agginventory.WritePathPackagePublish, agginventory.WritePathDeployWrite, agginventory.WritePathInfraWrite) ||
		containsPathValue(path.ActionClasses, agginventory.ActionClassDeploy) ||
		(strings.Contains(location, "release") && !strings.Contains(location, "/tools/") && !strings.HasPrefix(location, "tools/")) ||
		strings.Contains(location, "publish"):
		addReason("delivery_surface:true")
		return TargetClassReleaseAdjacent, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	default:
		if strings.TrimSpace(repo) != "" {
			addRef("repo:" + strings.TrimSpace(path.Repo))
		}
		return TargetClassUnknown, []string{"target_class:unknown"}, dedupeSortedStrings(refs)
	}
}

func chooseTargetClass(current, incoming string) string {
	current = normalizeTargetClass(current)
	incoming = normalizeTargetClass(incoming)
	switch {
	case current == "":
		return incoming
	case incoming == "":
		return current
	case current == incoming:
		return current
	default:
		if targetClassRank(incoming) < targetClassRank(current) {
			return incoming
		}
		return current
	}
}

func normalizeTargetClass(value string) string {
	value = strings.TrimSpace(value)
	if !ValidTargetClass(value) {
		return ""
	}
	return value
}

func targetClassRank(value string) int {
	switch strings.TrimSpace(value) {
	case TargetClassProductionImpacting:
		return 0
	case TargetClassCustomerDataAdjacent:
		return 1
	case TargetClassReleaseAdjacent:
		return 2
	case TargetClassUnknown:
		return 3
	case TargetClassInternalTooling:
		return 4
	case TargetClassDeveloperProductivity:
		return 5
	case TargetClassTestDemoSandbox:
		return 6
	default:
		return 99
	}
}

func pathIsDeveloperProductivity(path ActionPath) bool {
	location := strings.ToLower(strings.TrimSpace(path.Location))
	toolType := strings.ToLower(strings.TrimSpace(path.ToolType))
	switch {
	case strings.Contains(location, "agents.md"),
		strings.Contains(location, "claude.md"),
		strings.Contains(location, ".claude/"),
		strings.Contains(location, ".cursor/"),
		strings.Contains(location, ".codex/"),
		strings.Contains(location, "copilot-instructions"):
		return true
	case toolType == "claude" || toolType == "cursor" || toolType == "codex" || toolType == "copilot" || toolType == "prompt_channel" || toolType == "skill":
		return true
	default:
		return false
	}
}

func pathIsInternalTooling(path ActionPath) bool {
	location := strings.ToLower(strings.TrimSpace(path.Location))
	repo := strings.ToLower(strings.TrimSpace(path.Repo))
	switch {
	case strings.TrimSpace(path.BusinessStateSurface) == "ticketing" || strings.TrimSpace(path.BusinessStateSurface) == "workflow_control":
		return true
	case strings.Contains(location, "/internal/") || strings.HasPrefix(location, "internal/"),
		strings.Contains(location, "/tools/") || strings.HasPrefix(location, "tools/"),
		strings.Contains(location, "/ops/") || strings.HasPrefix(location, "ops/"),
		strings.Contains(location, "backoffice"),
		strings.Contains(repo, "platform"),
		strings.Contains(repo, "tooling"):
		return true
	default:
		return false
	}
}

func pathIsTestDemoSandbox(path ActionPath) bool {
	location := strings.ToLower(strings.TrimSpace(path.Location))
	if path.PathContext != nil {
		switch strings.TrimSpace(path.PathContext.Kind) {
		case agginventory.PathContextExample,
			agginventory.PathContextUnitTest,
			agginventory.PathContextFunctionalTest,
			agginventory.PathContextDocs:
			return true
		}
	}
	switch {
	case strings.Contains(location, "/test/"),
		strings.Contains(location, "/tests/"),
		strings.Contains(location, "demo"),
		strings.Contains(location, "sandbox"),
		strings.Contains(location, "fixture"),
		strings.Contains(location, "example"):
		return true
	default:
		return false
	}
}
