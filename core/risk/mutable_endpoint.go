package risk

import (
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func pathMutableEndpointSemantics(path ActionPath) []agginventory.MutableEndpointSemantic {
	return path.MutableEndpointSemantics
}

func pathHasMutableEndpointSemantic(path ActionPath, wants ...string) bool {
	wanted := make(map[string]struct{}, len(wants))
	for _, want := range wants {
		if want = strings.TrimSpace(want); want != "" {
			wanted[want] = struct{}{}
		}
	}
	for _, item := range pathMutableEndpointSemantics(path) {
		if _, ok := wanted[strings.TrimSpace(item.Semantic)]; ok {
			return true
		}
	}
	return false
}

func pathHasAnyMutableEndpoint(path ActionPath) bool {
	return len(pathMutableEndpointSemantics(path)) > 0
}

func pathHasHighImpactMutableEndpoint(path ActionPath) bool {
	return pathHasMutableEndpointSemantic(path,
		agginventory.EndpointSemanticPayment,
		agginventory.EndpointSemanticRefund,
		agginventory.EndpointSemanticUserAdmin,
		agginventory.EndpointSemanticDelete,
		agginventory.EndpointSemanticDeploy,
		agginventory.EndpointSemanticProductionMutation,
	)
}

func pathHasSensitiveDataEndpoint(path ActionPath) bool {
	return pathHasMutableEndpointSemantic(path,
		agginventory.EndpointSemanticPayment,
		agginventory.EndpointSemanticRefund,
		agginventory.EndpointSemanticDataExport,
		agginventory.EndpointSemanticUserAdmin,
		agginventory.EndpointSemanticProductionMutation,
	)
}

func pathMutableEndpointOperations(path ActionPath) []string {
	values := []string{}
	for _, item := range pathMutableEndpointSemantics(path) {
		if strings.TrimSpace(item.Operation) != "" {
			values = append(values, strings.TrimSpace(item.Operation))
			continue
		}
		values = append(values, strings.TrimSpace(item.Semantic))
	}
	sort.Strings(values)
	if len(values) == 0 {
		return nil
	}
	return values
}

func pathMutableEndpointPriority(path ActionPath) int {
	score := 0
	for _, item := range pathMutableEndpointSemantics(path) {
		switch strings.TrimSpace(item.Semantic) {
		case agginventory.EndpointSemanticProductionMutation:
			score += 8
		case agginventory.EndpointSemanticPayment, agginventory.EndpointSemanticRefund:
			score += 7
		case agginventory.EndpointSemanticUserAdmin:
			score += 6
		case agginventory.EndpointSemanticDeploy:
			score += 5
		case agginventory.EndpointSemanticDelete:
			score += 4
		case agginventory.EndpointSemanticDataExport:
			score += 3
		case agginventory.EndpointSemanticWrite:
			score += 2
		case agginventory.EndpointSemanticRead:
			score += 1
		}
		if strings.TrimSpace(item.Confidence) == "high" {
			score++
		}
	}
	return score
}
