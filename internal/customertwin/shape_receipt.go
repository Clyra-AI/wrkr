package customertwin

import "sort"

type ShapeReceiptInput struct {
	Repositories                  int `json:"repositories"`
	JenkinsFiles                  int `json:"jenkins_files"`
	DirectCredentialReferences    int `json:"direct_credential_references"`
	InheritedCredentialReferences int `json:"inherited_credential_references"`
	ResolvedRelationships         int `json:"resolved_relationships"`
	UnresolvedRelationships       int `json:"unresolved_relationships"`
	APISpecifications             int `json:"api_specifications"`
	APIOperations                 int `json:"api_operations"`
	ParserFailures                int `json:"parser_failures"`
}

type ShapeDelta struct {
	Metric   string `json:"metric"`
	Expected int    `json:"expected"`
	Observed int    `json:"observed"`
	Delta    int    `json:"delta"`
}

type ShapeReceipt struct {
	Version int          `json:"version"`
	Deltas  []ShapeDelta `json:"deltas"`
}

func CompareShape(input ShapeReceiptInput) ShapeReceipt {
	oracle := CustomerOracle()
	values := []ShapeDelta{
		shapeDelta("repositories", oracle.Repositories, input.Repositories),
		shapeDelta("jenkins_files", oracle.JenkinsCallers, input.JenkinsFiles),
		shapeDelta("direct_credential_references", oracle.DirectCredentialRefs, input.DirectCredentialReferences),
		shapeDelta("inherited_credential_references", oracle.InheritedCredentialRefs, input.InheritedCredentialReferences),
		shapeDelta("resolved_relationships", oracle.SharedLibraryCallers-oracle.UnmappedLibraryCallers, input.ResolvedRelationships),
		shapeDelta("unresolved_relationships", oracle.UnmappedLibraryCallers+oracle.DynamicRelationships, input.UnresolvedRelationships),
		shapeDelta("api_specifications", oracle.APISpecFiles, input.APISpecifications),
		shapeDelta("api_operations", oracle.APIOperations, input.APIOperations),
		shapeDelta("parser_failures", oracle.ParserFailures, input.ParserFailures),
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Metric < values[j].Metric })
	return ShapeReceipt{Version: 1, Deltas: values}
}

func shapeDelta(metric string, expected, observed int) ShapeDelta {
	return ShapeDelta{Metric: metric, Expected: expected, Observed: observed, Delta: observed - expected}
}
