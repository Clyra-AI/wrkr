package report

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/risk"
)

type actionSurfaceRegistryAccumulator struct {
	rank  int
	entry ActionSurfaceRegistryEntry
}

func BuildActionSurfaceRegistry(summary Summary) []ActionSurfaceRegistryEntry {
	if len(summary.ActionPaths) == 0 {
		return nil
	}
	bomByPath := map[string]AgentActionBOMItem{}
	if summary.AgentActionBOM != nil {
		for _, item := range summary.AgentActionBOM.Items {
			bomByPath[strings.TrimSpace(item.PathID)] = item
		}
	}
	graphRefsByPath, _ := controlPathGraphRefs(summary.ControlPathGraph)

	groups := map[string]*actionSurfaceRegistryAccumulator{}
	for idx, path := range summary.ActionPaths {
		key := actionSurfaceRegistryKey(path)
		group, ok := groups[key]
		if !ok {
			group = &actionSurfaceRegistryAccumulator{
				rank: idx,
				entry: ActionSurfaceRegistryEntry{
					RegistryID:             actionSurfaceRegistryID(key),
					SurfaceType:            actionSurfaceType(path),
					Org:                    strings.TrimSpace(path.Org),
					Repo:                   strings.TrimSpace(path.Repo),
					ToolType:               strings.TrimSpace(path.ToolType),
					ToolInstanceID:         strings.TrimSpace(path.ToolInstanceID),
					Location:               strings.TrimSpace(path.Location),
					Label:                  actionSurfaceLabel(path),
					Owner:                  strings.TrimSpace(path.OperationalOwner),
					OwnerSource:            strings.TrimSpace(path.OwnerSource),
					Purpose:                strings.TrimSpace(path.Purpose),
					PurposeSource:          strings.TrimSpace(path.PurposeSource),
					PurposeConfidence:      strings.TrimSpace(path.PurposeConfidence),
					Version:                strings.TrimSpace(path.Version),
					VersionSource:          strings.TrimSpace(path.VersionSource),
					ConfigFingerprint:      strings.TrimSpace(path.ConfigFingerprint),
					ConfigSource:           strings.TrimSpace(path.ConfigSource),
					CredentialAuthorityRef: strings.TrimSpace(path.CredentialAuthorityRef),
					AuthorityBindingRefs:   append([]string(nil), path.AuthorityBindingRefs...),
					ConfidenceLane:         strings.TrimSpace(path.ConfidenceLane),
					Remediation:            risk.RemediationForActionPath(path),
				},
			}
			groups[key] = group
		}
		if idx < group.rank {
			group.rank = idx
		}

		group.entry.Owner = firstNonEmptyValue(group.entry.Owner, strings.TrimSpace(path.OperationalOwner))
		group.entry.OwnerSource = firstNonEmptyValue(group.entry.OwnerSource, strings.TrimSpace(path.OwnerSource))
		group.entry.Purpose = firstNonEmptyValue(group.entry.Purpose, strings.TrimSpace(path.Purpose))
		group.entry.PurposeSource = firstNonEmptyValue(group.entry.PurposeSource, strings.TrimSpace(path.PurposeSource))
		group.entry.PurposeConfidence = firstNonEmptyValue(group.entry.PurposeConfidence, strings.TrimSpace(path.PurposeConfidence))
		group.entry.Version = firstNonEmptyValue(group.entry.Version, strings.TrimSpace(path.Version))
		group.entry.VersionSource = firstNonEmptyValue(group.entry.VersionSource, strings.TrimSpace(path.VersionSource))
		group.entry.ConfigFingerprint = firstNonEmptyValue(group.entry.ConfigFingerprint, strings.TrimSpace(path.ConfigFingerprint))
		group.entry.ConfigSource = firstNonEmptyValue(group.entry.ConfigSource, strings.TrimSpace(path.ConfigSource))
		group.entry.Remediation = firstNonEmptyValue(group.entry.Remediation, risk.RemediationForActionPath(path))
		group.entry.ReachableActions = uniqueSortedStrings(append(group.entry.ReachableActions, append([]string(nil), path.ActionClasses...)...))
		group.entry.MutableEndpointSemanticRefs = uniqueSortedStrings(append(group.entry.MutableEndpointSemanticRefs, append([]string(nil), path.MutableEndpointSemanticRefs...)...))
		group.entry.MutableEndpointSemantics = agginventory.NormalizeMutableEndpointSemantics(append(group.entry.MutableEndpointSemantics, path.MutableEndpointSemantics...))
		group.entry.PathIDs = uniqueSortedStrings(append(group.entry.PathIDs, strings.TrimSpace(path.PathID)))
		group.entry.ActionPathCount = len(group.entry.PathIDs)
		group.entry.GraphRefs = mergeRegistryGraphRefs(group.entry.GraphRefs, graphRefsByPath[strings.TrimSpace(path.PathID)])
		group.entry.CredentialAuthorityRef = firstNonEmptyValue(group.entry.CredentialAuthorityRef, strings.TrimSpace(path.CredentialAuthorityRef))
		group.entry.AuthorityBindingRefs = uniqueSortedStrings(append(group.entry.AuthorityBindingRefs, append([]string(nil), path.AuthorityBindingRefs...)...))
		group.entry.CredentialAuthority = mergeRegistryCredentialAuthority(group.entry.CredentialAuthority, path.CredentialAuthority)
		group.entry.Credentials = mergeRegistryCredentials(group.entry.Credentials, path.Credentials)
		if registryConfidenceLaneRank(strings.TrimSpace(path.ConfidenceLane)) < registryConfidenceLaneRank(group.entry.ConfidenceLane) {
			group.entry.ConfidenceLane = strings.TrimSpace(path.ConfidenceLane)
		}
		if item, ok := bomByPath[strings.TrimSpace(path.PathID)]; ok {
			group.entry.ProofStatus = mergeRegistryProofStatus(group.entry.ProofStatus, strings.TrimSpace(item.ProofCoverage))
		}
	}

	ordered := make([]*actionSurfaceRegistryAccumulator, 0, len(groups))
	for _, group := range groups {
		ordered = append(ordered, group)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].rank != ordered[j].rank {
			return ordered[i].rank < ordered[j].rank
		}
		left := ordered[i].entry
		right := ordered[j].entry
		if left.Org != right.Org {
			return left.Org < right.Org
		}
		if left.Repo != right.Repo {
			return left.Repo < right.Repo
		}
		if left.SurfaceType != right.SurfaceType {
			return left.SurfaceType < right.SurfaceType
		}
		if left.Location != right.Location {
			return left.Location < right.Location
		}
		if left.Label != right.Label {
			return left.Label < right.Label
		}
		return strings.Join(left.PathIDs, ",") < strings.Join(right.PathIDs, ",")
	})
	out := make([]ActionSurfaceRegistryEntry, 0, len(ordered))
	for _, group := range ordered {
		out = append(out, group.entry)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func actionSurfaceRegistryKey(path risk.ActionPath) string {
	return strings.Join([]string{
		strings.TrimSpace(path.Org),
		strings.TrimSpace(path.Repo),
		actionSurfaceType(path),
		firstNonEmptyValue(strings.TrimSpace(path.ToolInstanceID), strings.TrimSpace(path.ToolFamilyID), strings.TrimSpace(path.ToolType)),
		strings.TrimSpace(path.Location),
	}, "|")
}

func actionSurfaceRegistryID(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return "asr-" + hex.EncodeToString(sum[:6])
}

func actionSurfaceType(path risk.ActionPath) string {
	location := strings.ToLower(strings.TrimSpace(path.Location))
	toolType := strings.ToLower(strings.TrimSpace(path.ToolType))
	switch {
	case strings.Contains(location, ".github/workflows") || strings.Contains(location, "jenkinsfile") ||
		strings.HasSuffix(location, ".gitlab-ci.yml") || strings.HasSuffix(location, ".gitlab-ci.yaml") ||
		strings.Contains(location, "/.gitlab/ci/") || strings.HasSuffix(location, "azure-pipelines.yml") ||
		strings.HasSuffix(location, "azure-pipelines.yaml") || strings.Contains(location, "/.azure/pipelines/") ||
		toolType == "ci_agent":
		return "workflow"
	case toolType == "openapi":
		return "api_schema"
	case toolType == "route":
		return "route_file"
	case strings.Contains(toolType, "mcp"):
		return "server"
	case strings.Contains(location, "package.json"):
		return "package_script"
	case strings.Contains(location, "agent") || strings.Contains(location, "config") || strings.Contains(location, "agents.md"):
		return "agent_config"
	default:
		return "surface"
	}
}

func actionSurfaceLabel(path risk.ActionPath) string {
	return firstNonEmptyValue(strings.TrimSpace(path.Purpose), strings.TrimSpace(path.ToolType), strings.TrimSpace(path.Location))
}

func mergeRegistryGraphRefs(current, incoming AgentActionBOMGraphRefs) AgentActionBOMGraphRefs {
	return AgentActionBOMGraphRefs{
		NodeIDs: uniqueSortedStrings(append(append([]string(nil), current.NodeIDs...), incoming.NodeIDs...)),
		EdgeIDs: uniqueSortedStrings(append(append([]string(nil), current.EdgeIDs...), incoming.EdgeIDs...)),
	}
}

func mergeRegistryCredentialAuthority(current, incoming *agginventory.CredentialAuthority) *agginventory.CredentialAuthority {
	switch {
	case current == nil:
		return agginventory.CloneCredentialAuthority(incoming)
	case incoming == nil:
		return agginventory.CloneCredentialAuthority(current)
	case incoming.CredentialUsableByPath && !current.CredentialUsableByPath:
		return agginventory.CloneCredentialAuthority(incoming)
	case incoming.StandingAccess && !current.StandingAccess:
		return agginventory.CloneCredentialAuthority(incoming)
	default:
		return agginventory.CloneCredentialAuthority(current)
	}
}

func mergeRegistryCredentials(current, incoming []*agginventory.CredentialProvenance) []*agginventory.CredentialProvenance {
	return dedupeRegistryCredentials(append(append([]*agginventory.CredentialProvenance(nil), current...), incoming...))
}

func dedupeRegistryCredentials(values []*agginventory.CredentialProvenance) []*agginventory.CredentialProvenance {
	if len(values) == 0 {
		return nil
	}
	type key struct {
		kind    string
		subject string
		scope   string
	}
	merged := map[key]*agginventory.CredentialProvenance{}
	for _, item := range values {
		normalized := agginventory.CloneCredentialProvenance(item)
		if normalized == nil {
			continue
		}
		k := key{
			kind:    strings.TrimSpace(normalized.CredentialKind),
			subject: strings.TrimSpace(normalized.Subject),
			scope:   strings.TrimSpace(normalized.Scope),
		}
		if existing, ok := merged[k]; ok {
			existing.EvidenceBasis = uniqueSortedStrings(append(existing.EvidenceBasis, normalized.EvidenceBasis...))
			continue
		}
		merged[k] = normalized
	}
	out := make([]*agginventory.CredentialProvenance, 0, len(merged))
	for _, item := range merged {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CredentialKind != out[j].CredentialKind {
			return out[i].CredentialKind < out[j].CredentialKind
		}
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		return out[i].Scope < out[j].Scope
	})
	return out
}

func mergeRegistryProofStatus(current, incoming string) string {
	switch {
	case strings.TrimSpace(current) == "":
		return strings.TrimSpace(incoming)
	case registryProofStatusRank(strings.TrimSpace(incoming)) < registryProofStatusRank(strings.TrimSpace(current)):
		return strings.TrimSpace(incoming)
	default:
		return strings.TrimSpace(current)
	}
}

func registryProofStatusRank(value string) int {
	switch strings.TrimSpace(value) {
	case "missing":
		return 0
	case "chain_attached":
		return 1
	case "covered":
		return 2
	default:
		return 3
	}
}

func registryConfidenceLaneRank(value string) int {
	switch strings.TrimSpace(value) {
	case risk.ConfidenceLaneConfirmedActionPath:
		return 0
	case risk.ConfidenceLaneLikelyActionPath:
		return 1
	case risk.ConfidenceLaneSemanticReviewCandidate:
		return 2
	default:
		return 3
	}
}
