package diff

import (
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/source"
)

// Key is the tuple-key identity contract for diffing.
type Key struct {
	FindingType     string `json:"finding_type"`
	RuleID          string `json:"rule_id,omitempty"`
	DiscoveryMethod string `json:"discovery_method,omitempty"`
	ToolType        string `json:"tool_type"`
	Location        string `json:"location"`
	Repo            string `json:"repo,omitempty"`
	Org             string `json:"org"`
	Detector        string `json:"detector,omitempty"`
	CheckResult     string `json:"check_result,omitempty"`
	Severity        string `json:"severity,omitempty"`
	Autonomy        string `json:"autonomy,omitempty"`
	EvidenceKey     string `json:"evidence_key,omitempty"`
	ParseError      string `json:"parse_error,omitempty"`
}

// ChangedItem reports the before/after permission tuple when key identity is stable.
type ChangedItem struct {
	Key               Key      `json:"key"`
	PreviousPerms     []string `json:"previous_permissions"`
	CurrentPerms      []string `json:"current_permissions"`
	PermissionChanged bool     `json:"permission_changed"`
}

// Result is the deterministic diff payload.
type Result struct {
	Added   []source.Finding `json:"added"`
	Removed []source.Finding `json:"removed"`
	Changed []ChangedItem    `json:"changed"`
}

func Compute(previous, current []source.Finding) Result {
	prevByKey := make(map[Key][]source.Finding, len(previous))
	currByKey := make(map[Key][]source.Finding, len(current))

	for _, item := range previous {
		normalized := normalizeFinding(item)
		prevByKey[toKey(normalized)] = append(prevByKey[toKey(normalized)], normalized)
	}
	for _, item := range current {
		normalized := normalizeFinding(item)
		currByKey[toKey(normalized)] = append(currByKey[toKey(normalized)], normalized)
	}

	for key := range prevByKey {
		sortFindingSlice(prevByKey[key])
	}
	for key := range currByKey {
		sortFindingSlice(currByKey[key])
	}

	added := make([]source.Finding, 0)
	removed := make([]source.Finding, 0)
	changed := make([]ChangedItem, 0)
	seen := make(map[Key]struct{}, len(currByKey))

	for key, currList := range currByKey {
		seen[key] = struct{}{}
		prevList, ok := prevByKey[key]
		if !ok {
			added = append(added, currList...)
			continue
		}

		minLen := min(len(prevList), len(currList))
		for i := 0; i < minLen; i++ {
			if !equalPerms(prevList[i].Permissions, currList[i].Permissions) {
				changed = append(changed, ChangedItem{
					Key:               key,
					PreviousPerms:     copySlice(prevList[i].Permissions),
					CurrentPerms:      copySlice(currList[i].Permissions),
					PermissionChanged: true,
				})
			}
		}
		if len(currList) > minLen {
			added = append(added, currList[minLen:]...)
		}
		if len(prevList) > minLen {
			removed = append(removed, prevList[minLen:]...)
		}
	}

	for key, prevList := range prevByKey {
		if _, ok := seen[key]; ok {
			continue
		}
		removed = append(removed, prevList...)
	}

	source.SortFindings(added)
	source.SortFindings(removed)
	sort.Slice(changed, func(i, j int) bool {
		return keyLess(changed[i].Key, changed[j].Key)
	})

	return Result{Added: added, Removed: removed, Changed: changed}
}

func Empty(result Result) bool {
	return len(result.Added) == 0 && len(result.Removed) == 0 && len(result.Changed) == 0
}

func toKey(item source.Finding) Key {
	return Key{
		FindingType:     strings.TrimSpace(item.FindingType),
		RuleID:          strings.TrimSpace(item.RuleID),
		DiscoveryMethod: strings.TrimSpace(item.DiscoveryMethod),
		ToolType:        strings.TrimSpace(item.ToolType),
		Location:        strings.TrimSpace(item.Location),
		Repo:            strings.TrimSpace(item.Repo),
		Org:             strings.TrimSpace(item.Org),
		Detector:        strings.TrimSpace(item.Detector),
		CheckResult:     strings.TrimSpace(item.CheckResult),
		Severity:        strings.TrimSpace(item.Severity),
		Autonomy:        strings.TrimSpace(item.Autonomy),
		EvidenceKey:     evidenceKey(item.Evidence),
		ParseError:      parseErrorKey(item.ParseError),
	}
}

func normalizeFinding(item source.Finding) source.Finding {
	item.FindingType = strings.TrimSpace(item.FindingType)
	item.RuleID = strings.TrimSpace(item.RuleID)
	item.ToolType = strings.TrimSpace(item.ToolType)
	item.Location = strings.TrimSpace(item.Location)
	item.Repo = strings.TrimSpace(item.Repo)
	item.Org = strings.TrimSpace(item.Org)
	item.DiscoveryMethod = strings.TrimSpace(item.DiscoveryMethod)
	if item.DiscoveryMethod == "" {
		item.DiscoveryMethod = model.DiscoveryMethodStatic
	}
	item.Permissions = normalizePerms(item.Permissions)
	return item
}

func normalizePerms(in []string) []string {
	out := make([]string, 0, len(in))
	for _, perm := range in {
		trimmed := strings.TrimSpace(perm)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func equalPerms(a, b []string) bool {
	a = normalizePerms(a)
	b = normalizePerms(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func copySlice(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func evidenceKey(in []model.Evidence) string {
	if len(in) == 0 {
		return ""
	}
	items := make([]string, 0, len(in))
	for _, item := range in {
		key := strings.TrimSpace(item.Key)
		value := strings.TrimSpace(item.Value)
		if key == "" && value == "" {
			continue
		}
		items = append(items, key+"="+value)
	}
	sort.Strings(items)
	return strings.Join(items, "|")
}

func parseErrorKey(in *model.ParseError) string {
	if in == nil {
		return ""
	}
	parts := []string{
		strings.TrimSpace(in.Kind),
		strings.TrimSpace(in.Format),
		strings.TrimSpace(in.Path),
		strings.TrimSpace(in.Detector),
		strings.TrimSpace(in.Message),
	}
	return strings.Join(parts, "|")
}

func sortFindingSlice(in []source.Finding) {
	sort.Slice(in, func(i, j int) bool {
		left := strings.Join(in[i].Permissions, ",")
		right := strings.Join(in[j].Permissions, ",")
		return left < right
	})
}

func keyLess(a, b Key) bool {
	if a.FindingType != b.FindingType {
		return a.FindingType < b.FindingType
	}
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	if a.DiscoveryMethod != b.DiscoveryMethod {
		return a.DiscoveryMethod < b.DiscoveryMethod
	}
	if a.ToolType != b.ToolType {
		return a.ToolType < b.ToolType
	}
	if a.Location != b.Location {
		return a.Location < b.Location
	}
	if a.Repo != b.Repo {
		return a.Repo < b.Repo
	}
	if a.Org != b.Org {
		return a.Org < b.Org
	}
	if a.Detector != b.Detector {
		return a.Detector < b.Detector
	}
	if a.CheckResult != b.CheckResult {
		return a.CheckResult < b.CheckResult
	}
	if a.Severity != b.Severity {
		return a.Severity < b.Severity
	}
	if a.Autonomy != b.Autonomy {
		return a.Autonomy < b.Autonomy
	}
	if a.EvidenceKey != b.EvidenceKey {
		return a.EvidenceKey < b.EvidenceKey
	}
	return a.ParseError < b.ParseError
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
