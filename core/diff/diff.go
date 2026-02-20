package diff

import (
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/source"
)

// Key is the tuple-key identity contract for diffing.
type Key struct {
	FindingType string `json:"finding_type"`
	RuleID      string `json:"rule_id,omitempty"`
	ToolType    string `json:"tool_type"`
	Location    string `json:"location"`
	Repo        string `json:"repo,omitempty"`
	Org         string `json:"org"`
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
	prevByKey := make(map[Key]source.Finding, len(previous))
	currByKey := make(map[Key]source.Finding, len(current))

	for _, item := range previous {
		prevByKey[toKey(item)] = normalizeFinding(item)
	}
	for _, item := range current {
		currByKey[toKey(item)] = normalizeFinding(item)
	}

	added := make([]source.Finding, 0)
	removed := make([]source.Finding, 0)
	changed := make([]ChangedItem, 0)

	for key, curr := range currByKey {
		prev, ok := prevByKey[key]
		if !ok {
			added = append(added, curr)
			continue
		}
		if !equalPerms(prev.Permissions, curr.Permissions) {
			changed = append(changed, ChangedItem{
				Key:               key,
				PreviousPerms:     copySlice(prev.Permissions),
				CurrentPerms:      copySlice(curr.Permissions),
				PermissionChanged: true,
			})
		}
	}

	for key, prev := range prevByKey {
		if _, ok := currByKey[key]; !ok {
			removed = append(removed, prev)
		}
	}

	source.SortFindings(added)
	source.SortFindings(removed)
	sort.Slice(changed, func(i, j int) bool {
		a := changed[i].Key
		b := changed[j].Key
		if a.FindingType == b.FindingType {
			if a.RuleID == b.RuleID {
				if a.ToolType == b.ToolType {
					if a.Location == b.Location {
						if a.Repo == b.Repo {
							return a.Org < b.Org
						}
						return a.Repo < b.Repo
					}
					return a.Location < b.Location
				}
				return a.ToolType < b.ToolType
			}
			return a.RuleID < b.RuleID
		}
		return a.FindingType < b.FindingType
	})

	return Result{Added: added, Removed: removed, Changed: changed}
}

func Empty(result Result) bool {
	return len(result.Added) == 0 && len(result.Removed) == 0 && len(result.Changed) == 0
}

func toKey(item source.Finding) Key {
	return Key{
		FindingType: strings.TrimSpace(item.FindingType),
		RuleID:      strings.TrimSpace(item.RuleID),
		ToolType:    strings.TrimSpace(item.ToolType),
		Location:    strings.TrimSpace(item.Location),
		Repo:        strings.TrimSpace(item.Repo),
		Org:         strings.TrimSpace(item.Org),
	}
}

func normalizeFinding(item source.Finding) source.Finding {
	item.FindingType = strings.TrimSpace(item.FindingType)
	item.RuleID = strings.TrimSpace(item.RuleID)
	item.ToolType = strings.TrimSpace(item.ToolType)
	item.Location = strings.TrimSpace(item.Location)
	item.Repo = strings.TrimSpace(item.Repo)
	item.Org = strings.TrimSpace(item.Org)
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
