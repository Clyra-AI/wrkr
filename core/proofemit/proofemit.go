package proofemit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	proof "github.com/Clyra-AI/proof"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/model"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/proofmap"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/score"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

type Summary struct {
	Findings    int
	Risk        int
	Transitions int
	Total       int
	ChainPath   string
}

func ChainPath(statePath string) string {
	dir := filepath.Dir(strings.TrimSpace(statePath))
	if dir == "" || dir == "." {
		dir = ".wrkr"
	}
	return filepath.Join(dir, "proof-chain.json")
}

func SigningKeyPath(statePath string) string {
	return keyPath(statePath)
}

func LoadChain(path string) (*proof.Chain, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- path is an explicit local proof chain location controlled by CLI state configuration.
	if err != nil {
		if os.IsNotExist(err) {
			return proof.NewChain("wrkr-proof"), nil
		}
		return nil, fmt.Errorf("read proof chain: %w", err)
	}
	var chain proof.Chain
	if err := json.Unmarshal(payload, &chain); err != nil {
		return nil, fmt.Errorf("parse proof chain: %w", err)
	}
	if strings.TrimSpace(chain.ChainID) == "" {
		chain.ChainID = "wrkr-proof"
	}
	return &chain, nil
}

func SaveChain(path string, chain *proof.Chain) error {
	if chain == nil {
		return fmt.Errorf("chain is required")
	}
	payload, err := json.Marshal(chain)
	if err != nil {
		return fmt.Errorf("marshal proof chain: %w", err)
	}
	payload = append(payload, '\n')
	if err := atomicwrite.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write proof chain: %w", err)
	}
	return nil
}

func EmitScan(statePath string, now time.Time, findings []model.Finding, inventory *agginventory.Inventory, report risk.Report, profile profileeval.Result, posture score.Result, transitions []lifecycle.Transition) (Summary, error) {
	return EmitScanWithContext(context.Background(), statePath, now, findings, inventory, report, profile, posture, transitions)
}

func EmitScanWithContext(ctx context.Context, statePath string, now time.Time, findings []model.Finding, inventory *agginventory.Inventory, report risk.Report, profile profileeval.Result, posture score.Result, transitions []lifecycle.Transition) (Summary, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	chainPath := ChainPath(statePath)
	chain, err := LoadChain(chainPath)
	if err != nil {
		return Summary{}, err
	}
	key, err := loadSigningKey(statePath)
	if err != nil {
		return Summary{}, err
	}

	summary := Summary{ChainPath: chainPath}
	findingRecordIDs := map[string]string{}
	visibility := proofVisibilityContext(inventory)
	mappedFindings := proofmap.MapFindings(findings, &profile, visibility, now)
	for _, mapped := range mappedFindings {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Summary{}, ctxErr
		}
		record, err := appendSignedRecord(chain, key, mapped)
		if err != nil {
			return Summary{}, err
		}
		canonicalKey := metadataString(mapped.Metadata, "canonical_finding_key")
		if canonicalKey != "" {
			findingRecordIDs[canonicalKey] = strings.TrimSpace(record.RecordID)
			findingRecordIDs[canonicalFindingLookupKey(canonicalKey)] = strings.TrimSpace(record.RecordID)
		}
		summary.Findings++
		summary.Total++
	}

	mappedRisk := proofmap.MapRisk(report, posture, profile, visibility, now)
	for _, mapped := range mappedRisk {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Summary{}, ctxErr
		}
		linkMappedRecordToFindings(&mapped, findingRecordIDs)
		if _, err := appendSignedRecord(chain, key, mapped); err != nil {
			return Summary{}, err
		}
		summary.Risk++
		summary.Total++
	}

	for _, transition := range transitions {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Summary{}, ctxErr
		}
		mapped := proofmap.MapTransition(transition, "lifecycle_transition")
		if _, err := appendSignedRecord(chain, key, mapped); err != nil {
			return Summary{}, err
		}
		summary.Transitions++
		summary.Total++
	}

	if err := signChain(chain, key); err != nil {
		return Summary{}, err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Summary{}, ctxErr
	}
	if err := SaveChain(chainPath, chain); err != nil {
		return Summary{}, err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Summary{}, ctxErr
	}
	if err := saveChainAttestation(chainPath, len(chain.Records), chain.HeadHash, key); err != nil {
		return Summary{}, err
	}
	return summary, nil
}

func proofVisibilityContext(inventory *agginventory.Inventory) proofmap.SecurityVisibilityContext {
	context := proofmap.SecurityVisibilityContext{
		Summary:          agginventory.SecurityVisibilitySummary{},
		StatusByInstance: map[string]string{},
	}
	if inventory == nil {
		return context
	}
	context.Summary = inventory.SecurityVisibility
	for _, agent := range inventory.Agents {
		instanceID := strings.TrimSpace(agent.AgentInstanceID)
		if instanceID == "" {
			continue
		}
		context.StatusByInstance[instanceID] = strings.TrimSpace(agent.SecurityVisibilityStatus)
	}
	return context
}

func EmitIdentityTransition(statePath string, transition lifecycle.Transition, eventType string) error {
	chainPath := ChainPath(statePath)
	chain, err := LoadChain(chainPath)
	if err != nil {
		return err
	}
	key, err := loadSigningKey(statePath)
	if err != nil {
		return err
	}
	mapped := proofmap.MapTransition(transition, eventType)
	if _, err := appendSignedRecord(chain, key, mapped); err != nil {
		return err
	}
	if err := signChain(chain, key); err != nil {
		return err
	}
	if err := SaveChain(chainPath, chain); err != nil {
		return err
	}
	return saveChainAttestation(chainPath, len(chain.Records), chain.HeadHash, key)
}

func LoadVerifierKey(statePath string) (proof.PublicKey, error) {
	return loadPublicKey(statePath)
}

func LoadSigningMaterial(statePath string) (proof.SigningKey, error) {
	return loadSigningKey(statePath)
}

func appendSignedRecord(chain *proof.Chain, key proof.SigningKey, mapped proofmap.MappedRecord) (*proof.Record, error) {
	if chain == nil {
		return nil, fmt.Errorf("proof chain is required")
	}
	controls := proof.Controls{PermissionsEnforced: true}
	if strings.TrimSpace(mapped.ApprovedScope) != "" {
		controls.ApprovedScope = strings.TrimSpace(mapped.ApprovedScope)
		withinScope := true
		controls.WithinScope = &withinScope
	}
	relationship := relationshipForRecord(chain, mapped.Relationship)
	record, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     mapped.Timestamp.UTC(),
		Source:        "wrkr",
		SourceProduct: "wrkr",
		AgentID:       strings.TrimSpace(mapped.AgentID),
		Type:          mapped.RecordType,
		Event:         mapped.Event,
		Metadata:      mapped.Metadata,
		Relationship:  relationship,
		Controls:      controls,
	})
	if err != nil {
		return nil, fmt.Errorf("build proof record: %w", err)
	}
	record.Integrity.PreviousRecordHash = chain.HeadHash
	hash, err := proof.ComputeRecordHash(record)
	if err != nil {
		return nil, fmt.Errorf("compute proof hash: %w", err)
	}
	record.Integrity.RecordHash = hash
	if _, err := proof.Sign(record, key); err != nil {
		return nil, fmt.Errorf("sign proof record: %w", err)
	}
	if err := proof.AppendToChain(chain, record); err != nil {
		return nil, fmt.Errorf("append proof record: %w", err)
	}
	return record, nil
}

func signChain(chain *proof.Chain, key proof.SigningKey) error {
	if chain == nil {
		return fmt.Errorf("proof chain is required")
	}
	chain.Signatures = nil
	if _, err := proof.SignChain(chain, key); err != nil {
		return fmt.Errorf("sign proof chain: %w", err)
	}
	return nil
}

func relationshipForRecord(chain *proof.Chain, relationship *proof.Relationship) *proof.Relationship {
	if relationship == nil {
		relationship = &proof.Relationship{}
	}
	if parentRecordID := previousRecordID(chain); parentRecordID != "" {
		if relationship.ParentRef == nil {
			relationship.ParentRef = &proof.RelationshipRef{Kind: "evidence", ID: parentRecordID}
		}
		if strings.TrimSpace(relationship.ParentRecordID) == "" {
			relationship.ParentRecordID = parentRecordID
		}
	}
	relationship.RelatedRecordIDs = uniqueSortedStrings(relationship.RelatedRecordIDs)
	entityIDs := make([]string, 0, len(relationship.EntityRefs))
	for _, ref := range relationship.EntityRefs {
		entityIDs = append(entityIDs, strings.TrimSpace(ref.ID))
	}
	relationship.RelatedEntityIDs = uniqueSortedStrings(append(relationship.RelatedEntityIDs, entityIDs...))
	if relationshipIsEmpty(*relationship) {
		return nil
	}
	return relationship
}

func linkMappedRecordToFindings(mapped *proofmap.MappedRecord, findingRecordIDs map[string]string) {
	if mapped == nil || len(findingRecordIDs) == 0 {
		return
	}
	related := []string{}
	if canonical := metadataString(mapped.Metadata, "canonical_finding"); canonical != "" {
		lookupKey := canonicalFindingLookupKey(canonical)
		if recordID := strings.TrimSpace(findingRecordIDs[lookupKey]); recordID != "" {
			related = append(related, recordID)
		}
	}
	for _, key := range metadataStringSlice(mapped.Metadata, "attack_path_source") {
		lookupKey := canonicalFindingLookupKey(key)
		if recordID := strings.TrimSpace(findingRecordIDs[lookupKey]); recordID != "" {
			related = append(related, recordID)
		}
	}
	if len(related) == 0 {
		return
	}
	if mapped.Relationship == nil {
		mapped.Relationship = &proof.Relationship{}
	}
	mapped.Relationship.RelatedRecordIDs = uniqueSortedStrings(append(mapped.Relationship.RelatedRecordIDs, related...))
}

func metadataString(metadata map[string]any, key string) string {
	value, ok := metadata[key]
	if !ok {
		return ""
	}
	typed, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(typed)
}

func metadataStringSlice(metadata map[string]any, key string) []string {
	value, ok := metadata[key]
	if !ok {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return uniqueSortedStrings(typed)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			asString, ok := item.(string)
			if !ok {
				continue
			}
			values = append(values, asString)
		}
		return uniqueSortedStrings(values)
	default:
		return nil
	}
}

func previousRecordID(chain *proof.Chain) string {
	if chain == nil || len(chain.Records) == 0 {
		return ""
	}
	return strings.TrimSpace(chain.Records[len(chain.Records)-1].RecordID)
}

func relationshipIsEmpty(relationship proof.Relationship) bool {
	return relationship.ParentRef == nil &&
		len(relationship.EntityRefs) == 0 &&
		relationship.PolicyRef == nil &&
		len(relationship.AgentChain) == 0 &&
		len(relationship.Edges) == 0 &&
		strings.TrimSpace(relationship.ParentRecordID) == "" &&
		len(relationship.RelatedRecordIDs) == 0 &&
		len(relationship.RelatedEntityIDs) == 0 &&
		len(relationship.AgentLineage) == 0
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func canonicalFindingLookupKey(key string) string {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "skill_policy_conflict:") {
		parts := strings.SplitN(trimmed, ":", 3)
		if len(parts) != 3 {
			return trimmed
		}
		org := normalizeCanonicalOrgPart(parts[1])
		repo := strings.TrimSpace(parts[2])
		return strings.Join([]string{"skill_policy_conflict", org, repo}, ":")
	}
	parts := strings.Split(trimmed, "|")
	if len(parts) != 6 {
		return trimmed
	}
	parts[0] = strings.TrimSpace(parts[0])
	parts[1] = strings.TrimSpace(parts[1])
	parts[2] = strings.TrimSpace(parts[2])
	parts[3] = strings.TrimSpace(parts[3])
	parts[4] = strings.TrimSpace(parts[4])
	parts[5] = normalizeCanonicalOrgPart(parts[5])
	return strings.Join(parts, "|")
}

func normalizeCanonicalOrgPart(org string) string {
	trimmed := strings.TrimSpace(org)
	if trimmed == "" {
		return "local"
	}
	return trimmed
}
