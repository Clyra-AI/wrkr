package proofemit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/model"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/proofmap"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/score"
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
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir proof chain dir: %w", err)
	}
	payload, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal proof chain: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write proof chain: %w", err)
	}
	return nil
}

func EmitScan(statePath string, now time.Time, findings []model.Finding, report risk.Report, profile profileeval.Result, posture score.Result, transitions []lifecycle.Transition) (Summary, error) {
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
	mappedFindings := proofmap.MapFindings(findings, &profile, now)
	for _, mapped := range mappedFindings {
		if err := appendSignedRecord(chain, key, mapped); err != nil {
			return Summary{}, err
		}
		summary.Findings++
		summary.Total++
	}

	mappedRisk := proofmap.MapRisk(report, posture, profile, now)
	for _, mapped := range mappedRisk {
		if err := appendSignedRecord(chain, key, mapped); err != nil {
			return Summary{}, err
		}
		summary.Risk++
		summary.Total++
	}

	for _, transition := range transitions {
		mapped := proofmap.MapTransition(transition, "lifecycle_transition")
		if err := appendSignedRecord(chain, key, mapped); err != nil {
			return Summary{}, err
		}
		summary.Transitions++
		summary.Total++
	}

	if err := SaveChain(chainPath, chain); err != nil {
		return Summary{}, err
	}
	return summary, nil
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
	if err := appendSignedRecord(chain, key, mapped); err != nil {
		return err
	}
	return SaveChain(chainPath, chain)
}

func LoadVerifierKey(statePath string) (proof.PublicKey, error) {
	return loadPublicKey(statePath)
}

func LoadSigningMaterial(statePath string) (proof.SigningKey, error) {
	return loadSigningKey(statePath)
}

func appendSignedRecord(chain *proof.Chain, key proof.SigningKey, mapped proofmap.MappedRecord) error {
	if chain == nil {
		return fmt.Errorf("proof chain is required")
	}
	controls := proof.Controls{PermissionsEnforced: true}
	if strings.TrimSpace(mapped.ApprovedScope) != "" {
		controls.ApprovedScope = strings.TrimSpace(mapped.ApprovedScope)
		withinScope := true
		controls.WithinScope = &withinScope
	}
	record, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     mapped.Timestamp.UTC(),
		Source:        "wrkr",
		SourceProduct: "wrkr",
		AgentID:       strings.TrimSpace(mapped.AgentID),
		Type:          mapped.RecordType,
		Event:         mapped.Event,
		Metadata:      mapped.Metadata,
		Controls:      controls,
	})
	if err != nil {
		return fmt.Errorf("build proof record: %w", err)
	}
	record.Integrity.PreviousRecordHash = chain.HeadHash
	hash, err := proof.ComputeRecordHash(record)
	if err != nil {
		return fmt.Errorf("compute proof hash: %w", err)
	}
	record.Integrity.RecordHash = hash
	if _, err := proof.Sign(record, key); err != nil {
		return fmt.Errorf("sign proof record: %w", err)
	}
	if err := proof.AppendToChain(chain, record); err != nil {
		return fmt.Errorf("append proof record: %w", err)
	}
	return nil
}
