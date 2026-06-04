package proofcompat

import (
	"fmt"
	"strings"
	"sync"

	proof "github.com/Clyra-AI/proof"
)

type wrkrRecordType struct {
	name   string
	schema string
}

var (
	ensureOnce sync.Once
	ensureErr  error
)

var wrkrRecordTypes = []wrkrRecordType{
	{
		name: "lifecycle_transition",
		schema: `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["record_type", "event"],
  "properties": {
    "record_type": {"const": "lifecycle_transition"},
    "event": {
      "type": "object",
      "required": ["event_type", "previous_state", "new_state", "trigger"],
      "properties": {
        "event_type": {"const": "lifecycle_transition"},
        "previous_state": {"type": "string"},
        "new_state": {"type": "string"},
        "trigger": {"type": "string"},
        "diff": {"type": "object"}
      },
      "additionalProperties": true
    }
  },
  "additionalProperties": true
}`,
	},
	{
		name: "evidence",
		schema: `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["record_type", "event"],
  "properties": {
    "record_type": {"const": "evidence"},
    "event": {
      "type": "object",
      "required": ["event_type"],
      "properties": {
        "event_type": {
          "enum": [
            "owner_assigned",
            "evidence_attached",
            "least_privilege_verified",
            "rotation_evidence_attached",
            "deployment_gate_present",
            "production_access_classified",
            "proof_artifact_generated",
            "review_cadence_set"
          ]
        }
      },
      "additionalProperties": true
    }
  },
  "additionalProperties": true
}`,
	},
}

func EnsureWrkrRecordTypes() error {
	ensureOnce.Do(func() {
		for _, recordType := range wrkrRecordTypes {
			if hasRecordType(recordType.name) {
				continue
			}
			if err := proof.RegisterCustomType(recordType.name, []byte(recordType.schema)); err != nil {
				ensureErr = fmt.Errorf("register wrkr proof record type %s: %w", recordType.name, err)
				return
			}
		}
	})
	return ensureErr
}

func hasRecordType(name string) bool {
	name = strings.TrimSpace(name)
	for _, recordType := range proof.ListRecordTypes() {
		if strings.TrimSpace(recordType.Name) == name {
			return true
		}
	}
	return false
}
