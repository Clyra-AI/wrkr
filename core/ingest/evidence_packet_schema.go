package ingest

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

const evidencePacketSchemaURL = "https://wrkr.dev/schemas/v1/evidence/agentic-evidence-packets.schema.json"

//go:embed schema/agentic-evidence-packets.schema.json
var evidencePacketSchemaJSON []byte

var (
	evidencePacketSchemaOnce sync.Once
	evidencePacketSchema     *jsonschema.Schema
	evidencePacketSchemaErr  error
)

func ValidateEvidencePacketJSON(payload []byte) error {
	var doc any
	if err := json.Unmarshal(payload, &doc); err != nil {
		return err
	}
	schema, err := compiledEvidencePacketSchema()
	if err != nil {
		return err
	}
	return schema.Validate(doc)
}

func compiledEvidencePacketSchema() (*jsonschema.Schema, error) {
	evidencePacketSchemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		evidencePacketSchemaErr = compiler.AddResource(evidencePacketSchemaURL, bytes.NewReader(evidencePacketSchemaJSON))
		if evidencePacketSchemaErr != nil {
			return
		}
		evidencePacketSchema, evidencePacketSchemaErr = compiler.Compile(evidencePacketSchemaURL)
	})
	return evidencePacketSchema, evidencePacketSchemaErr
}
