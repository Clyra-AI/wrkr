package ingest

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

const externalControlEvidenceSchemaURL = "https://wrkr.dev/schemas/v1/evidence/external-control-evidence.schema.json"

//go:embed schema/external-control-evidence.schema.json
var externalControlEvidenceSchemaJSON []byte

var (
	externalControlEvidenceSchemaOnce sync.Once
	externalControlEvidenceSchema     *jsonschema.Schema
	externalControlEvidenceSchemaErr  error
)

func ValidateExternalControlEvidenceJSON(payload []byte) error {
	var doc any
	if err := json.Unmarshal(payload, &doc); err != nil {
		return err
	}
	schema, err := compiledExternalControlEvidenceSchema()
	if err != nil {
		return err
	}
	return schema.Validate(doc)
}

func compiledExternalControlEvidenceSchema() (*jsonschema.Schema, error) {
	externalControlEvidenceSchemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		externalControlEvidenceSchemaErr = compiler.AddResource(externalControlEvidenceSchemaURL, bytes.NewReader(externalControlEvidenceSchemaJSON))
		if externalControlEvidenceSchemaErr != nil {
			return
		}
		externalControlEvidenceSchema, externalControlEvidenceSchemaErr = compiler.Compile(externalControlEvidenceSchemaURL)
	})
	return externalControlEvidenceSchema, externalControlEvidenceSchemaErr
}
