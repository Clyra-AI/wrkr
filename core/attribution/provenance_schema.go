package attribution

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

const provenanceSchemaURL = "https://wrkr.dev/schemas/v1/provenance/pr-mr-provenance.schema.json"

//go:embed schema/pr-mr-provenance.schema.json
var provenanceSchemaJSON []byte

var (
	provenanceSchemaOnce sync.Once
	provenanceSchema     *jsonschema.Schema
	provenanceSchemaErr  error
)

func ValidateProvenanceJSON(payload []byte) error {
	var doc any
	if err := json.Unmarshal(payload, &doc); err != nil {
		return err
	}
	schema, err := compiledProvenanceSchema()
	if err != nil {
		return err
	}
	return schema.Validate(doc)
}

func compiledProvenanceSchema() (*jsonschema.Schema, error) {
	provenanceSchemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		provenanceSchemaErr = compiler.AddResource(provenanceSchemaURL, bytes.NewReader(provenanceSchemaJSON))
		if provenanceSchemaErr != nil {
			return
		}
		provenanceSchema, provenanceSchemaErr = compiler.Compile(provenanceSchemaURL)
	})
	return provenanceSchema, provenanceSchemaErr
}
