package ingest

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

const runtimeSessionSchemaURL = "https://wrkr.dev/schemas/v1/evidence/runtime-sessions.schema.json"

//go:embed schema/runtime-sessions.schema.json
var runtimeSessionSchemaJSON []byte

var (
	runtimeSessionSchemaOnce sync.Once
	runtimeSessionSchema     *jsonschema.Schema
	runtimeSessionSchemaErr  error
)

func ValidateSessionJSON(payload []byte) error {
	var doc any
	if err := json.Unmarshal(payload, &doc); err != nil {
		return err
	}
	schema, err := compiledRuntimeSessionSchema()
	if err != nil {
		return err
	}
	return schema.Validate(doc)
}

func compiledRuntimeSessionSchema() (*jsonschema.Schema, error) {
	runtimeSessionSchemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		runtimeSessionSchemaErr = compiler.AddResource(runtimeSessionSchemaURL, bytes.NewReader(runtimeSessionSchemaJSON))
		if runtimeSessionSchemaErr != nil {
			return
		}
		runtimeSessionSchema, runtimeSessionSchemaErr = compiler.Compile(runtimeSessionSchemaURL)
	})
	return runtimeSessionSchema, runtimeSessionSchemaErr
}
