package rego

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/open-policy-agent/opa/rego"
	"github.com/pkg/errors"
)

func ValidateJSON(jsonBody []byte, entrypoints []string) error {
	ctx := context.Background()

	r := rego.New(
		rego.Query("data.signature.allow"), // hardcoded, ? data.cosign.allow→
		rego.Load(entrypoints, nil))

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return err
	}

	var input interface{}
	dec := json.NewDecoder(bytes.NewBuffer(jsonBody))
	dec.UseNumber()
	if err := dec.Decode(&input); err != nil {
		return err
	}

	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return err
	}

	if rs.Allowed() {
		return nil
	}
	return errors.New("rego validation failed")
}
