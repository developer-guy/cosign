//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/cue"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

// VerifyAttestationCommand verifies a signature on a supplied container image
// nolint
type VerifyAttestationCommand struct {
	options.RegistryOptions
	CheckClaims   bool
	KeyRef        string
	Sk            bool
	Slot          string
	Output        string
	FulcioURL     string
	RekorURL      string
	PredicateType string
	Policies      []string
}

// DSSE messages contain the signature and payload in one object, but our interface expects a signature and payload
// This means we need to use one field and ignore the other. The DSSE verifier upstream uses the signature field and ignores
// The message field, but we want the reverse here.
type reverseDSSEVerifier struct {
	signature.Verifier
}

func (w *reverseDSSEVerifier) VerifySignature(s io.Reader, m io.Reader, opts ...signature.VerifyOption) error {
	return w.Verifier.VerifySignature(m, nil, opts...)
}

// Exec runs the verification command
func (c *VerifyAttestationCommand) Exec(ctx context.Context, images []string) (err error) {
	if len(images) == 0 {
		return flag.ErrHelp
	}

	if !options.OneOf(c.KeyRef, c.Sk) && !options.EnableExperimental() {
		return &options.KeyParseError{}
	}

	ociremoteOpts, err := c.ClientOpts(ctx)
	if err != nil {
		return errors.Wrap(err, "constructing client options")
	}

	co := &cosign.CheckOpts{
		RegistryClientOpts: ociremoteOpts,
	}
	if c.CheckClaims {
		co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	}
	if options.EnableExperimental() {
		co.RekorURL = c.RekorURL
		co.RootCerts = fulcio.GetRoots()
	}
	keyRef := c.KeyRef

	// Keys are optional!
	var pubKey signature.Verifier
	if keyRef != "" {
		pubKey, err = sigs.PublicKeyFromKeyRef(ctx, keyRef)
		if err != nil {
			return errors.Wrap(err, "loading public key")
		}
	} else if c.Sk {
		sk, err := pivkey.GetKeyWithSlot(c.Slot)
		if err != nil {
			return errors.Wrap(err, "opening piv token")
		}
		defer sk.Close()
		pubKey, err = sk.Verifier()
		if err != nil {
			return errors.Wrap(err, "initializing piv token verifier")
		}
	}

	co.SigVerifier = &reverseDSSEVerifier{
		Verifier: dsse.WrapVerifier(pubKey),
	}

	for _, imageRef := range images {
		ref, err := name.ParseReference(imageRef)
		if err != nil {
			return err
		}

		verified, bundleVerified, err := cosign.VerifyAttestations(ctx, ref, co)
		if err != nil {
			return err
		}

		for _, vp := range verified {
			payload, err := vp.Payload()
			if err != nil {
				return err
			}

			var payloadData map[string]interface{}
			if err := json.Unmarshal(payload, &payloadData); err != nil {
				return err
			}

			if options.PredicateTypeMap[c.PredicateType] != payloadData["payloadType"] {
				continue
			}

			decodedPayload, err := base64.StdEncoding.DecodeString(payloadData["payload"].(string))
			if err != nil {
				return err
			}

			switch c.PredicateType {
			case options.PredicateCustom:
				var cosignStatement in_toto.Statement
				if err := json.Unmarshal(decodedPayload, &cosignStatement); err != nil {
					return err
				}
				payload, _ := json.Marshal(cosignStatement.Predicate)
				if err := cue.ValidateJSON(payload, c.Policies); err != nil {
					return err
				}
			case options.PredicateLink:
				var linkStatement in_toto.LinkStatement
				if err := json.Unmarshal(decodedPayload, &linkStatement); err != nil {
					return err
				}
				payload, _ := json.Marshal(linkStatement.Predicate)
				if err := cue.ValidateJSON(payload, c.Policies); err != nil {
					return err
				}
			case options.PredicateSLSA:
				var slsaProvenanceStatement in_toto.ProvenanceStatement
				if err := json.Unmarshal(decodedPayload, &slsaProvenanceStatement); err != nil {
					return err
				}
				payload, _ := json.Marshal(slsaProvenanceStatement.Predicate)
				if err := cue.ValidateJSON(payload, c.Policies); err != nil {
					return err
				}
			case options.PredicateSPDX:
				var spdxStatement in_toto.SPDXStatement
				if err := json.Unmarshal(decodedPayload, &spdxStatement); err != nil {
					return err
				}
				payload, _ := json.Marshal(spdxStatement.Predicate)
				if err := cue.ValidateJSON(payload, c.Policies); err != nil {
					return err
				}
			default:
				continue
			}
		}

		// TODO: add CUE validation report to `PrintVerificationHeader`.
		PrintVerificationHeader(imageRef, co, bundleVerified)
		// The attestations are always JSON, so use the raw "text" mode for outputting them instead of conversion
		PrintVerification(imageRef, verified, "text")
	}

	return nil
}
