// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package whatif

import (
	"bytes"
	"encoding/json"
	"fmt"

	sigsyaml "sigs.k8s.io/yaml"

	"github.com/T0ut4t1s/portolan/pkg/snapshot"
)

// jsonUnmarshal is aliased so collectRulePorts stays testable without an
// import cycle on this file's imports.
var jsonUnmarshal = json.Unmarshal

// draftDoc is the shape shared by every supported draft manifest.
type draftDoc struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec  json.RawMessage   `json:"spec"`
	Specs []json.RawMessage `json:"specs"`
}

// ParseDrafts parses one YAML (or JSON) file that may contain multiple
// documents, each a CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy,
// or NetworkPolicy manifest, into snapshot.Policy values — the same shape
// the collector produces, so the engines treat drafts and live policies
// identically.
func ParseDrafts(name string, data []byte) ([]snapshot.Policy, error) {
	var out []snapshot.Policy
	for i, doc := range bytes.Split(data, []byte("\n---")) {
		doc = bytes.TrimSpace(doc)
		doc = bytes.TrimPrefix(doc, []byte("---"))
		if len(doc) == 0 {
			continue
		}
		jsonDoc, err := sigsyaml.YAMLToJSON(doc)
		if err != nil {
			return nil, fmt.Errorf("%s document %d: %w", name, i+1, err)
		}
		var d draftDoc
		if err := json.Unmarshal(jsonDoc, &d); err != nil {
			return nil, fmt.Errorf("%s document %d: %w", name, i+1, err)
		}

		var kind snapshot.PolicyKind
		switch d.Kind {
		case "CiliumNetworkPolicy":
			kind = snapshot.KindCNP
		case "CiliumClusterwideNetworkPolicy":
			kind = snapshot.KindCCNP
		case "NetworkPolicy":
			kind = snapshot.KindNetPol
		case "":
			return nil, fmt.Errorf("%s document %d: missing kind", name, i+1)
		default:
			return nil, fmt.Errorf("%s document %d: unsupported kind %s", name, i+1, d.Kind)
		}
		if d.Metadata.Name == "" {
			return nil, fmt.Errorf("%s document %d: missing metadata.name", name, i+1)
		}
		if kind != snapshot.KindCCNP && d.Metadata.Namespace == "" {
			return nil, fmt.Errorf("%s document %d (%s/%s): missing metadata.namespace",
				name, i+1, d.Kind, d.Metadata.Name)
		}
		if kind == snapshot.KindCCNP && d.Metadata.Namespace != "" {
			return nil, fmt.Errorf("%s document %d: CCNP %s must not carry a namespace",
				name, i+1, d.Metadata.Name)
		}

		// Same contract as the collector: .spec first, then each element of
		// .specs — both enforced when both are present.
		var rules []json.RawMessage
		if len(d.Spec) > 0 && !bytes.Equal(d.Spec, []byte("null")) {
			rules = append(rules, d.Spec)
		}
		rules = append(rules, d.Specs...)
		if len(rules) == 0 {
			return nil, fmt.Errorf("%s document %d (%s/%s): neither .spec nor .specs",
				name, i+1, d.Kind, d.Metadata.Name)
		}

		out = append(out, snapshot.Policy{
			Kind:       kind,
			Namespace:  d.Metadata.Namespace,
			Name:       d.Metadata.Name,
			APIVersion: d.APIVersion,
			Rules:      rules,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no policy documents found", name)
	}
	return out, nil
}
