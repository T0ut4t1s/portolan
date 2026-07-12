// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package render

import (
	"bytes"
	"testing"

	"github.com/T0ut4t1s/portolan/pkg/graph"
)

func TestHTMLSubstitutesBothTokens(t *testing.T) {
	for _, tc := range []struct {
		name string
		ui   UI
		want string
	}{
		{"served with auth", UI{Auth: true}, `{"auth":true}`},
		{"standalone file", UI{}, `{"auth":false}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := HTML(&graph.Graph{}, tc.ui)
			if err != nil {
				t.Fatalf("HTML: %v", err)
			}
			if !bytes.Contains(out, []byte("const UI = "+tc.want)) {
				t.Errorf("UI not injected as %s", tc.want)
			}
			for _, tok := range []string{dataToken, uiToken} {
				if bytes.Contains(out, []byte(tok)) {
					t.Errorf("token %s survived substitution", tok)
				}
			}
		})
	}
}

// A workload named after a token must not be mistaken for the token. The graph
// is substituted last precisely so cluster-derived names cannot shadow it.
func TestHTMLTokenInGraphDataIsInert(t *testing.T) {
	g := &graph.Graph{Namespaces: []graph.Namespace{{Name: uiToken}}}
	out, err := HTML(g, UI{Auth: true})
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if !bytes.Contains(out, []byte(`const UI = {"auth":true}`)) {
		t.Error("UI token was shadowed by a workload name in the graph")
	}
}
