// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

// Package render turns a policy graph into a single self-contained HTML
// file: no external assets, no network access needed to view it. The UI
// template is embedded at build time; the graph is injected as JSON.
package render

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/T0ut4t1s/portolan/pkg/graph"
)

//go:embed map.html
var template []byte

const (
	dataToken = "__PORTOLAN_DATA__"
	uiToken   = "__PORTOLAN_UI__"
)

// UI carries the serving context into the page. The same rendered bytes are
// handed to every viewer and to the offline `render` command, so this holds
// only facts about the deployment, never anything about the current user.
type UI struct {
	// Auth reveals the sign-out control. False for standalone files, where
	// there is no server to sign out of.
	Auth bool `json:"auth"`
}

// HTML renders the graph into the embedded template.
func HTML(g *graph.Graph, ui UI) ([]byte, error) {
	// json.Marshal escapes <, >, and & by default, so neither payload can
	// break out of its <script> element.
	data, err := json.Marshal(g)
	if err != nil {
		return nil, fmt.Errorf("encoding graph: %w", err)
	}
	uiJSON, err := json.Marshal(ui)
	if err != nil {
		return nil, fmt.Errorf("encoding ui: %w", err)
	}
	for _, token := range []string{uiToken, dataToken} {
		if !bytes.Contains(template, []byte(token)) {
			return nil, fmt.Errorf("embedded template is missing the %s token", token)
		}
	}
	// Substitute the UI token before the graph: cluster-derived names land in
	// the graph JSON, and a workload named after a token would otherwise be
	// mistaken for the token itself.
	out := bytes.Replace(template, []byte(uiToken), uiJSON, 1)
	return bytes.Replace(out, []byte(dataToken), data, 1), nil
}
