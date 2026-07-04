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

const dataToken = "__PORTOLAN_DATA__"

// HTML renders the graph into the embedded template.
func HTML(g *graph.Graph) ([]byte, error) {
	// json.Marshal escapes <, >, and & by default, so the payload cannot
	// break out of its <script> element.
	data, err := json.Marshal(g)
	if err != nil {
		return nil, fmt.Errorf("encoding graph: %w", err)
	}
	if !bytes.Contains(template, []byte(dataToken)) {
		return nil, fmt.Errorf("embedded template is missing the %s token", dataToken)
	}
	return bytes.Replace(template, []byte(dataToken), data, 1), nil
}
