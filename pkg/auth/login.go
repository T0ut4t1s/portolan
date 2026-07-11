// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package auth

import (
	_ "embed"
	"html/template"
	"net/http"
)

//go:embed login.html
var loginHTML string

type loginTemplate struct{ t *template.Template }

func loginTmpl() *loginTemplate {
	return &loginTemplate{t: template.Must(template.New("login").Parse(loginHTML))}
}

func (lt *loginTemplate) render(w http.ResponseWriter, next string, showErr bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// html/template auto-escapes Next (it lands in a value="" attribute).
	_ = lt.t.Execute(w, map[string]any{"Next": next, "Error": showErr})
}
