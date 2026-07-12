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

// loginView is what the card renders. In oidc mode the password fields give way
// to a single button: the card stays because sign-out has to land somewhere
// that does not immediately bounce back through a still-live SSO session, and
// because a rejection needs somewhere to be explained.
type loginView struct {
	Next     string
	Error    string // fixed copy from errMessage; empty for none
	Note     string // neutral notice, e.g. after signing out
	OIDC     bool
	Provider string // display name for the sign-in button
	StartURL string // begins the authorization-code flow
}

func (lt *loginTemplate) render(w http.ResponseWriter, v loginView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// html/template escapes every field: Next lands in a value="" attribute and
	// StartURL in an href, both of which it knows how to sanitize.
	_ = lt.t.Execute(w, v)
}
