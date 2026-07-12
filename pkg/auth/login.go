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

// loginView is what the card renders. The sign-in methods compose: Local puts up
// the password form, OIDC the provider button, and both together stack them with
// a divider. Exactly one of them is always true — an Authenticator with neither
// serves no login page at all.
type loginView struct {
	Next     string
	Error    string // fixed copy from errMessage; empty for none
	Note     string // neutral notice, e.g. after signing out
	Local    bool   // show the username/password form
	OIDC     bool   // show the provider button
	Provider string // display name for that button
	StartURL string // begins the authorization-code flow
}

func (lt *loginTemplate) render(w http.ResponseWriter, v loginView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// html/template escapes every field: Next lands in a value="" attribute and
	// StartURL in an href, both of which it knows how to sanitize.
	_ = lt.t.Execute(w, v)
}
