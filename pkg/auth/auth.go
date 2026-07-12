// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

// Package auth adds optional login to Portolan's serve mode. It is opt-in
// (mode "none" is the default and a no-op) and self-contained: no database and
// no external identity provider are required for local mode.
//
// Sessions are stateless — an AES-256-GCM authenticated-encryption token in an
// HttpOnly/Secure/SameSite=Lax cookie, carrying only a subject and an expiry.
// The server keeps no session state, so it scales to any replica count on a
// single shared key; the tradeoff is that a token cannot be revoked before it
// expires (short TTL + logout cover the practical need). This is appropriate
// for a read-only dashboard; anything needing instant revocation would want
// server-side sessions, and a datastore Portolan deliberately does not carry.
package auth

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Mode selects the authentication scheme. Both modes that authenticate share
// this package's session layer — they differ only in how a session is minted.
type Mode string

const (
	ModeNone  Mode = "none"  // no auth (default) — for CLI use or behind a trusted proxy
	ModeLocal Mode = "local" // built-in username/password, bcrypt-hashed
	ModeOIDC  Mode = "oidc"  // authorization-code flow with PKCE against an OIDC provider
)

const (
	cookieName    = "portolan_session"
	sessionKeyLen = 32 // AES-256
)

// Cookie purposes are bound into the AEAD as additional authenticated data, so
// a token sealed for one purpose cannot be opened as the other. The session
// cookie and the OIDC login transaction share a key but not a namespace.
const (
	purposeSession = "portolan/session/v1"
	purposeTx      = "portolan/oidc-tx/v1"
)

// Config is the resolved auth configuration for serve mode.
type Config struct {
	// Modes are the sign-in methods offered, and they compose: [oidc, local]
	// puts both on one card. Empty (or [none]) means no auth at all. The methods
	// differ only in how a session is earned; the session itself is the same.
	//
	// Running local beside oidc is the break-glass pattern every mature admin
	// tool ships (Grafana, ArgoCD, Vault): the emergency way in must not route
	// through the system that may itself be broken. It is also a permanently
	// attached weaker credential that bypasses the OIDC allowlist — so it wants
	// exactly one account, a long random password, and no daily use.
	Modes []Mode
	// SessionKey must be exactly 32 bytes (AES-256) when any mode authenticates.
	SessionKey []byte
	SessionTTL time.Duration
	// Users maps username -> bcrypt hash (local mode).
	Users map[string]string
	// OIDC configures the oidc mode.
	OIDC *OIDCConfig
	// Insecure drops the cookie Secure flag — for plain-HTTP local testing
	// only. In production the browser⇔proxy leg is HTTPS, so leave this false
	// even though the pod itself is reached over HTTP behind TLS termination.
	Insecure bool
}

// Authenticator enforces a Config: it gates a handler and serves the login
// endpoints. With no authenticating mode it passes everything through.
type Authenticator struct {
	cfg       Config
	aead      cipher.AEAD
	local     bool        // username/password enabled
	dummyHash []byte      // constant-time decoy for unknown users (defeats enumeration timing)
	oidc      *oidcClient // nil unless oidc is enabled
	tmpl      *loginTemplate
}

// has reports whether m is among the configured modes.
func (c Config) has(m Mode) bool { return slices.Contains(c.Modes, m) }

// New validates cfg and builds an Authenticator. In mode "none" it returns a
// pass-through. Otherwise it fails closed on any misconfiguration — a
// half-configured auth is worse than none.
//
// In mode oidc this reaches the provider for discovery, so it can block for as
// long as the discovery retry budget (see newOIDCClient); ctx also governs the
// background refresh of the provider's signing keys, so pass one that lives as
// long as the server.
func New(ctx context.Context, cfg Config) (*Authenticator, error) {
	// Normalize: no modes, or an explicit none, means the map is served open.
	// `none` is not a mode you can combine with a real one — that would be a
	// config that reads as "auth, sometimes".
	cfg.Modes = slices.DeleteFunc(cfg.Modes, func(m Mode) bool { return m == "" })
	if len(cfg.Modes) == 0 || slices.Contains(cfg.Modes, ModeNone) {
		if len(cfg.Modes) > 1 {
			return nil, fmt.Errorf("auth: mode none cannot be combined with %v", cfg.Modes)
		}
		cfg.Modes = nil
		return &Authenticator{cfg: cfg}, nil
	}
	for _, m := range cfg.Modes {
		if m != ModeLocal && m != ModeOIDC {
			return nil, fmt.Errorf("auth: unknown mode %q", m)
		}
	}

	if len(cfg.SessionKey) != sessionKeyLen {
		return nil, fmt.Errorf("auth: session key must be %d bytes, got %d", sessionKeyLen, len(cfg.SessionKey))
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	block, err := aes.NewCipher(cfg.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	a := &Authenticator{cfg: cfg, aead: aead, tmpl: loginTmpl()}

	// Every enabled mode must be wholly valid. A half-configured auth fails
	// closed here, before the listener binds, rather than at someone's login.
	if cfg.has(ModeLocal) {
		if len(cfg.Users) == 0 {
			return nil, errors.New("auth: mode local requires at least one user")
		}
		// A real (unmatchable) hash so a login attempt for an unknown user still
		// pays the bcrypt cost — otherwise response timing leaks which users exist.
		dummy, err := bcrypt.GenerateFromPassword([]byte("portolan-decoy"), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("auth: %w", err)
		}
		a.local, a.dummyHash = true, dummy
	}
	if cfg.has(ModeOIDC) {
		if cfg.OIDC == nil {
			return nil, errors.New("auth: mode oidc requires OIDC configuration")
		}
		// Auto-redirect skips the login card entirely. With local also enabled
		// that would hide the password form — leaving no way to reach it. That is
		// a contradiction, not a preference, so say so instead of quietly picking
		// a winner.
		if cfg.OIDC.AutoRedirect && a.local {
			return nil, errors.New("auth: oidc auto-redirect cannot be used alongside local login — it would hide the password form")
		}
		oc, err := newOIDCClient(ctx, cfg.OIDC)
		if err != nil {
			return nil, err
		}
		a.oidc = oc
	}
	return a, nil
}

// Enabled reports whether any auth mode is active.
func (a *Authenticator) Enabled() bool { return len(a.cfg.Modes) > 0 }

// Modes lists the active sign-in methods, for logging.
func (a *Authenticator) Modes() []Mode { return a.cfg.Modes }

// ---- stateless session token ----

type session struct {
	Sub string `json:"s"`
	Exp int64  `json:"e"` // unix seconds
}

// seal encrypts v into a URL-safe token: nonce ‖ AES-GCM(json(v)). The purpose
// is authenticated but not carried, so a token minted for one purpose fails to
// open under another.
func (a *Authenticator) seal(purpose string, v any) (string, error) {
	pt, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, a.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := a.aead.Seal(nonce, nonce, pt, []byte(purpose))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// open authenticates a token against purpose and unmarshals it into v.
func (a *Authenticator) open(purpose, tok string, v any) bool {
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(raw) < a.aead.NonceSize() {
		return false
	}
	nonce, ct := raw[:a.aead.NonceSize()], raw[a.aead.NonceSize():]
	pt, err := a.aead.Open(nil, nonce, ct, []byte(purpose))
	if err != nil {
		return false
	}
	return json.Unmarshal(pt, v) == nil
}

// encode seals a session cookie.
func (a *Authenticator) encode(s session) (string, error) {
	return a.seal(purposeSession, s)
}

// decode verifies and opens a session token, returning the subject if it is
// authentic and unexpired.
func (a *Authenticator) decode(tok string) (string, bool) {
	var s session
	if !a.open(purposeSession, tok, &s) {
		return "", false
	}
	if s.Sub == "" || time.Now().Unix() >= s.Exp {
		return "", false
	}
	return s.Sub, true
}

func (a *Authenticator) setCookie(w http.ResponseWriter, tok string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: tok, Path: "/", Expires: exp,
		HttpOnly: true, Secure: !a.cfg.Insecure, SameSite: http.SameSiteLaxMode,
	})
}

func (a *Authenticator) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: !a.cfg.Insecure, SameSite: http.SameSiteLaxMode,
	})
}

// user returns the authenticated subject for a request, or "" if none.
func (a *Authenticator) user(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	sub, ok := a.decode(c.Value)
	if !ok {
		return ""
	}
	return sub
}

// ---- gate ----

// public paths bypass the gate: liveness and the auth endpoints themselves.
// /auth/callback in particular must be reachable without a session — it is
// where a session comes from.
func isPublic(p string) bool {
	switch p {
	case "/healthz", "/login", "/logout", "/auth/login", "/auth/callback":
		return true
	}
	return false
}

// Middleware wraps h, requiring a valid session for every non-public path.
// Browser navigations get a 302 to /login; API/JSON/other get a 401.
func (a *Authenticator) Middleware(h http.Handler) http.Handler {
	if !a.Enabled() {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublic(r.URL.Path) || a.user(r) != "" {
			h.ServeHTTP(w, r)
			return
		}
		if wantsHTML(r) {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		http.Error(w, "authentication required", http.StatusUnauthorized)
	})
}

func wantsHTML(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html")
}

// ---- login endpoints ----

// Register mounts the auth endpoints on mux (no-op in mode none).
func (a *Authenticator) Register(mux *http.ServeMux) {
	if !a.Enabled() {
		return
	}
	mux.HandleFunc("GET /login", a.loginForm)
	if a.local {
		mux.HandleFunc("POST /login", a.loginSubmit)
	}
	if a.oidc != nil {
		mux.HandleFunc("GET /auth/login", a.oidcStart)
		mux.HandleFunc("GET /auth/callback", a.oidcCallback)
	}
	// POST only: a GET /logout can be fired by any third-party page (an <img>
	// tag is enough) to sign a viewer out.
	mux.HandleFunc("POST /logout", a.logout)
}

func (a *Authenticator) loginForm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	next := safeNext(q.Get("next"))
	if a.user(r) != "" { // already logged in
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	v := loginView{
		Next:  next,
		Local: a.local,
		Error: errMessage(q.Get("err")),
	}
	if q.Get("signedout") != "" {
		v.Note = "You have been signed out."
	}
	if a.oidc != nil {
		v.OIDC = true
		v.Provider = a.oidc.name
		v.StartURL = "/auth/login?next=" + url.QueryEscape(next)

		// Auto-redirect: with a single sign-in method there is nothing to choose,
		// so don't make the viewer click through a card to reach it.
		//
		// Except when the card has something to say. Redirecting after a sign-out
		// would bounce straight back through a live SSO session and silently sign
		// the viewer back in — sign-out would look broken. Redirecting on an error
		// would spin: a viewer the allowlist rejects would be sent to the provider,
		// authenticated, rejected, and sent again, forever.
		if a.oidc.cfg.AutoRedirect && v.Error == "" && v.Note == "" {
			http.Redirect(w, r, v.StartURL, http.StatusFound)
			return
		}
	}
	a.tmpl.render(w, v)
}

// errMessage maps the opaque ?err= code to fixed copy. The query string is
// never echoed into the page, and the provider's own error text stays in the
// server log rather than the browser.
func errMessage(code string) string {
	switch code {
	case "creds":
		return "Incorrect username or password."
	case "denied":
		return "Your account is not permitted to view this dashboard."
	case "failed":
		return "Sign-in did not complete. Please try again."
	}
	return ""
}

func (a *Authenticator) loginSubmit(w http.ResponseWriter, r *http.Request) {
	// CSRF: a genuine login form is same-origin. Reject cross-origin POSTs.
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	user := r.PostFormValue("username")
	pass := r.PostFormValue("password")
	next := safeNext(r.PostFormValue("next"))

	hash, ok := a.cfg.Users[user]
	if !ok {
		hash = string(a.dummyHash) // equalize timing for unknown users
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) != nil || !ok {
		http.Redirect(w, r, "/login?err=creds&next="+url.QueryEscape(next), http.StatusFound)
		return
	}

	exp := time.Now().Add(a.cfg.SessionTTL)
	tok, err := a.encode(session{Sub: user, Exp: exp.Unix()})
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	a.setCookie(w, tok, exp)
	http.Redirect(w, r, next, http.StatusFound)
}

// logout ends the Portolan session and nothing else. In oidc mode it
// deliberately does not drive the provider's end_session_endpoint: signing out
// of Portolan should not sign you out of every other app behind the same IdP.
// Ending the IdP session is the IdP's own affair.
func (a *Authenticator) logout(w http.ResponseWriter, r *http.Request) {
	// Same guard as login: SameSite=Lax withholds the cookie from a cross-site
	// POST, but the response could still clear it, so a hostile page could
	// force a sign-out. Only annoyance, but the check is free.
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	a.clearCookie(w)
	// Land on the card rather than bouncing straight back through the IdP,
	// which — with a live SSO session — would silently sign the viewer back in
	// and make sign-out look broken.
	http.Redirect(w, r, "/login?signedout=1", http.StatusFound)
}

// safeNext prevents open-redirects: only local absolute paths are allowed.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, "\\") {
		return "/"
	}
	return next
}

// sameOrigin verifies the Origin (or Referer) host matches the request host —
// a stateless CSRF defense for the login POST, alongside SameSite=Lax.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return true // non-browser client (e.g. curl) with no Origin — allow
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

// ---- user file ----

// LoadUsers parses an htpasswd-style file: one "username:bcrypthash" per line.
// Blank lines and #-comments are ignored. Compatible with `htpasswd -B` and
// with `portolan hashpw`.
func LoadUsers(r io.Reader) (map[string]string, error) {
	users := map[string]string{}
	sc := bufio.NewScanner(r)
	for line := 1; sc.Scan(); line++ {
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		name, hash, ok := strings.Cut(t, ":")
		if !ok || name == "" || hash == "" {
			return nil, fmt.Errorf("users line %d: expected username:hash", line)
		}
		if !strings.HasPrefix(hash, "$2") { // bcrypt hashes start $2a/$2b/$2y
			return nil, fmt.Errorf("users line %d: hash is not bcrypt", line)
		}
		users[name] = hash
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

// DecodeKey parses a 32-byte session key from base64 (std, raw, or url) or hex.
func DecodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(s); err == nil && len(b) == sessionKeyLen {
			return b, nil
		}
	}
	return nil, fmt.Errorf("session key must decode (base64 or hex) to %d bytes", sessionKeyLen)
}
