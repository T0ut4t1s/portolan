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
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Mode selects the authentication scheme. OIDC is a planned second mode that
// will reuse this package's session layer.
type Mode string

const (
	ModeNone  Mode = "none"  // no auth (default) — for CLI use or behind a trusted proxy
	ModeLocal Mode = "local" // built-in username/password, bcrypt-hashed
)

const (
	cookieName    = "portolan_session"
	sessionKeyLen = 32 // AES-256
)

// Config is the resolved auth configuration for serve mode.
type Config struct {
	Mode Mode
	// SessionKey must be exactly 32 bytes (AES-256) when Mode != none.
	SessionKey []byte
	SessionTTL time.Duration
	// Users maps username -> bcrypt hash (local mode).
	Users map[string]string
	// Insecure drops the cookie Secure flag — for plain-HTTP local testing
	// only. In production the browser⇔proxy leg is HTTPS, so leave this false
	// even though the pod itself is reached over HTTP behind TLS termination.
	Insecure bool
}

// Authenticator enforces a Config: it gates a handler and serves the login
// endpoints. The zero-value modes (none) pass everything through.
type Authenticator struct {
	cfg       Config
	aead      cipher.AEAD
	dummyHash []byte // constant-time decoy for unknown users (defeats enumeration timing)
	tmpl      *loginTemplate
}

// New validates cfg and builds an Authenticator. In mode "none" it returns a
// pass-through. Otherwise it fails closed on any misconfiguration — a
// half-configured auth is worse than none.
func New(cfg Config) (*Authenticator, error) {
	if cfg.Mode == "" {
		cfg.Mode = ModeNone
	}
	if cfg.Mode == ModeNone {
		return &Authenticator{cfg: cfg}, nil
	}
	if cfg.Mode != ModeLocal {
		return nil, fmt.Errorf("auth: unknown mode %q", cfg.Mode)
	}
	if len(cfg.SessionKey) != sessionKeyLen {
		return nil, fmt.Errorf("auth: session key must be %d bytes, got %d", sessionKeyLen, len(cfg.SessionKey))
	}
	if len(cfg.Users) == 0 {
		return nil, errors.New("auth: mode local requires at least one user")
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
	// A real (unmatchable) hash so a login attempt for an unknown user still
	// pays the bcrypt cost — otherwise response timing leaks which users exist.
	dummy, err := bcrypt.GenerateFromPassword([]byte("portolan-decoy"), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	return &Authenticator{cfg: cfg, aead: aead, dummyHash: dummy, tmpl: loginTmpl()}, nil
}

// Enabled reports whether any auth mode is active.
func (a *Authenticator) Enabled() bool { return a.cfg.Mode != ModeNone }

// ---- stateless session token ----

type session struct {
	Sub string `json:"s"`
	Exp int64  `json:"e"` // unix seconds
}

// encode seals a session into a URL-safe token: nonce ‖ AES-GCM(plaintext).
func (a *Authenticator) encode(s session) (string, error) {
	pt, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, a.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := a.aead.Seal(nonce, nonce, pt, nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// decode verifies and opens a token, returning the subject if it is
// authentic and unexpired.
func (a *Authenticator) decode(tok string) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(raw) < a.aead.NonceSize() {
		return "", false
	}
	nonce, ct := raw[:a.aead.NonceSize()], raw[a.aead.NonceSize():]
	pt, err := a.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", false
	}
	var s session
	if err := json.Unmarshal(pt, &s); err != nil {
		return "", false
	}
	if time.Now().Unix() >= s.Exp {
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
func isPublic(p string) bool {
	switch p {
	case "/healthz", "/login", "/logout":
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

// Register mounts /login and /logout on mux (no-op in mode none).
func (a *Authenticator) Register(mux *http.ServeMux) {
	if !a.Enabled() {
		return
	}
	mux.HandleFunc("GET /login", a.loginForm)
	mux.HandleFunc("POST /login", a.loginSubmit)
	// POST only: a GET /logout can be fired by any third-party page (an <img>
	// tag is enough) to sign a viewer out.
	mux.HandleFunc("POST /logout", a.logout)
}

func (a *Authenticator) loginForm(w http.ResponseWriter, r *http.Request) {
	if a.user(r) != "" { // already logged in
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusFound)
		return
	}
	a.tmpl.render(w, safeNext(r.URL.Query().Get("next")), r.URL.Query().Get("err") != "")
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
		http.Redirect(w, r, "/login?err=1&next="+url.QueryEscape(next), http.StatusFound)
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

func (a *Authenticator) logout(w http.ResponseWriter, r *http.Request) {
	// Same guard as login: SameSite=Lax withholds the cookie from a cross-site
	// POST, but the response could still clear it, so a hostile page could
	// force a sign-out. Only annoyance, but the check is free.
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	a.clearCookie(w)
	http.Redirect(w, r, "/login", http.StatusFound)
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
