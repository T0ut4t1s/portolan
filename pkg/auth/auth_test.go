// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func testAuth(t *testing.T) *Authenticator {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	h, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost) // MinCost: fast tests
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(context.Background(), Config{
		Modes: []Mode{ModeLocal}, SessionKey: key, SessionTTL: time.Hour,
		Users: map[string]string{"alice": string(h)}, Insecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("OK")) })
}

func TestNewFailsClosed(t *testing.T) {
	cases := []Config{
		{Modes: []Mode{ModeLocal}, SessionKey: make([]byte, 16), Users: map[string]string{"a": "$2a$x"}}, // short key
		{Modes: []Mode{ModeLocal}, SessionKey: make([]byte, 32)},                                         // no users
		{Modes: []Mode{"bogus"}, SessionKey: make([]byte, 32), Users: map[string]string{"a": "$2a$x"}},   // bad mode
	}
	for i, c := range cases {
		if _, err := New(context.Background(), c); err == nil {
			t.Errorf("case %d: expected error, got nil", i)
		}
	}
	// mode none is always fine and a pass-through.
	a, err := New(context.Background(), Config{Modes: []Mode{ModeNone}})
	if err != nil || a.Enabled() {
		t.Fatalf("mode none: err=%v enabled=%v", err, a.Enabled())
	}
}

func TestSessionRoundTrip(t *testing.T) {
	a := testAuth(t)
	tok, err := a.encode(session{Sub: "alice", Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if sub, ok := a.decode(tok); !ok || sub != "alice" {
		t.Fatalf("roundtrip: sub=%q ok=%v", sub, ok)
	}
}

func TestSessionTamperRejected(t *testing.T) {
	a := testAuth(t)
	tok, _ := a.encode(session{Sub: "alice", Exp: time.Now().Add(time.Hour).Unix()})
	// flip a byte in the middle of the token.
	b := []byte(tok)
	b[len(b)/2] ^= 0x01
	if _, ok := a.decode(string(b)); ok {
		t.Fatal("tampered token accepted")
	}
	// a token from a different key must not verify.
	other := testAuth(t)
	if _, ok := a.decode(mustEncode(t, other, "alice")); ok {
		t.Fatal("token from foreign key accepted")
	}
}

func TestSessionExpiryRejected(t *testing.T) {
	a := testAuth(t)
	tok, _ := a.encode(session{Sub: "alice", Exp: time.Now().Add(-time.Second).Unix()})
	if _, ok := a.decode(tok); ok {
		t.Fatal("expired token accepted")
	}
}

func TestGate(t *testing.T) {
	a := testAuth(t)
	h := a.Middleware(okHandler())

	// unauthenticated JSON/API -> 401
	r := httptest.NewRequest("GET", "/snapshot.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("api unauth: got %d want 401", w.Code)
	}

	// unauthenticated browser navigation -> 302 to /login
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept", "text/html")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), "/login") {
		t.Errorf("browser unauth: got %d loc=%q", w.Code, w.Header().Get("Location"))
	}

	// /healthz is always public
	r = httptest.NewRequest("GET", "/healthz", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("healthz: got %d want 200", w.Code)
	}

	// with a valid cookie -> passes through
	r = httptest.NewRequest("GET", "/snapshot.json", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: mustEncode(t, a, "alice")})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Body.String() != "OK" {
		t.Errorf("authed: got %d body=%q", w.Code, w.Body.String())
	}
}

func TestModeNonePassesThrough(t *testing.T) {
	a, _ := New(context.Background(), Config{Modes: []Mode{ModeNone}})
	h := a.Middleware(okHandler())
	r := httptest.NewRequest("GET", "/snapshot.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("mode none should pass: got %d", w.Code)
	}
}

func TestLoginFlow(t *testing.T) {
	a := testAuth(t)
	mux := http.NewServeMux()
	a.Register(mux)

	post := func(user, pass, origin string) *httptest.ResponseRecorder {
		form := url.Values{"username": {user}, "password": {pass}, "next": {"/audit.json"}}
		r := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}

	// correct creds, same-origin -> 302 to next, with a session cookie
	w := post("alice", "hunter2", "http://example.com")
	// httptest requests have Host "example.com"
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/audit.json" {
		t.Fatalf("good login: got %d loc=%q", w.Code, w.Header().Get("Location"))
	}
	var cookie string
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			cookie = c.Value
		}
	}
	if cookie == "" {
		t.Fatal("no session cookie set")
	}
	if sub, ok := a.decode(cookie); !ok || sub != "alice" {
		t.Fatalf("issued cookie invalid: sub=%q ok=%v", sub, ok)
	}

	// wrong password -> redirect back to /login?err
	w = post("alice", "wrong", "http://example.com")
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "err=creds") {
		t.Errorf("bad password: got %d loc=%q", w.Code, w.Header().Get("Location"))
	}

	// unknown user -> same treatment (no cookie, err)
	w = post("mallory", "whatever", "http://example.com")
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "err=creds") {
		t.Errorf("unknown user: got %d loc=%q", w.Code, w.Header().Get("Location"))
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName && c.Value != "" {
			t.Error("unknown user got a session cookie")
		}
	}

	// cross-origin POST -> 403 (CSRF defense)
	w = post("alice", "hunter2", "http://evil.example")
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-origin: got %d want 403", w.Code)
	}
}

func TestLogout(t *testing.T) {
	a := testAuth(t)
	mux := http.NewServeMux()
	a.Register(mux)

	logout := func(method, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/logout", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}

	// same-origin POST -> cookie cleared, back to the login page
	w := logout("POST", "http://example.com")
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), "/login") {
		t.Fatalf("logout: got %d loc=%q", w.Code, w.Header().Get("Location"))
	}
	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName && c.Value == "" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout did not clear the session cookie")
	}

	// GET is not a route: a third-party <img src=".../logout"> must not be
	// able to sign a viewer out.
	if w := logout("GET", "http://example.com"); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /logout: got %d want 405", w.Code)
	}

	// cross-origin POST -> 403, same guard as login
	if w := logout("POST", "http://evil.example"); w.Code != http.StatusForbidden {
		t.Errorf("cross-origin logout: got %d want 403", w.Code)
	}
}

func TestLoadUsers(t *testing.T) {
	good := "# comment\nalice:$2a$10$abcdefghijklmnopqrstuv\n\nbob:$2b$10$zyxwvutsrqponmlkjihgfe\n"
	users, err := LoadUsers(strings.NewReader(good))
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users["alice"] == "" || users["bob"] == "" {
		t.Fatalf("parsed %v", users)
	}
	for _, bad := range []string{"noseparator\n", "alice:plaintext\n", ":$2a$x\n"} {
		if _, err := LoadUsers(strings.NewReader(bad)); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestDecodeKey(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	// base64 and hex encodings of a 32-byte key must both decode.
	for _, enc := range []string{
		base64.StdEncoding.EncodeToString(raw), hex.EncodeToString(raw),
	} {
		got, err := DecodeKey(enc)
		if err != nil || len(got) != 32 {
			t.Errorf("DecodeKey(%q): err=%v len=%d", enc, err, len(got))
		}
	}
	if _, err := DecodeKey("tooshort"); err == nil {
		t.Error("expected error for short key")
	}
}

// helpers

func mustEncode(t *testing.T, a *Authenticator, sub string) string {
	t.Helper()
	tok, err := a.encode(session{Sub: sub, Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
