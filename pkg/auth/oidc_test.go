// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ---- a fake OpenID provider ----
//
// Enough of an IdP to exercise the real flow end to end: discovery, an
// authorization endpoint that records the PKCE challenge, a token endpoint that
// checks the verifier against it, and a JWKS the ID token actually validates
// against. The knobs let each test bend exactly one thing and prove Portolan
// rejects it.

type fakeIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	issuer   string // what the discovery document and the tokens claim
	clientID string

	// per-test knobs
	audience      string         // aud override (default: clientID)
	nonce         string         // id_token nonce override (default: the one requested)
	lifetime      time.Duration  // id_token lifetime (default 1h; negative = already expired)
	claims        map[string]any // extra claims merged into the id_token
	failDiscovery int            // 503 the first N discovery requests (an IdP still booting)

	codes map[string]authCode
}

type authCode struct{ nonce, challenge string }

func newFakeIdP(t *testing.T, clientID string) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, clientID: clientID, lifetime: time.Hour, codes: map[string]authCode{}}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if f.failDiscovery > 0 {
			f.failDiscovery--
			http.Error(w, "still starting up", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]any{
			"issuer":                                f.issuer,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := f.key.Public().(*rsa.PublicKey)
		writeJSON(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test",
			"n": b64(pub.N.Bytes()),
			"e": b64(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	// The browser lands here, consents, and is bounced back with a code.
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := "code-" + q.Get("state")[:8]
		f.codes[code] = authCode{nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
		redirect, _ := url.Parse(q.Get("redirect_uri"))
		rq := redirect.Query()
		rq.Set("code", code)
		rq.Set("state", q.Get("state"))
		redirect.RawQuery = rq.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})
	// The back channel: verifier must hash to the challenge we recorded.
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		rec, ok := f.codes[r.PostFormValue("code")]
		if !ok {
			http.Error(w, "unknown code", http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if b64(sum[:]) != rec.challenge {
			http.Error(w, "PKCE verification failed", http.StatusBadRequest)
			return
		}
		nonce := rec.nonce
		if f.nonce != "" {
			nonce = f.nonce
		}
		aud := f.audience
		if aud == "" {
			aud = f.clientID
		}
		claims := map[string]any{
			"iss": f.issuer, "aud": aud, "sub": "user-1", "nonce": nonce,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(f.lifetime).Unix(),
		}
		for k, v := range f.claims {
			claims[k] = v
		}
		writeJSON(w, map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
			"id_token": f.signJWT(t, claims),
		})
	})

	f.srv = httptest.NewServer(mux)
	f.issuer = f.srv.URL // overridden by the discovery-override test
	t.Cleanup(f.srv.Close)
	return f
}

// signJWT hand-rolls an RS256 JWT — a real one, verifiable against the JWKS
// above, without pulling a JOSE library into the test.
func (f *fakeIdP) signJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	hdr, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := b64(hdr) + "." + b64(body)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64(sig)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// ---- harness ----

// oidcAuth builds an Authenticator wired to f, letting the caller adjust the
// config first.
func oidcAuth(t *testing.T, f *fakeIdP, tweak func(*OIDCConfig)) *Authenticator {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c := &OIDCConfig{
		Issuer:        f.issuer,
		ClientID:      f.clientID,
		ClientSecret:  "shh",
		RedirectURL:   "http://portolan.example/auth/callback",
		AllowedGroups: []string{"portolan-viewers"},
	}
	if tweak != nil {
		tweak(c)
	}
	a, err := New(context.Background(), Config{
		Mode: ModeOIDC, SessionKey: key, SessionTTL: time.Hour, OIDC: c, Insecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// signIn walks the whole flow — start, provider authorize, callback — and
// returns the callback's response.
func signIn(t *testing.T, a *Authenticator, corrupt func(q url.Values)) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	a.Register(mux)

	// 1. start: Portolan seals a transaction and points us at the provider.
	start := httptest.NewRecorder()
	mux.ServeHTTP(start, httptest.NewRequest("GET", "/auth/login?next=/audit.json", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("/auth/login: got %d, want 302", start.Code)
	}
	txCookie := cookieNamed(start.Result().Cookies(), txCookieName)
	if txCookie == nil {
		t.Fatal("/auth/login set no transaction cookie")
	}

	// 2. the provider authenticates and bounces back with a code.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	back, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := back.Query()
	if corrupt != nil {
		corrupt(q)
	}

	// 3. callback: Portolan finishes the flow.
	r := httptest.NewRequest("GET", "/auth/callback?"+q.Encode(), nil)
	r.AddCookie(txCookie)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func cookieNamed(cs []*http.Cookie, name string) *http.Cookie {
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// assertDenied checks the callback bounced to the login page with the given
// error code and, above all, minted no session.
func assertDenied(t *testing.T, w *httptest.ResponseRecorder, wantErr string) {
	t.Helper()
	if w.Code != http.StatusFound {
		t.Fatalf("got %d, want a 302 back to /login", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login") || !strings.Contains(loc, "err="+wantErr) {
		t.Errorf("Location = %q, want /login?err=%s", loc, wantErr)
	}
	if c := cookieNamed(w.Result().Cookies(), cookieName); c != nil && c.Value != "" {
		t.Fatal("a rejected sign-in minted a session cookie")
	}
}

// ---- the flow ----

func TestOIDCSignIn(t *testing.T) {
	f := newFakeIdP(t, "portolan")
	f.claims = map[string]any{
		"preferred_username": "alice",
		"groups":             []any{"other", "portolan-viewers"},
	}
	a := oidcAuth(t, f, nil)

	w := signIn(t, a, nil)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/audit.json" {
		t.Fatalf("sign-in: got %d loc=%q, want 302 to /audit.json", w.Code, w.Header().Get("Location"))
	}
	c := cookieNamed(w.Result().Cookies(), cookieName)
	if c == nil {
		t.Fatal("no session cookie issued")
	}
	if sub, ok := a.decode(c.Value); !ok || sub != "alice" {
		t.Fatalf("session: sub=%q ok=%v, want alice", sub, ok)
	}
	// The transaction is spent: the callback clears it whatever the outcome.
	if tx := cookieNamed(w.Result().Cookies(), txCookieName); tx == nil || tx.MaxAge >= 0 {
		t.Error("callback did not clear the transaction cookie")
	}
}

// State is what stops an attacker walking a victim's browser through a login
// with the attacker's own code.
func TestOIDCStateMismatchRejected(t *testing.T) {
	f := newFakeIdP(t, "portolan")
	f.claims = map[string]any{"groups": []any{"portolan-viewers"}}
	a := oidcAuth(t, f, nil)

	w := signIn(t, a, func(q url.Values) { q.Set("state", "not-the-state-we-issued") })
	assertDenied(t, w, "failed")
}

// Without the sealed transaction there is no verifier and no nonce to check
// against, so the callback has nothing to trust.
func TestOIDCCallbackWithoutTransaction(t *testing.T) {
	f := newFakeIdP(t, "portolan")
	a := oidcAuth(t, f, nil)
	mux := http.NewServeMux()
	a.Register(mux)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/auth/callback?code=x&state=y", nil))
	assertDenied(t, w, "failed")
}

// A transaction cookie is not a session cookie: the two are sealed with the
// same key but under different AEAD purposes, so neither opens as the other.
func TestOIDCTransactionIsNotASession(t *testing.T) {
	f := newFakeIdP(t, "portolan")
	a := oidcAuth(t, f, nil)

	tok, err := a.seal(purposeTx, oidcTx{State: "s", Nonce: "n", Next: "/", Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if sub, ok := a.decode(tok); ok {
		t.Fatalf("a transaction token was accepted as a session (sub=%q)", sub)
	}
}

// An ID token minted for some other login carries a nonce we never issued.
func TestOIDCNonceMismatchRejected(t *testing.T) {
	f := newFakeIdP(t, "portolan")
	f.claims = map[string]any{"groups": []any{"portolan-viewers"}}
	f.nonce = "a-nonce-from-another-login"
	a := oidcAuth(t, f, nil)

	assertDenied(t, signIn(t, a, nil), "failed")
}

func TestOIDCExpiredTokenRejected(t *testing.T) {
	f := newFakeIdP(t, "portolan")
	f.claims = map[string]any{"groups": []any{"portolan-viewers"}}
	f.lifetime = -time.Minute
	a := oidcAuth(t, f, nil)

	assertDenied(t, signIn(t, a, nil), "failed")
}

// A token minted for a different client is not a token for us.
func TestOIDCWrongAudienceRejected(t *testing.T) {
	f := newFakeIdP(t, "portolan")
	f.claims = map[string]any{"groups": []any{"portolan-viewers"}}
	f.audience = "some-other-app"
	a := oidcAuth(t, f, nil)

	assertDenied(t, signIn(t, a, nil), "failed")
}

// ---- authorization ----

// Authenticating is not authorizing: a valid account in no allowed group is
// still turned away.
func TestOIDCGroupNotAllowed(t *testing.T) {
	f := newFakeIdP(t, "portolan")
	f.claims = map[string]any{
		"preferred_username": "mallory",
		"groups":             []any{"everyone"},
	}
	a := oidcAuth(t, f, nil)

	assertDenied(t, signIn(t, a, nil), "denied")
}

func TestOIDCAllowedEmail(t *testing.T) {
	f := newFakeIdP(t, "portolan")
	f.claims = map[string]any{"email": "Alice@Example.com", "email_verified": true}
	a := oidcAuth(t, f, func(c *OIDCConfig) {
		c.AllowedGroups = nil
		c.AllowedEmails = []string{"alice@example.com"}
	})

	if w := signIn(t, a, nil); w.Code != http.StatusFound || w.Header().Get("Location") != "/audit.json" {
		t.Fatalf("allowed email: got %d loc=%q", w.Code, w.Header().Get("Location"))
	}
}

// An address the provider itself flags as unverified must not satisfy an email
// allowlist — otherwise a self-service IdP lets anyone claim their way in.
func TestOIDCUnverifiedEmailRejected(t *testing.T) {
	f := newFakeIdP(t, "portolan")
	f.claims = map[string]any{"email": "alice@example.com", "email_verified": false}
	a := oidcAuth(t, f, func(c *OIDCConfig) {
		c.AllowedGroups = nil
		c.AllowedEmails = []string{"alice@example.com"}
	})

	assertDenied(t, signIn(t, a, nil), "denied")
}

func TestOIDCAllowAnyAuthenticated(t *testing.T) {
	f := newFakeIdP(t, "portolan")
	f.claims = map[string]any{"preferred_username": "anyone", "groups": []any{"nobody"}}
	a := oidcAuth(t, f, func(c *OIDCConfig) {
		c.AllowedGroups = nil
		c.AllowAnyAuthenticated = true
	})

	if w := signIn(t, a, nil); w.Code != http.StatusFound || w.Header().Get("Location") != "/audit.json" {
		t.Fatalf("allow-any: got %d loc=%q", w.Code, w.Header().Get("Location"))
	}
}

// A custom groups claim (Authentik can be told to emit any name).
func TestOIDCCustomGroupsClaim(t *testing.T) {
	f := newFakeIdP(t, "portolan")
	f.claims = map[string]any{"roles": []any{"portolan-viewers"}}
	a := oidcAuth(t, f, func(c *OIDCConfig) { c.GroupsClaim = "roles" })

	if w := signIn(t, a, nil); w.Code != http.StatusFound {
		t.Fatalf("custom groups claim: got %d", w.Code)
	}
}

// ---- configuration ----

// An empty allowlist is a wide-open dashboard for anyone who can get an account
// at the IdP. Refuse to start rather than discover that later.
func TestOIDCRequiresAnAllowlist(t *testing.T) {
	f := newFakeIdP(t, "portolan")
	key := make([]byte, 32)
	rand.Read(key)
	_, err := New(context.Background(), Config{
		Mode: ModeOIDC, SessionKey: key, Insecure: true,
		OIDC: &OIDCConfig{
			Issuer: f.issuer, ClientID: "portolan", ClientSecret: "shh",
			RedirectURL: "http://portolan.example/auth/callback",
		},
	})
	if err == nil {
		t.Fatal("expected an error: no allowlist and no allow-any-authenticated")
	}
	if !strings.Contains(err.Error(), "allowlist") {
		t.Errorf("error should name the missing allowlist, got: %v", err)
	}
}

func TestOIDCConfigFailsClosed(t *testing.T) {
	f := newFakeIdP(t, "portolan")
	base := func() *OIDCConfig {
		return &OIDCConfig{
			Issuer: f.issuer, ClientID: "portolan", ClientSecret: "shh",
			RedirectURL:   "http://portolan.example/auth/callback",
			AllowedGroups: []string{"portolan-viewers"},
		}
	}
	cases := map[string]func(*OIDCConfig){
		"no issuer":          func(c *OIDCConfig) { c.Issuer = "" },
		"no client id":       func(c *OIDCConfig) { c.ClientID = "" },
		"no client secret":   func(c *OIDCConfig) { c.ClientSecret = "" },
		"no redirect url":    func(c *OIDCConfig) { c.RedirectURL = "" },
		"relative redirect":  func(c *OIDCConfig) { c.RedirectURL = "/auth/callback" },
		"unreachable issuer": func(c *OIDCConfig) { c.Issuer = "http://127.0.0.1:1/nope" },
	}
	// The unreachable-issuer case would otherwise sit through the real retry
	// budget; the point here is that it fails, not how patiently.
	defer func(n int, d time.Duration) { discoveryAttempts, discoveryBackoff = n, d }(discoveryAttempts, discoveryBackoff)
	discoveryAttempts, discoveryBackoff = 2, time.Millisecond

	key := make([]byte, 32)
	rand.Read(key)
	for name, break_ := range cases {
		t.Run(name, func(t *testing.T) {
			c := base()
			break_(c)
			if _, err := New(context.Background(), Config{
				Mode: ModeOIDC, SessionKey: key, OIDC: c, Insecure: true,
			}); err == nil {
				t.Error("expected an error, got nil")
			}
		})
	}
}

// The discovery override: metadata, keys and tokens are fetched from wherever
// we point them, but `iss` is still pinned to the public issuer.
func TestOIDCDiscoveryURLOverride(t *testing.T) {
	const public = "https://sso.example.com/application/o/portolan/"
	f := newFakeIdP(t, "portolan")
	f.issuer = public // the document and the tokens claim the public identity...
	f.claims = map[string]any{"preferred_username": "alice", "groups": []any{"portolan-viewers"}}

	a := oidcAuth(t, f, func(c *OIDCConfig) {
		c.Issuer = public
		c.DiscoveryURL = f.srv.URL // ...while we actually talk to the local one
	})
	w := signIn(t, a, nil)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/audit.json" {
		t.Fatalf("override sign-in: got %d loc=%q", w.Code, w.Header().Get("Location"))
	}
}

// A whole-cluster restart can bring Portolan up before its IdP. Wait it out
// rather than crash-looping — but only for as long as the budget allows.
func TestOIDCDiscoveryRetriesThenSucceeds(t *testing.T) {
	defer func(n int, d time.Duration) { discoveryAttempts, discoveryBackoff = n, d }(discoveryAttempts, discoveryBackoff)
	discoveryAttempts, discoveryBackoff = 5, time.Millisecond

	f := newFakeIdP(t, "portolan")
	f.failDiscovery = 3 // the provider is still coming up
	f.claims = map[string]any{"preferred_username": "alice", "groups": []any{"portolan-viewers"}}

	a := oidcAuth(t, f, nil) // fatals if discovery gave up
	if w := signIn(t, a, nil); w.Code != http.StatusFound {
		t.Fatalf("sign-in after a slow start: got %d", w.Code)
	}
}

func TestRehost(t *testing.T) {
	got, err := rehost("https://sso.example.com/application/o/token/", "http://authentik.authentik:9000")
	if err != nil {
		t.Fatal(err)
	}
	if want := "http://authentik.authentik:9000/application/o/token/"; got != want {
		t.Errorf("rehost = %q, want %q", got, want)
	}
	if _, err := rehost("https://sso.example.com/x", "not-a-url"); err == nil {
		t.Error("expected an error for a non-absolute discovery URL")
	}
}

// ---- the login page ----

func TestOIDCLoginPage(t *testing.T) {
	f := newFakeIdP(t, "portolan")
	a := oidcAuth(t, f, func(c *OIDCConfig) { c.ProviderName = "Authentik" })
	mux := http.NewServeMux()
	a.Register(mux)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/login?signedout=1", nil))
	body := w.Body.String()
	if !strings.Contains(body, "Sign in with Authentik") {
		t.Error("login page should offer the provider button")
	}
	if strings.Contains(body, `type="password"`) {
		t.Error("oidc mode must not render a password field")
	}
	// Sign-out lands here rather than bouncing straight back through a live SSO
	// session, which would silently sign the viewer back in.
	if !strings.Contains(body, "You have been signed out.") {
		t.Error("login page should confirm the sign-out")
	}
	// There is no local password endpoint to post to in oidc mode.
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/login", strings.NewReader("username=a&password=b")))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /login in oidc mode: got %d, want 405", w.Code)
	}
}
