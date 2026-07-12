// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig configures mode oidc: the authorization-code flow with PKCE
// against an OpenID Connect provider. The resulting session is the same sealed
// cookie local mode issues — only the way it is earned differs.
type OIDCConfig struct {
	// Issuer is what the provider calls itself in the `iss` claim, and where
	// discovery happens unless DiscoveryURL overrides it.
	Issuer string
	// DiscoveryURL, when set, is where the discovery document, the signing keys
	// and the token endpoint are actually fetched from, while `iss` is still
	// required to equal Issuer. This lets an in-cluster Portolan reach its IdP
	// over a Service (http://authentik-server.authentik:80/...) instead of
	// hairpinning out through the public ingress and back — which would need a
	// far wider egress policy for a pod that otherwise only talks to the
	// kube-API and Hubble. The browser-facing authorization endpoint always
	// stays the public URL the provider advertises.
	DiscoveryURL string
	ClientID     string
	ClientSecret string
	// RedirectURL is the absolute callback, and must match what is registered
	// with the provider: https://portolan.example.com/auth/callback
	RedirectURL string
	Scopes      []string // default: openid, profile, email
	// GroupsClaim names the ID-token claim holding the user's groups.
	GroupsClaim string // default: groups

	// Authorization. Authenticating is not authorizing: holding an account at
	// the IdP is not by itself a reason to be handed a map of the cluster's
	// network policy. One of these must be set — see newOIDCClient.
	AllowedGroups         []string
	AllowedEmails         []string
	AllowAnyAuthenticated bool

	// ProviderName labels the sign-in button; defaults to the issuer's host.
	ProviderName string
}

// oidcClient is the resolved provider: everything discovery told us, with the
// back-channel endpoints pointed wherever DiscoveryURL says.
type oidcClient struct {
	cfg      *OIDCConfig
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	name     string
}

// The discovery budget bounds the wait for a provider that is still starting
// up: a cluster-wide restart can bring Portolan up seconds before its IdP, and
// crash-looping on that is noise, not signal. When the budget runs out we still
// exit rather than serve the map open. Variables, not constants, only so the
// tests need not sit through half a minute of real backoff.
var (
	discoveryAttempts = 6
	discoveryBackoff  = 5 * time.Second
)

func newOIDCClient(ctx context.Context, c *OIDCConfig) (*oidcClient, error) {
	switch {
	case c.Issuer == "":
		return nil, errors.New("auth: oidc requires an issuer URL")
	case c.ClientID == "":
		return nil, errors.New("auth: oidc requires a client ID")
	case c.ClientSecret == "":
		return nil, errors.New("auth: oidc requires a client secret")
	case c.RedirectURL == "":
		return nil, errors.New("auth: oidc requires a redirect URL (the absolute https://…/auth/callback registered with the provider)")
	}
	if u, err := url.Parse(c.RedirectURL); err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("auth: oidc redirect URL must be absolute, got %q", c.RedirectURL)
	}
	// Fail closed on an unbounded allowlist: an open IdP registration would
	// otherwise silently mean an open dashboard.
	if !c.AllowAnyAuthenticated && len(c.AllowedGroups) == 0 && len(c.AllowedEmails) == 0 {
		return nil, errors.New("auth: oidc requires an allowlist — set allowed-groups or allowed-emails, " +
			"or allow-any-authenticated to admit every account the provider authenticates")
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	if c.GroupsClaim == "" {
		c.GroupsClaim = "groups"
	}

	provider, err := discover(ctx, c)
	if err != nil {
		return nil, err
	}
	var meta struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, fmt.Errorf("auth: oidc: reading discovery document: %w", err)
	}
	if meta.JWKSURL == "" {
		return nil, errors.New("auth: oidc: discovery document advertises no jwks_uri")
	}

	endpoint := provider.Endpoint()
	jwksURL, tokenURL := meta.JWKSURL, endpoint.TokenURL
	if c.DiscoveryURL != "" {
		// Discovery advertises the provider's public URLs. The browser needs the
		// public authorization endpoint — it is the browser that goes there — but
		// our own back-channel calls should stay inside the cluster, so send them
		// to the discovery host instead.
		if jwksURL, err = rehost(jwksURL, c.DiscoveryURL); err != nil {
			return nil, err
		}
		if tokenURL, err = rehost(tokenURL, c.DiscoveryURL); err != nil {
			return nil, err
		}
	}

	// The verifier checks the signature against the provider's live JWKS and
	// pins iss to the public issuer and aud to our client ID — regardless of
	// where the metadata was fetched from.
	verifier := oidc.NewVerifier(c.Issuer, oidc.NewRemoteKeySet(ctx, jwksURL), &oidc.Config{ClientID: c.ClientID})

	name := c.ProviderName
	if name == "" {
		if u, err := url.Parse(c.Issuer); err == nil && u.Host != "" {
			name = u.Host
		} else {
			name = "your identity provider"
		}
	}

	return &oidcClient{
		cfg: c,
		oauth: &oauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:   endpoint.AuthURL,
				TokenURL:  tokenURL,
				AuthStyle: endpoint.AuthStyle,
			},
			RedirectURL: c.RedirectURL,
			Scopes:      c.Scopes,
		},
		verifier: verifier,
		name:     name,
	}, nil
}

// discover fetches the provider metadata, retrying a provider that is not up
// yet before finally giving up (and, upstack, refusing to start).
func discover(ctx context.Context, c *OIDCConfig) (*oidc.Provider, error) {
	from := c.Issuer
	dctx := ctx
	if c.DiscoveryURL != "" {
		from = c.DiscoveryURL
		// go-oidc otherwise insists the document's `issuer` equal the URL it
		// fetched from. Decoupling the two is the entire point of the override,
		// and it costs nothing: the ID token's `iss` is still verified against
		// c.Issuer below, and its signature still has to match the provider's
		// published keys. All we give up is the assumption that metadata can
		// only come from the issuer's own public URL — which is exactly the
		// assumption an in-cluster Service call breaks.
		dctx = oidc.InsecureIssuerURLContext(ctx, c.Issuer)
	}
	var lastErr error
	for attempt := 1; attempt <= discoveryAttempts; attempt++ {
		provider, err := oidc.NewProvider(dctx, from)
		if err == nil {
			return provider, nil
		}
		lastErr = err
		if attempt == discoveryAttempts {
			break
		}
		fmt.Fprintf(os.Stderr, "auth: oidc discovery at %s failed (attempt %d/%d): %v\n", from, attempt, discoveryAttempts, err)
		select {
		case <-time.After(discoveryBackoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("auth: oidc discovery at %s failed after %d attempts: %w", from, discoveryAttempts, lastErr)
}

// rehost swaps raw's scheme and host for base's, keeping its path and query.
func rehost(raw, base string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("auth: oidc: parsing discovered endpoint %q: %w", raw, err)
	}
	b, err := url.Parse(base)
	if err != nil || b.Scheme == "" || b.Host == "" {
		return "", fmt.Errorf("auth: oidc: discovery URL must be absolute, got %q", base)
	}
	u.Scheme, u.Host = b.Scheme, b.Host
	return u.String(), nil
}

// ---- login transaction ----

// oidcTx is everything the callback needs to finish a flow it did not itself
// start. It is sealed into a short-lived cookie rather than parked in a
// server-side map: the server stays stateless, any replica can complete any
// login, and there is nothing to expire or garbage-collect.
type oidcTx struct {
	State    string `json:"st"`
	Verifier string `json:"cv"` // PKCE code_verifier
	Nonce    string `json:"no"`
	Next     string `json:"nx"`
	Exp      int64  `json:"e"`
}

const (
	txCookieName = "portolan_oidc_tx"
	txTTL        = 10 * time.Minute
)

// oidcStart mints a transaction and sends the browser to the provider.
func (a *Authenticator) oidcStart(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if a.user(r) != "" { // already signed in
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	state, err := randToken()
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	nonce, err := randToken()
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()

	exp := time.Now().Add(txTTL)
	tok, err := a.seal(purposeTx, oidcTx{State: state, Verifier: verifier, Nonce: nonce, Next: next, Exp: exp.Unix()})
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: txCookieName, Value: tok, Path: "/", Expires: exp,
		HttpOnly: true, Secure: !a.cfg.Insecure, SameSite: http.SameSiteLaxMode,
	})
	// Lax is what makes this work: the provider sends the browser back with a
	// top-level GET, which carries a Lax cookie. Strict would withhold it and
	// every login would fail.
	http.Redirect(w, r, a.oidc.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// oidcCallback completes the flow: state, code exchange, ID token, allowlist,
// session.
func (a *Authenticator) oidcCallback(w http.ResponseWriter, r *http.Request) {
	tx, ok := a.takeTx(w, r) // single-use, whatever happens below
	if !ok {
		a.oidcFail(w, r, "/", "failed", "no valid login transaction (it expired, or cookies are being blocked)")
		return
	}
	next := safeNext(tx.Next)
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		a.oidcFail(w, r, next, "failed", "provider returned error: "+e+" "+q.Get("error_description"))
		return
	}
	// State ties this callback to the transaction we started. Without it, an
	// attacker can walk a victim's browser through a login with the attacker's
	// own authorization code, and the victim ends up in the attacker's session.
	if subtle.ConstantTimeCompare([]byte(tx.State), []byte(q.Get("state"))) != 1 {
		a.oidcFail(w, r, next, "failed", "state mismatch")
		return
	}
	code := q.Get("code")
	if code == "" {
		a.oidcFail(w, r, next, "failed", "provider returned no authorization code")
		return
	}

	tok, err := a.oidc.oauth.Exchange(r.Context(), code, oauth2.VerifierOption(tx.Verifier))
	if err != nil {
		a.oidcFail(w, r, next, "failed", "code exchange: "+err.Error())
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		a.oidcFail(w, r, next, "failed", "token response carried no id_token")
		return
	}
	// Signature, issuer, audience and expiry.
	idt, err := a.oidc.verifier.Verify(r.Context(), rawID)
	if err != nil {
		a.oidcFail(w, r, next, "failed", "id token: "+err.Error())
		return
	}
	// The nonce binds the token to this transaction: an ID token captured from
	// some other login carries a nonce we never issued.
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(tx.Nonce)) != 1 {
		a.oidcFail(w, r, next, "failed", "nonce mismatch")
		return
	}

	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		a.oidcFail(w, r, next, "failed", "id token claims: "+err.Error())
		return
	}
	sub, err := a.oidc.authorize(claims, idt.Subject)
	if err != nil {
		a.oidcFail(w, r, next, "denied", err.Error())
		return
	}

	exp := time.Now().Add(a.cfg.SessionTTL)
	stok, err := a.encode(session{Sub: sub, Exp: exp.Unix()})
	if err != nil {
		a.oidcFail(w, r, next, "failed", "sealing session: "+err.Error())
		return
	}
	a.setCookie(w, stok, exp)
	fmt.Fprintf(os.Stderr, "auth: %s signed in via %s\n", sub, a.oidc.name)
	http.Redirect(w, r, next, http.StatusFound)
}

// takeTx reads and invalidates the transaction cookie. It is cleared on every
// path, so a failed or replayed callback cannot reuse it.
func (a *Authenticator) takeTx(w http.ResponseWriter, r *http.Request) (oidcTx, bool) {
	http.SetCookie(w, &http.Cookie{
		Name: txCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: !a.cfg.Insecure, SameSite: http.SameSiteLaxMode,
	})
	c, err := r.Cookie(txCookieName)
	if err != nil {
		return oidcTx{}, false
	}
	var tx oidcTx
	if !a.open(purposeTx, c.Value, &tx) {
		return oidcTx{}, false
	}
	if tx.State == "" || tx.Nonce == "" || time.Now().Unix() >= tx.Exp {
		return oidcTx{}, false
	}
	return tx, true
}

// oidcFail logs the real reason and shows the viewer a fixed message. The
// provider's error text can carry detail that is none of the browser's
// business, and echoing it back is a reflection hazard besides.
func (a *Authenticator) oidcFail(w http.ResponseWriter, r *http.Request, next, code, reason string) {
	fmt.Fprintf(os.Stderr, "auth: oidc sign-in failed (%s): %s\n", code, reason)
	http.Redirect(w, r, "/login?err="+code+"&next="+url.QueryEscape(next), http.StatusFound)
}

// ---- authorization ----

// authorize decides whether an authenticated identity may see the map, and
// returns the name to record in the session. Authentication was the provider's
// job; authorization is ours.
func (o *oidcClient) authorize(claims map[string]any, subject string) (string, error) {
	name := firstString(claims, "preferred_username", "email", "name")
	if name == "" {
		name = subject
	}
	if o.cfg.AllowAnyAuthenticated {
		return name, nil
	}

	// An email match is only as trustworthy as the provider's control of the
	// address. If it says outright that the address is unverified, do not match
	// on it — a self-service IdP would otherwise let anyone claim their way in.
	// (Providers that omit the claim entirely are taken at their word.)
	verified, stated := claims["email_verified"].(bool)
	if email := strings.ToLower(claimString(claims, "email")); email != "" && (verified || !stated) {
		for _, allowed := range o.cfg.AllowedEmails {
			if strings.EqualFold(strings.TrimSpace(allowed), email) {
				return name, nil
			}
		}
	}

	groups := claimStrings(claims, o.cfg.GroupsClaim)
	for _, allowed := range o.cfg.AllowedGroups {
		allowed = strings.TrimSpace(allowed)
		for _, g := range groups {
			if strings.EqualFold(g, allowed) {
				return name, nil
			}
		}
	}
	return "", fmt.Errorf("%q is in no allowed group (%s claim: %v) and matches no allowed email", name, o.cfg.GroupsClaim, groups)
}

func claimString(c map[string]any, key string) string {
	s, _ := c[key].(string)
	return s
}

func firstString(c map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := claimString(c, k); s != "" {
			return s
		}
	}
	return ""
}

// claimStrings reads a claim that should hold a list of strings, tolerating a
// provider that emits a lone bare string instead.
func claimStrings(c map[string]any, key string) []string {
	switch v := c[key].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// randToken returns 32 bytes of entropy, URL-safe.
func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
