package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// stubIdP is a minimal TLS OpenID provider whose endpoints each test scripts.
type stubIdP struct {
	srv      *httptest.Server
	key      *ecdsa.PrivateKey
	token    func(w http.ResponseWriter, r *http.Request)
	userinfo func(w http.ResponseWriter, r *http.Request)
	jwks     func(w http.ResponseWriter, r *http.Request)
	// discovery lets a test edit the document; nil keeps it as built.
	discovery func(d *Discovery)
	// noDiscovery answers the discovery URL with this status when non-zero.
	noDiscovery int
	extraKeys   []jose.JSONWebKey
}

const stubClientID = "client-1"

func newStubIdP(t *testing.T) *stubIdP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &stubIdP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if s.noDiscovery != 0 {
			w.WriteHeader(s.noDiscovery)
			return
		}
		doc := Discovery{
			Issuer:                s.srv.URL,
			AuthorizationEndpoint: s.srv.URL + "/authorize",
			TokenEndpoint:         s.srv.URL + "/token",
			UserinfoEndpoint:      s.srv.URL + "/userinfo",
			JWKSURI:               s.srv.URL + "/jwks",
		}
		if s.discovery != nil {
			s.discovery(&doc)
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) { s.token(w, r) })
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) { s.userinfo(w, r) })
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		if s.jwks != nil {
			s.jwks(w, r)
			return
		}
		keys := append([]jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}, s.extraKeys...)
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: keys})
	})
	s.srv = httptest.NewTLSServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stubIdP) client(t *testing.T, mutate func(*Settings)) *Client {
	t.Helper()
	settings := Settings{
		Issuer:       s.srv.URL,
		ClientID:     stubClientID,
		ClientSecret: strings.Repeat("s", MinHS256SecretBytes),
		CAPEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.srv.Certificate().Raw})),
	}
	if mutate != nil {
		mutate(&settings)
	}
	c, err := NewClient(settings)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// sign makes a compact JWS over payload with the stub's key.
func (s *stubIdP) sign(t *testing.T, payload string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: s.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func writeToken(status int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func byGrant(grants map[string]func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if handler, ok := grants[r.PostForm.Get("grant_type")]; ok {
			handler(w, r)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}
}

func TestLenientSecondsIgnoresOddValues(t *testing.T) {
	t.Parallel()
	cases := map[string]lenientSeconds{`60`: 60, `"90"`: 90, `" 15 "`: 15, `true`: 0, `"soon"`: 0, `[1]`: 0}
	for raw, want := range cases {
		var got lenientSeconds
		if err := json.Unmarshal([]byte(raw), &got); err != nil || got != want {
			t.Errorf("%s = %d, %v; want %d", raw, got, err, want)
		}
	}
}

func TestNewClientNeedsAnIssuer(t *testing.T) {
	t.Parallel()
	if _, err := NewClient(Settings{ClientID: "c"}); !errors.Is(err, ErrConfig) {
		t.Fatalf("err = %v", err)
	}
}

func TestHTTPClientRedirectPolicy(t *testing.T) {
	t.Parallel()
	client, err := NewHTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	secure, _ := http.NewRequest(http.MethodGet, "https://idp.example/next", nil)
	insecure, _ := http.NewRequest(http.MethodGet, "http://idp.example/next", nil)
	if err := client.CheckRedirect(secure, nil); err != nil {
		t.Fatalf("https redirect refused: %v", err)
	}
	if err := client.CheckRedirect(insecure, nil); err == nil {
		t.Fatal("redirect to http accepted")
	}
	if err := client.CheckRedirect(secure, make([]*http.Request, 5)); err == nil {
		t.Fatal("sixth redirect accepted")
	}
	// A CA bundle is added to the system roots, so a bundle with a real
	// certificate must be accepted.
	idp := newStubIdP(t)
	if _, err := NewHTTPClient(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.srv.Certificate().Raw}))); err != nil {
		t.Fatalf("valid CA bundle: %v", err)
	}
}

func TestHelpers(t *testing.T) {
	t.Parallel()
	if truncate(strings.Repeat("a", 10), 4) != "aaaa..." || truncate("abc", 4) != "abc" {
		t.Fatal("truncate")
	}
	plain := errors.New("plain")
	if redactURLError(plain) != plain {
		t.Fatal("a non-URL error must pass through")
	}
	inner := errors.New("inner")
	if redactURLError(&url.Error{Op: "Get", URL: "https://secret@idp/x", Err: inner}) != inner {
		t.Fatal("a URL error must be reduced to its cause")
	}
}

func TestProbeClientAuthOutcomes(t *testing.T) {
	t.Parallel()
	ok := writeToken(http.StatusOK, `{"access_token":"a","token_type":"Bearer"}`)
	notJSON := writeToken(http.StatusOK, `not json`)
	oauth := func(code string) func(http.ResponseWriter, *http.Request) {
		return writeToken(http.StatusBadRequest, `{"error":"`+code+`"}`)
	}
	for _, tc := range []struct {
		name    string
		refresh func(http.ResponseWriter, *http.Request)
		code    func(http.ResponseWriter, *http.Request)
		want    ProbeResult
		detail  string
		wantErr bool
		mutate  func(*Settings)
	}{
		{"refresh accepted without secret", ok, nil, ProbeAccepted, "", false, func(s *Settings) { s.ClientSecret = "" }},
		{"refresh answer unreadable", notJSON, nil, ProbeInconclusive, "", true, nil},
		{"refresh unauthorized", writeToken(http.StatusUnauthorized, ``), nil, ProbeRejected, "invalid_client", false, nil},
		{"refresh grant invalid", oauth("invalid_grant"), nil, ProbeAccepted, "invalid_grant", false, nil},
		{"code accepted", oauth("unsupported_grant_type"), ok, ProbeAccepted, "unsupported_grant_type", false, nil},
		{"code grant invalid", oauth("unsupported_grant_type"), oauth("invalid_grant"), ProbeAccepted, "unsupported_grant_type, invalid_grant", false, nil},
		{"code unknown error", writeToken(http.StatusBadRequest, ``), oauth("server_error"), ProbeInconclusive, "unknown_error, server_error", false, nil},
		{"code answer unreadable", oauth("unsupported_grant_type"), notJSON, ProbeInconclusive, "unsupported_grant_type", false, nil},
		{"post auth", oauth("invalid_grant"), nil, ProbeAccepted, "invalid_grant", false, func(s *Settings) { s.TokenAuthMethod = AuthMethodPost }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newStubIdP(t)
			idp.token = byGrant(map[string]func(http.ResponseWriter, *http.Request){"refresh_token": tc.refresh, "authorization_code": tc.code})
			got, detail, err := idp.client(t, tc.mutate).ProbeClientAuth(context.Background(), "https://prairie.example/callback")
			if got != tc.want || detail != tc.detail || (err != nil) != tc.wantErr {
				t.Fatalf("probe = %v %q %v; want %v %q err=%v", got, detail, err, tc.want, tc.detail, tc.wantErr)
			}
		})
	}
}

func TestTokenServerFailureIsUnavailable(t *testing.T) {
	t.Parallel()
	idp := newStubIdP(t)
	idp.token = writeToken(http.StatusBadGateway, ``)
	if _, _, err := idp.client(t, nil).ProbeClientAuth(context.Background(), "https://prairie.example/cb"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestEndpointsFailWhenDiscoveryFails(t *testing.T) {
	t.Parallel()
	for status, want := range map[int]error{http.StatusServiceUnavailable: ErrUnavailable, http.StatusNotFound: ErrConfig} {
		idp := newStubIdP(t)
		idp.noDiscovery = status
		c := idp.client(t, nil)
		ctx := context.Background()
		if _, err := c.JWKS(ctx, false); !errors.Is(err, want) {
			t.Errorf("JWKS err = %v, want %v", err, want)
		}
		if _, err := c.UserInfo(ctx, "tok", "sub"); !errors.Is(err, want) {
			t.Errorf("UserInfo err = %v, want %v", err, want)
		}
		if _, _, err := c.ProbeClientAuth(ctx, "https://prairie.example/cb"); err == nil {
			t.Error("probe must fail when discovery fails")
		}
		if _, err := c.VerifyIDToken(ctx, idp.sign(t, `{}`), Expectations{}); err == nil {
			t.Error("verification must fail when discovery fails")
		}
	}
}

func TestDiscoveryAndJWKSBodyErrors(t *testing.T) {
	t.Parallel()
	idp := newStubIdP(t)
	idp.jwks = func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{not json`)) }
	if _, err := idp.client(t, nil).JWKS(context.Background(), false); !errors.Is(err, ErrConfig) {
		t.Fatalf("bad JWKS body err = %v", err)
	}
	if err := idp.client(t, nil).getJSON(context.Background(), "https://bad host\x7f/", &struct{}{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("bad URL err = %v", err)
	}
}

func TestUserInfoVariants(t *testing.T) {
	t.Parallel()
	idp := newStubIdP(t)
	idp.discovery = func(d *Discovery) { d.UserinfoEndpoint = "" }
	if claims, err := idp.client(t, nil).UserInfo(context.Background(), "tok", "sub"); claims != nil || err != nil {
		t.Fatalf("no endpoint = %v, %v", claims, err)
	}

	idp = newStubIdP(t)
	idp.userinfo = writeToken(http.StatusOK, `garbage`)
	if _, err := idp.client(t, nil).UserInfo(context.Background(), "tok", "sub"); !errors.Is(err, ErrConfig) {
		t.Fatalf("unreadable userinfo err = %v", err)
	}

	signed := func(payload string) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/jwt")
			_, _ = w.Write([]byte(idp.sign(t, payload)))
		}
	}
	for name, tc := range map[string]struct {
		payload string
		wantErr error
	}{
		"valid":          {`{"sub":"u1"}`, nil},
		"wrong issuer":   {`{"sub":"u1","iss":"https://other.example"}`, ErrInvalidToken},
		"wrong audience": {`{"sub":"u1","aud":"someone-else"}`, ErrInvalidToken},
		"not an object":  {`[1,2]`, ErrInvalidToken},
	} {
		idp.userinfo = signed(tc.payload)
		claims, err := idp.client(t, nil).UserInfo(context.Background(), "tok", "u1")
		if tc.wantErr == nil && (err != nil || claims["sub"] != "u1") {
			t.Errorf("%s: %v %v", name, claims, err)
		}
		if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.wantErr)
		}
	}
}

func TestVerifyIDTokenKeySelection(t *testing.T) {
	t.Parallel()
	idp := newStubIdP(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// None of these may be used to verify, and none may break verification.
	idp.extraKeys = []jose.JSONWebKey{
		{Key: &other.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "enc"},
		{Key: &other.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		{Key: other, KeyID: "k1", Algorithm: "ES256", Use: "sig"},
	}
	c := idp.client(t, nil)
	if _, err := c.VerifyIDToken(context.Background(), "", Expectations{}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("empty token err = %v", err)
	}
	if _, err := c.VerifyIDToken(context.Background(), "abc", Expectations{}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("garbage token err = %v", err)
	}
	if _, err := c.VerifyIDToken(context.Background(), idp.sign(t, `[1]`), Expectations{}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("non-object payload err = %v", err)
	}
	if _, err := UnverifiedClaims("abc"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("UnverifiedClaims err = %v", err)
	}
}

func TestTokenParsingHelpers(t *testing.T) {
	t.Parallel()
	if got, ok := numericDate(json.Number("12.5")); !ok || got.Unix() != 12 {
		t.Fatalf("json.Number date = %v, %v", got, ok)
	}
	if _, ok := numericDate(json.Number("x")); ok {
		t.Fatal("a non-numeric json.Number is not a date")
	}
	if _, ok := numericDate("12"); ok {
		t.Fatal("a string is not a date")
	}
	if !jwtExpiry("a.!!!.c").IsZero() {
		t.Fatal("bad base64 payload must give no expiry")
	}
	if !jwtExpiry("a." + base64.RawURLEncoding.EncodeToString([]byte("nope")) + ".c").IsZero() {
		t.Fatal("bad JSON payload must give no expiry")
	}
	if _, err := decodeClaims([]byte("[1]")); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("decodeClaims err = %v", err)
	}
	if got, err := RandomToken(8); err != nil || got == "" {
		t.Fatalf("RandomToken = %q, %v", got, err)
	}
}
