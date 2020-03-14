package server

import (
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/jr0d/konvoy-async-auth/pkg/kaal"
	"github.com/jr0d/konvoy-async-auth/pkg/kaal/server/storage/memory"
	"golang.org/x/oauth2"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestKonvoyAsyncAuthServer_AsyncInit(t *testing.T) {
	storage := memory.New()
	s := KonvoyAsyncAuthServer{
		Quiet: false,
		OAuth2Config: &oauth2.Config{
			ClientID:     "my-client",
			ClientSecret: "secret",
			RedirectURL: "https://example.com/token/async/auth/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:   "https://example.com/dex/auth",
				TokenURL:  "https://example.com/dex/token",
				AuthStyle: 0,
			},
			Scopes: []string{oidc.ScopeOpenID, "offline_access", "profile", "email", "groups"},
		},
		HmacTTL:    300,
		HmacSecret: []byte("secret"),
		Storage:    &storage,
	}

	w := httptest.NewRecorder()

	body := `{
  "requestCode": "12345"
}`
	req := httptest.NewRequest("POST", kaal.InitEndpoint, strings.NewReader(body))
	s.AsyncInit(w, req)

	if w.Code != 201 {
		t.Errorf("incorrect status: %d", w.Code)
	}

	response := &kaal.InitAsyncOIDCResponse{}
	if err := json.NewDecoder(w.Body).Decode(response); err != nil {
		t.Errorf("could not parse body")
	}
	if !strings.HasPrefix(response.AuthURL, "https://example.com/dex/auth") {
		t.Errorf("wrong auth URL")
	}

	et, ok, err := storage.Get(response.Hmac)
	if err != nil || !ok {
		t.Fatalf("could not retrieve ephemeral token: err: %v, ok: %v", err, ok)

	}
	if et.RequestCode != "12345" {
		t.Errorf("request code is incorrect: actual: %s, expected: 12345", et.RequestCode)
	}
}

// Find a way to unit test token Exchange
//func TestKonvoyAsyncAuthServer_AuthCallback(t *testing.T) {
//	storage := memory.New()
//	s := KonvoyAsyncAuthServer{
//		Quiet: false,
//		OAuth2Config: &oauth2.Config{
//			ClientID:     "my-client",
//			ClientSecret: "secret",
//			RedirectURL: "https://example.com/token/async/auth/callback",
//			Endpoint: oauth2.Endpoint{
//				AuthURL:   "https://example.com/dex/auth",
//				TokenURL:  "https://example.com/dex/token",
//				AuthStyle: 0,
//			},
//			Scopes: []string{oidc.ScopeOpenID, "offline_access", "profile", "email", "groups"},
//		},
//		HmacTTL:    300,
//		HmacSecret: []byte("secret"),
//		Storage:    &storage,
//	}
//
//	w := httptest.NewRecorder()
//
//	mac := s.GenerateHMAC(time.Now().Unix())
//	requestCode := "ABCDEF"
//	_ = storage.Create(mac, requestCode, s.HmacTTL)
//
//	req := httptest.NewRequest("GET",
//		fmt.Sprintf("https://example.com/token/autht/callback?code=XXXXX&state=%s", mac), nil)
//
//	s.AuthCallback(w, req)
//
//	fmt.Printf("%v\n", w)
//	x, ok, err := storage.Get(mac)
//	if !ok || err != nil {
//		t.Errorf("could not get token storage: err: %v, ok: %v", err, ok)
//	}
//	fmt.Printf("%v\n", x)
//}

func TestKonvoyAsyncAuthServer_Query(t *testing.T) {
	storage := memory.New()
	s := KonvoyAsyncAuthServer{
		Quiet: false,
		OAuth2Config: &oauth2.Config{
			ClientID:     "my-client",
			ClientSecret: "secret",
			RedirectURL: "https://example.com/token/async/auth/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:   "https://example.com/dex/auth",
				TokenURL:  "https://example.com/dex/token",
				AuthStyle: 0,
			},
			Scopes: []string{oidc.ScopeOpenID, "offline_access", "profile", "email", "groups"},
		},
		HmacTTL:    300,
		HmacSecret: []byte("secret"),
		Storage:    &storage,
	}

	w := httptest.NewRecorder()

	token := "XXXXX"
	hmac := s.GenerateHMAC(time.Now().Unix())
	_ = storage.Create(hmac, "ABCDEF", 300)
	req := httptest.NewRequest(
		"GET", fmt.Sprintf("https://example.com/async/query?hmac=%s&requestCode=ABCDEF", hmac), nil)

	s.Query(w, req)

	response := kaal.QueryAsyncOIDCResponse{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Errorf("json parsing error: %v", err)
	}

	if response.Ready {
		t.Errorf("token not saved, ready should be false")
	}

	// write the token an try again
	_ = storage.Save(hmac, token)

	s.Query(w, req)

	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Errorf("json parsing error: %v", err)
	}

	if !response.Ready {
		t.Errorf("token save, ready should be true")
	}

	if token != response.Token {
		t.Errorf("token mismatch: expected %s, actual: %s", token, response.Token)
	}
}