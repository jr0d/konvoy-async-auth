package main

import (
	"context"
	"flag"
	"github.com/coreos/go-oidc"
	"github.com/jr0d/konvoy-async-auth/pkg/kaal/server"
	"github.com/jr0d/konvoy-async-auth/pkg/kaal/server/storage/memory"
	"golang.org/x/oauth2"
	"net/http"
	"os"
)

const (
	SECRET = "123456789"
)

func main() {
	issuer := flag.String("issuer-url", "", "URL of the OIDC issuer")
	caFile := flag.String("ca-file", "", "CA certificate to validate issuer")
	clientID := flag.String("client-id", "", "OAuth2 ClientID")
	clientSecret := flag.String("client-secret", "", "OAuth2 Client Secret")
	redirectURL := flag.String("redirect-url", "", "Redirect URL")

	flag.Parse()

		if len(*caFile) > 0 {
		if err := os.Setenv("SSL_CERT_FILE", *caFile); err != nil {

		}
	}

	provider, err := oidc.NewProvider(context.Background(), *issuer)
	if err != nil {
		panic(err.Error())
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		RedirectURL:  *redirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "offline_access", "profile", "email", "groups"},
	}
	storage := memory.New()
	s := server.KonvoyAsyncAuthServer{
		Quiet:        false,
		OAuth2Config: &oauth2Config,
		HmacTTL:      3600,
		HmacSecret:   []byte(SECRET),
		Storage:      &storage,
	}

	http.HandleFunc("/async", s.AsyncInit)
	http.HandleFunc("/async/callback", s.AuthCallback)
	http.HandleFunc("/async/query", s.Query)

	_ = http.ListenAndServe(":8080", nil)
}
