package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"golang.org/x/oauth2"
	"os"

	oidc "github.com/coreos/go-oidc"
)

const AuthCode = "vvc3geziiitgt5tm6whli7jun"


func main() {
	issuer := flag.String("issuer-url", "", "URL of the OIDC issuer")
	caFile := flag.String("ca-file", "", "CA certificate to validate issuer")
	clientID := flag.String("client-id", "", "OAuth2 ClientID")
	clientSecret := flag.String("client-secret", "", "OAuth2 Client Secret")
	redirectURL := flag.String("redirect-url", "", "Redirect URL")

	flag.Parse()

	fmt.Printf("issuer: %s\n", *issuer)

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

	fmt.Println("AuthURL: ", provider.Endpoint().AuthURL)
	fmt.Printf("%v\n", oauth2Config)

	state, err := Nonce()
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("AuthCode URL: %s\n", oauth2Config.AuthCodeURL(state))

	token, err := oauth2Config.Exchange(context.Background(), AuthCode)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%v\n", *token)
}

func Nonce() (string, error) {
	// Make nonce
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", nonce), err
}