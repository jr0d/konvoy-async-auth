package client

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/pkg/browser"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	// "golang.org/x/oauth2"

	"github.com/jr0d/konvoy-async-auth/pkg/kaal"
)

const (
	requestCodeLength = 12
)

type clientState struct {
	authUrl string
	Hmac	string
	HmacTTL int64
	requestCode string
}
type KonvoyAsyncAuthClient struct {
	AuthURI    string
	HTTPClient *http.Client
	NoBrowser  bool
	state clientState

	QueryTimeout uint
	QueryInterval uint
}

func New(authURI string, CAfile string, CAData []byte) (*KonvoyAsyncAuthClient, error) {
	client := KonvoyAsyncAuthClient{
		AuthURI: authURI,
	}

	certPool, err := x509.SystemCertPool()
	if err != nil {
		certPool = x509.NewCertPool()
	}

	if len(CAfile) > 1 {
		pem, err := ioutil.ReadFile(CAfile)
		if err != nil {
			return nil, fmt.Errorf("error reading %s: %w", CAfile, err)
		}
		certPool.AppendCertsFromPEM(pem)
	}

	if CAData != nil || len(CAData) > 1 {
		certPool.AppendCertsFromPEM(CAData)
	}

	tr := http.Transport{TLSClientConfig: &tls.Config{RootCAs: certPool}}

	client.HTTPClient = &http.Client{Transport: &tr}

	return &client, nil
}

func (k *KonvoyAsyncAuthClient) Initialize() error {
	code, err := generateRequestCode()
	if err != nil {
		return fmt.Errorf("rng error: %w", err)
	}

	initRequest := &kaal.InitAsyncOIDCRequest{RequestCode: code}

	data, err := json.Marshal(initRequest)
	if err != nil {
		return fmt.Errorf("error marshelling initReq: %w", err)
	}

	response := &kaal.InitAsyncOIDCResponse{}
	resp, err := k.HTTPClient.Post(k.join(kaal.InitEndpoint), "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("error initializing asynchronous workflow: %w", err)
	}
	if resp.StatusCode != 201 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("server responded with invalid status: %d, body: %s", resp.StatusCode, body)
	}

	if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
		return fmt.Errorf("failed to parse server response")
	}


	k.state = clientState{
		authUrl:     response.AuthURL,
		Hmac:        response.Hmac,
		HmacTTL:     response.HmacTTL,
		requestCode: code,
	}
	return nil
}

func (k *KonvoyAsyncAuthClient) Start() error {
	if !k.NoBrowser {
		if err := browser.OpenURL(k.state.authUrl); err == nil {
			return err
		}
	}
	fmt.Printf("Auth URL: %s\n", k.state.authUrl)
	return nil
}

func (k *KonvoyAsyncAuthClient) Query() (string, error) {
	req := fmt.Sprintf("%s?hmac=%s&requestCode=%s",
		k.join(kaal.QueryEndpoint), k.state.Hmac, k.state.requestCode)
	tokenResponse := kaal.QueryAsyncOIDCResponse{}
	start := time.Now().Unix()
	for time.Now().Unix() - start < int64(k.QueryTimeout) {
		res, err := k.HTTPClient.Get(req)
		if err != nil {
			return "", fmt.Errorf("error accessing query endpoint: %w", err)
		}
		if err := json.NewDecoder(res.Body).Decode(&tokenResponse); err != nil {
			return "", fmt.Errorf("error decoding response: %w", err)
		}
		if tokenResponse.Ready {
			return tokenResponse.Token, nil
		}
		time.Sleep(time.Duration(k.QueryInterval) * time.Second)
	}
	return "", nil
}

func (k *KonvoyAsyncAuthClient) join(endpoint string) string {
	return fmt.Sprintf("%s/%s", strings.TrimSuffix(k.AuthURI, "/"), strings.TrimPrefix(endpoint, "/"))
}

func generateRequestCode() (string, error) {
	code := make([]byte, requestCodeLength)
	_, err := rand.Read(code)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", code), nil
}
