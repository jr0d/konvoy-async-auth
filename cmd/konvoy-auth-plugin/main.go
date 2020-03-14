package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/jr0d/konvoy-async-auth/pkg/kaal/client"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

const (
	queryTimeout = 300
	queryInterval = 2
)

var (
	authURL        string
	kubeconfigUser string
	noBrowserExec  bool
	tokenDir       string
	tokenPath 	   string
	caFile		   string
)

// {
//  "apiVersion": "client.authentication.k8s.io/v1beta1",
//  "kind": "ExecCredential",
//  "status": {
//    "token": "my-bearer-token"
//  }
//}

type TokenStatus struct {
	Token string `json:"token"`
}

type TokenOutput struct {
	APIVersion string `json:"apiVersion"`
	Kind string `json:"kind"`
	Status TokenStatus `json:"status"`
}

func main() {
	httpClient, err := getHTTPClient(caFile)
	if err != nil {
		bail("failed to get HTTP client", 1)
	}
	asyncClient := client.KonvoyAsyncAuthClient{
		AuthURI:      authURL,
		HTTPClient:   httpClient,
		NoBrowser:    noBrowserExec,
		QueryTimeout: queryTimeout,
		QueryInterval: queryInterval,
	}


	if tokenExists() {
		// check token expiry
		// test token (through provider, or helper)
		// return token
		data, err := ioutil.ReadFile(tokenPath)
		if err != nil {
			bail("could not read token", 1)
		}
		tokenOutput := &TokenOutput{}
		if err := json.Unmarshal(data, tokenOutput); err != nil {
			bail(fmt.Sprintf("failed to parse token: %s\n", tokenPath), 1)
		}
		fmt.Print(string(data))
		os.Exit(0)
	}

	if err := asyncClient.Initialize(); err != nil {
		bail(fmt.Sprintf("error initializing: %v", err), 1)
	}

	// start oidc flow

	if err := asyncClient.Start(); err != nil {
		bail(fmt.Sprintf("failed to start oidc flow: %v", err), 1)
	}
	// get token or fail
	token, err := asyncClient.Query()
	if err != nil {
		bail(fmt.Sprintf("query failed: %v", err), 1)
	}
	if token == "" {
		bail("timeout...", 1)
	}
	// test token
	// write token

	tokenOutput := &TokenOutput{
		APIVersion: "client.authentication.k8s.io/v1beta1",
		Kind:       "ExecCredential",
		Status:     TokenStatus{
			Token: token,
		},
	}
	_ = os.MkdirAll(filepath.Join(tokenDir, kubeconfigUser), os.FileMode(0700))

	data, err := json.Marshal(tokenOutput)
	if err != nil {
		bail("could not create token dir", 1)
	}

	if err := ioutil.WriteFile(tokenPath, data, os.FileMode(0600)); err != nil {
		bail(fmt.Sprintf("failed to write token: %s", err), 1)
	}

	fmt.Print(string(data))
}

func init() {
	flag.StringVar(&authURL, "auth-url", "", "The base URL of the async auth controller")
	flag.StringVar(&kubeconfigUser, "kubeconfig-user", "", "Kubeconfig user to associate token with")
	flag.BoolVar(&noBrowserExec, "no-browser-exec", false, "Do not launch a browser window")

	// Read kubeconfig for certificate data?
	flag.StringVar(&caFile, "ca-file", "", "CA certificate file")

	defaultTokenDir := ""
	if home := homeDir(); home != "" {
		defaultTokenDir = filepath.Join(home, ".kube", "konvoy", "tokens")
	}

	flag.StringVar(&tokenDir, "token-dir", defaultTokenDir, "Alternate token directory")

	flag.Parse()

	if tokenDir == "" {
		bail("--token-dir is not defined", 1)
	}

	mode := int(0700)
	err := os.MkdirAll(tokenDir, os.FileMode(mode))
	if err != nil {
		bail(fmt.Sprintf("Could not create token directory: %v\n", err), 1)
	}
	tokenPath = filepath.Join(tokenDir, kubeconfigUser, "token")

}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}

func tokenExists() bool {
	stat, err := os.Stat(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		bail(fmt.Sprintf("error getting token file info: %s", err.Error()), 1)
	}
	if stat.IsDir() {
		bail(fmt.Sprintf("token path is a directory: %s\n", tokenPath), 1)
	}
	return true
}

//func generateRequestCode() string {
//	code := make([]byte, requestCodeLength)
//	_, err := rand.Read(code)
//	if err != nil {
//		bail("rng error", 99)
//	}
//	return fmt.Sprintf("%x", code)
//}

func bail(msg string, code uint) {
	fmt.Println(msg)
	os.Exit(1)
}

func getHTTPClient(caFile string) (*http.Client, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		certPool = x509.NewCertPool()
	}

	if len(caFile) > 1 {
		pem, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("error reading %s: %w", caFile, err)
		}
		certPool.AppendCertsFromPEM(pem)
	}
	tr := http.Transport{TLSClientConfig: &tls.Config{RootCAs: certPool}}

	c := &http.Client{Transport: &tr}

	return c, nil
}