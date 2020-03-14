package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/jr0d/konvoy-async-auth/pkg/kaal"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

// RoundTripFunc .
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip .
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

//NewTestClient returns *http.Client with Transport replaced to avoid making real calls
func NewTestClient(fn RoundTripFunc) *http.Client {
	return &http.Client{
		Transport: RoundTripFunc(fn),
	}
}

func buildHandler(res *http.Response) RoundTripFunc {
	return func(r *http.Request) *http.Response {
		return res
	}
}

func TestInit(t *testing.T) {
	initBody := kaal.InitAsyncOIDCResponse{
		AuthURL: "https://1.1.1.1/dex/auth?state=12345",
		Hmac:  "ABCDEF",
		HmacTTL: 300,
	}

	data, err := json.Marshal(initBody)
	if err != nil {
		t.Errorf("could not marshal object: %v", err)
	}

	resp := &http.Response{
		StatusCode:       201,
		Header:           http.Header{
			"Content-type": []string{"application/json"},
		},
		Body:             ioutil.NopCloser(bytes.NewReader(data)),
		ContentLength:    int64(len(data)),
	}

	f := buildHandler(resp)

	c := NewTestClient(f)

	k := KonvoyAsyncAuthClient{
		AuthURI:    "https://1.1.1.1/token",
		HTTPClient: c,
	}

	if err := k.Initialize(); err != nil {
		t.Errorf("error running initializae: %v", err)
	}
}

func TestInitBadStatus(t *testing.T) {
	resp := &http.Response{StatusCode: 500, Body: ioutil.NopCloser(strings.NewReader("ERROR"))}

	f := buildHandler(resp)
	c := NewTestClient(f)

	k := KonvoyAsyncAuthClient{
		AuthURI: "https://1.1.1.1/token",
		HTTPClient: c,
	}

	err := k.Initialize()

	if err == nil {
		t.Errorf("error not raised for bad status")
	}

	if err != nil && err.Error() != "server responded with invalid status: 500, body: ERROR" {
		t.Errorf("incorrect error messeage: actual: %s", err.Error())
	}
}

func TestJoin(t *testing.T) {
	k := KonvoyAsyncAuthClient{AuthURI: "https://1.1.1.1/token"}
	s := k.join(kaal.AuthEndpoint)
	fmt.Printf("%s\n", s)

	expected := "https://1.1.1.1/token/async/auth"
	if s != expected {
		t.Errorf("expected: %s, actual: %s", expected, s)
	}
}
