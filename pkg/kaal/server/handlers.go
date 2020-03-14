package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/jr0d/konvoy-async-auth/pkg/kaal"
	"github.com/jr0d/konvoy-async-auth/pkg/kaal/server/storage"
)

type KonvoyAsyncAuthServer struct {
	// Quiet when true, logging messages will be suppressed
	Quiet bool

	OAuth2Config *oauth2.Config

	HmacTTL    int64
	HmacSecret []byte

	Storage storage.TokenStore
}

func (k *KonvoyAsyncAuthServer) logRequest(req *http.Request, code, n int) {
	log.Printf("%s %s %s %d %d", req.RemoteAddr, req.Method, req.RequestURI, code, n)
}

func (k *KonvoyAsyncAuthServer) logError(err error, req *http.Request, msg string) {
	log.Printf("[error] %s %s %s: %v", req.RemoteAddr, req.RequestURI, msg, err)
}

func (k *KonvoyAsyncAuthServer) handleError(err error, req *http.Request, w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	n, _ := fmt.Fprintln(w, msg)
	if !k.Quiet {
		k.logRequest(req, code, n)
		k.logError(err, req, msg)
	}
}

func (k *KonvoyAsyncAuthServer) AsyncInit(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		k.handleError(nil, req, w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	initReq := &kaal.InitAsyncOIDCRequest{}

	var err error
	if err = json.NewDecoder(req.Body).Decode(initReq); err != nil {
		k.handleError(
			fmt.Errorf("error parsing request json: %w", err),
			req, w, "Bad Request", http.StatusBadRequest)
		return
	}

	mac := k.GenerateHMAC(time.Now().Unix())

	// Create cross referenced storage for token
	if err = k.Storage.Create(mac, initReq.RequestCode, k.HmacTTL); err != nil {
		k.handleError(fmt.Errorf("failed to create token storage: %w", err),
			req, w, "Internal Server Error", http.StatusInternalServerError)
	}

	response := &kaal.InitAsyncOIDCResponse{
		AuthURL: k.OAuth2Config.AuthCodeURL(mac),
		Hmac:    mac,
		HmacTTL: k.HmacTTL,
	}

	entity, err := json.Marshal(response)
	if err != nil {
		k.handleError(fmt.Errorf("could not marshel response: %w", err),
			req, w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	n, err := w.Write(entity)
	if err != nil {
		log.Printf("error writing output stream : %s | %s | %v", req.RemoteAddr, req.RequestURI, err)
		return
	}

	if !k.Quiet {
		k.logRequest(req, http.StatusCreated, n)
	}
}

func (k *KonvoyAsyncAuthServer) AuthCallback(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		k.handleError(nil, req, w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	mac := req.URL.Query().Get("state")
	if len(mac) == 0 {
		k.handleError(fmt.Errorf("state missing from request"),
			req, w, "Bad Request", http.StatusBadRequest)
		return
	}

	if !k.CheckHMAC(mac) {
		k.handleError(fmt.Errorf("HMAC failed validation"),
			req, w, "Unauthorized: HMAC", http.StatusUnauthorized)
		return
	}

	code := req.URL.Query().Get("code")
	if len(code) == 0 {
		k.handleError(fmt.Errorf("auth code is missing from request"),
			req, w, "Bad Request", http.StatusBadRequest)
		return
	}

	token, err := k.OAuth2Config.Exchange(context.Background(), code)
	if err != nil {
		k.handleError(fmt.Errorf("error exchanging code for token: %w", err),
			req, w, "Unauthorized: Token exchange", http.StatusUnauthorized)
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		k.handleError(errors.New("failed to extract token from oauth2 payload"),
			req, w, "Bad Gateway: missing token", http.StatusBadGateway)
	}

	if err = k.Storage.Save(mac, rawIDToken); err != nil {
		k.handleError(fmt.Errorf("error saving token: %w", err),
			req, w, "Internal Server Error", http.StatusInternalServerError)
	}

	w.WriteHeader(200)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	n, _ := w.Write([]byte("OK"))
	k.logRequest(req, 200, n)
}

func (k *KonvoyAsyncAuthServer) Query(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		k.handleError(nil, req, w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	mac := req.URL.Query().Get("hmac")
	if len(mac) == 0 {
		k.handleError(fmt.Errorf("hmac missing from request"),
			req, w, "Bad Request", http.StatusBadRequest)
		return
	}

	if !k.CheckHMAC(mac) {
		k.handleError(fmt.Errorf("HMAC failed validation"),
			req, w, "Unauthorized: HMAC", http.StatusUnauthorized)
		return
	}

	requestCode := req.URL.Query().Get("requestCode")
	if len(requestCode) == 0 {
		k.handleError(fmt.Errorf("request code missing from request"),
			req, w, "Bad Request", http.StatusBadRequest)
		return
	}

	et, ok, err := k.Storage.Get(mac)
	if !ok || err != nil {
		k.handleError(fmt.Errorf("could not find token resource, ok: %v, err: %w", ok, err),
			req, w, "Not Found", http.StatusNotFound)
		return
	}

	if et.RequestCode != requestCode {
		k.handleError(fmt.Errorf("invalid request code recieved"),
			req, w, "Unauthorized: RC", http.StatusUnauthorized)
		return
	}

	now := time.Now().Unix()
	if now-et.CreatedAt > et.TTL {
		_ = k.Storage.Delete(mac)
		k.handleError(nil, req, w, "HMAC expired", http.StatusBadRequest)
		return
	}
	ready := len(et.Token) > 0
	response := &kaal.QueryAsyncOIDCResponse{Token: et.Token, Ready: ready}

	data, err := json.Marshal(response)
	if err != nil {
		k.handleError(err, req, w, "Bad Gateway", http.StatusBadGateway)
	}

	w.WriteHeader(200)
	w.Header().Set("Content-Type", "application/json")
	n, _ := w.Write(data)
	k.logRequest(req, 200, n)

	if ready {
		if !k.Quiet {
			log.Printf("token retrieved, deleting storage for %s", mac)
		}
		_ = k.Storage.Delete(mac)
	}
}

func (k *KonvoyAsyncAuthServer) hmacSignature(timestamp int64) string {
	hash := hmac.New(sha256.New, k.HmacSecret)
	hash.Write([]byte(k.OAuth2Config.RedirectURL))
	hash.Write([]byte(fmt.Sprintf("%d", timestamp)))
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func (k *KonvoyAsyncAuthServer) GenerateHMAC(timestamp int64) string {
	// format hash(secret, redirectURL, unix timestamp).unix timestamp
	return fmt.Sprintf("%s.%d", k.hmacSignature(timestamp), timestamp)
}

func (k *KonvoyAsyncAuthServer) CheckHMAC(target string) bool {
	parts := strings.Split(target, ".")
	if len(parts) != 2 {
		return false
	}

	mac := parts[0]
	tstr := parts[1]

	timestamp, err := strconv.ParseInt(tstr, 10, 64)
	if err != nil {
		return false
	}
	sig := k.hmacSignature(timestamp)
	return sig == mac
}
