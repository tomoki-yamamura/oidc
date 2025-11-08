package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var (
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
	store        *sessions.CookieStore
)

func init() {
	ctx := context.Background()

	// Google OIDC Provider
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		log.Fatal(err)
	}

	// OAuth2 Config
	oauth2Config = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8080/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}

	// ID Token Verifier
	verifier = provider.Verifier(&oidc.Config{
		ClientID: oauth2Config.ClientID,
	})

	// Session Store
	store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))
}

func randomString() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func saveToSession(w http.ResponseWriter, r *http.Request, key, value string) {
	session, _ := store.Get(r, "oidc-session")
	session.Values[key] = value
	session.Save(r, w)
}

func loadFromSession(r *http.Request, key string) string {
	session, _ := store.Get(r, "oidc-session")
	if val, ok := session.Values[key].(string); ok {
		return val
	}
	return ""
}

func createAppSession(w http.ResponseWriter, r *http.Request, userID, email string) {
	session, _ := store.Get(r, "app-session")
	session.Values["user_id"] = userID
	session.Values["email"] = email
	session.Save(r, w)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	state := randomString()
	nonce := randomString()

	// S -> S: state, nonce を生成して保存
	saveToSession(w, r, "state", state)
	saveToSession(w, r, "nonce", nonce)

	// S -> B: 302 Redirect to Google ...
	url := oauth2Config.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
	)
	http.Redirect(w, r, url, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// S -> S: stateを検証
	gotState := r.URL.Query().Get("state")
	wantState := loadFromSession(r, "state")
	if gotState == "" || gotState != wantState {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")

	// S -> G: POST Token Endpoint
	oauth2Token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// G -> S: {access_token, id_token} をもらった後
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token found", http.StatusInternalServerError)
		return
	}

	// IDトークン検証
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var claims struct {
		Email string `json:"email"`
		Nonce string `json:"nonce"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to parse claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// S -> S: nonceを検証
	wantNonce := loadFromSession(r, "nonce")
	if claims.Nonce != wantNonce {
		http.Error(w, "nonce mismatch", http.StatusBadRequest)
		return
	}

	userID := idToken.Subject
	email := claims.Email

	// アプリ用のセッションを作る
	createAppSession(w, r, userID, email)

	// トップページにリダイレクト
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "app-session")
	userID, ok := session.Values["user_id"].(string)
	if !ok {
		fmt.Fprintf(w, `<h1>Welcome to OIDC Demo</h1><a href="/login">Login with Google</a>`)
		return
	}

	email := session.Values["email"].(string)
	fmt.Fprintf(w, `<h1>Hello %s</h1><p>User ID: %s</p><a href="/logout">Logout</a>`, email, userID)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "app-session")
	session.Values = make(map[interface{}]interface{})
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/logout", handleLogout)

	fmt.Println("Server starting on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}