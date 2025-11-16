package routes

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-jose/go-jose/v3"
	"github.com/rokoucha/go-oidc-idp-example/lib/oidc"
)

func (r *Routes) WellKnownOpenIdConfiguration(res http.ResponseWriter, req *http.Request) {
	json, err := json.Marshal(r.oidc.GetOpenIDProviderMetadata())
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	res.Write(json)
	return
}

func (r *Routes) OidcAuth(res http.ResponseWriter, req *http.Request) {
	var authReq oidc.AuthenticationRequest
	switch req.Method {
	case "GET":
		authReq = oidc.AuthenticationRequest{
			Scope:        req.URL.Query().Get("scope"),
			ResponseType: req.URL.Query().Get("response_type"),
			ClientID:     req.URL.Query().Get("client_id"),
			RedirectUri:  req.URL.Query().Get("redirect_uri"),
			Nonce:        req.URL.Query().Get("nonce"),
			State:        req.URL.Query().Get("state"),
		}
	case "POST":
		err := req.ParseForm()
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		authReq = oidc.AuthenticationRequest{
			Scope:        req.Form.Get("scope"),
			ResponseType: req.Form.Get("response_type"),
			ClientID:     req.Form.Get("client_id"),
			RedirectUri:  req.Form.Get("redirect_uri"),
			Nonce:        req.Form.Get("nonce"),
			State:        req.Form.Get("state"),
		}
	default:
		http.Redirect(res, req, fmt.Sprintf("%s?error=invalid_request&error_description=method not allowed", authReq.RedirectUri), http.StatusFound)
		return
	}

	fmt.Printf("%#v\n", authReq)

	err := r.oidc.ValidateAuthenticationRequest(authReq)
	if err != nil {
		http.Redirect(res, req, fmt.Sprintf("%s?error=%s", authReq.RedirectUri, err.Error()), http.StatusFound)
		return
	}

	user, err := r.getUserFromSession(req)
	if err != nil {
		http.Redirect(res, req, fmt.Sprintf("%s?error=login_required", authReq.RedirectUri), http.StatusFound)
		return
	}

	idToken, err := r.oidc.GenerateIDToken(user, authReq.ClientID, authReq.Nonce)
	if err != nil {
		http.Redirect(res, req, fmt.Sprintf("%s?error=server_error", authReq.RedirectUri), http.StatusFound)
		return
	}

	if authReq.ResponseType == "id_token" {
		http.Redirect(res, req, fmt.Sprintf("%s?id_token=%s", authReq.RedirectUri, idToken), http.StatusFound)
		return
	}

	code := r.store.Create(idToken)
	http.Redirect(res, req, fmt.Sprintf("%s?code=%s&state=%s", authReq.RedirectUri, code, authReq.State), http.StatusFound)
}

func (r *Routes) OidcJwks(res http.ResponseWriter, req *http.Request) {
	keys := r.oidc.GetPublicKeys()
	jwks := struct {
		Keys []jose.JSONWebKey `json:"keys"`
	}{Keys: keys}

	json, err := json.Marshal(jwks)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	res.Write(json)
	return
}

func (r *Routes) OidcToken(res http.ResponseWriter, req *http.Request) {
	var tokenRequest oidc.TokenRequest
	switch req.Method {
	case "POST":
		err := req.ParseForm()
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		tokenRequest = oidc.TokenRequest{
			GrantType:    req.Form.Get("grant_type"),
			ClientID:     req.Form.Get("client_id"),
			ClientSecret: req.Form.Get("client_secret"),
			RedirectUri:  req.Form.Get("redirect_uri"),
			Code:         req.Form.Get("code"),
		}
	default:
		res.Header().Add("allow", "POST")
		http.Error(res, "unsupported method (must be POST)", http.StatusMethodNotAllowed)
		return
	}

	fmt.Printf("%#v\n", tokenRequest)

	err := r.oidc.ValidateTokenRequest(tokenRequest)
	if err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	id_token, err := r.store.Pop(tokenRequest.Code)
	if err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	body := struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}{
		IDToken:     id_token,
		AccessToken: "not-used", // TODO ?
		ExpiresIn:   24 * 3600,  // TODO dynamic
		TokenType:   "Bearer",
		//"scope": "photo offline_access",
		//"refresh_token": "vUOknvjU8_Oal1a7j0F5XXD3"
	}

	body_json, err := json.Marshal(body)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	res.Write(body_json)
}
