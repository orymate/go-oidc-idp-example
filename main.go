package main

import (
	"crypto/rand"
	"log/slog"
	"net/http"

	"github.com/rokoucha/go-oidc-idp-example/lib/codestore"
	"github.com/rokoucha/go-oidc-idp-example/lib/keychain"
	"github.com/rokoucha/go-oidc-idp-example/lib/oidc"
	"github.com/rokoucha/go-oidc-idp-example/lib/routes"
	"github.com/rokoucha/go-oidc-idp-example/lib/session"
	"github.com/rokoucha/go-oidc-idp-example/lib/user"
)

func main() {
	salt := make([]byte, 64)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}

	k := keychain.New()
	o, err := oidc.New(oidc.Config{
		BaseUrl: "http://localhost:8080",
		Clients: []oidc.Client{
			{
				Id:          "test",
				Name:        "Test",
				RedirectUri: "http://localhost:8080",
			},
		},
		Keychain: k,
	})
	if err != nil {
		panic(err)
	}
	s := session.New()
	c := codestore.New()
	u := user.New(salt)
	err = u.Register("test", "test", user.RoleAdmin)
	if err != nil {
		panic(err)
	}

	r := routes.New(routes.Config{
		Oidc:      o,
		Session:   s,
		User:      u,
		CodeStore: c,
	})
	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(res, req)
			return
		}
		r.Index(res, req)
	})
	http.HandleFunc("/.well-known/openid-configuration", r.WellKnownOpenIdConfiguration)
	http.HandleFunc("/login", r.Login)
	http.HandleFunc("/logout", r.Logout)
	http.HandleFunc("/oidc/auth", r.OidcAuth)
	http.HandleFunc("/oidc/jwks", r.OidcJwks)
	http.HandleFunc("/token", r.OidcToken)
	http.HandleFunc("/register", r.Register)

	slog.Info("Listening on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
