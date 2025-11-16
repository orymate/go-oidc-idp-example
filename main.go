package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/rokoucha/go-oidc-idp-example/lib/codestore"
	"github.com/rokoucha/go-oidc-idp-example/lib/keychain"
	"github.com/rokoucha/go-oidc-idp-example/lib/oidc"
	"github.com/rokoucha/go-oidc-idp-example/lib/routes"
	"github.com/rokoucha/go-oidc-idp-example/lib/session"
	"github.com/rokoucha/go-oidc-idp-example/lib/user"
)

type config struct {
	Clients   []oidc.Client   `json:"clients"`
	Users     []user.UserInfo `json:"users"`
	BaseUrl   string          `json:"baseUrl"`
	UsersFile string          `json:"usersFile"`
}

func LoadConfig(path string) (cfg config, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	err = json.Unmarshal(data, &cfg)
	return
}

func main() {
	configPath := os.Getenv("CONFIG")
	if configPath == "" {
		configPath = "config.json"
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		fmt.Printf("failed to load config from %q: %v\n", configPath, err)
		os.Exit(1)
	}

	fmt.Printf("config: %#v\n\n", cfg)

	oidcConfig := oidc.Config{
		BaseUrl:  cfg.BaseUrl,
		Clients:  cfg.Clients,
		Keychain: keychain.New(),
	}

	o, err := oidc.New(oidcConfig)
	if err != nil {
		panic(err)
	}
	s := session.New()
	c := codestore.New()
	u := user.New(cfg.Users, cfg.UsersFile)
	if err := u.LoadUsers(); err != nil {
		fmt.Printf("failed to load users: %v\n", err)
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
