package routes

import (
	"errors"
	"html/template"
	"net/http"

	"github.com/rokoucha/go-oidc-idp-example/lib/codestore"
	"github.com/rokoucha/go-oidc-idp-example/lib/oidc"
	"github.com/rokoucha/go-oidc-idp-example/lib/session"
	"github.com/rokoucha/go-oidc-idp-example/lib/user"
)

type Config struct {
	Oidc      *oidc.Oidc
	Session   *session.Session
	User      *user.User
	CodeStore *codestore.CodeStore
}

type Routes struct {
	oidc     *oidc.Oidc
	session  *session.Session
	template *template.Template
	user     *user.User
	store    *codestore.CodeStore
}

func New(config Config) *Routes {
	return &Routes{
		oidc:     config.Oidc,
		session:  config.Session,
		template: template.Must(template.ParseGlob("templates/*.html")),
		user:     config.User,
		store:    config.CodeStore,
	}
}

func (r *Routes) getUserFromSession(req *http.Request) (user.UserInfo, error) {
	sessionId, err := req.Cookie("session")
	if err != nil {
		return user.UserInfo{}, err
	}

	userId, err := r.session.Get(sessionId.Value)
	if err != nil {
		return user.UserInfo{}, err
	}

	u, ok := r.user.Get(userId)
	if !ok {
		return user.UserInfo{}, errors.New("user not found")
	}

	return u, nil
}
