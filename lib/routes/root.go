package routes

import (
	"net/http"

	"github.com/rokoucha/go-oidc-idp-example/lib/user"
)

func (r *Routes) Index(res http.ResponseWriter, req *http.Request) {
	user, _ := r.getUserFromSession(req)

	r.template.ExecuteTemplate(res, "index.html", struct{ Username string }{Username: user.Username})
}

func (r *Routes) Login(res http.ResponseWriter, req *http.Request) {
	_, err := r.getUserFromSession(req)
	if err == nil {
		http.Redirect(res, req, "/", http.StatusFound)
		return
	}

	switch req.Method {
	case "GET":
		r.template.ExecuteTemplate(res, "login.html", nil)
		return

	case "POST":
		req.ParseForm()
		username := req.Form.Get("username")
		password := req.Form.Get("password")

		user, ok := r.user.Authenticate(username, password)
		if !ok {
			res.WriteHeader(http.StatusUnauthorized)
			r.template.ExecuteTemplate(res, "login.html", struct{ Message string }{Message: "Invalid username or password"})
			return
		}

		sessionId := r.session.Create(user.ID)
		http.SetCookie(res, &http.Cookie{
			Name:   "session",
			Value:  sessionId,
			MaxAge: 60 * 60 * 24 * 7,
		})

		http.Redirect(res, req, "/", http.StatusFound)
		return

	default:
		res.WriteHeader(http.StatusMethodNotAllowed)
		r.template.ExecuteTemplate(res, "login.html", nil)
		return
	}
}

func (r *Routes) Logout(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		res.WriteHeader(http.StatusMethodNotAllowed)
		r.template.ExecuteTemplate(res, "logout_failed.html", nil)
		return
	}

	session, err := req.Cookie("session")
	if err != nil {
		res.WriteHeader(http.StatusBadRequest)
		r.template.ExecuteTemplate(res, "logout_failed.html", nil)
		return
	}

	r.session.Delete(session.Value)
	http.SetCookie(res, &http.Cookie{
		MaxAge: -1,
		Name:   "session",
	})

	http.Redirect(res, req, "/", http.StatusFound)
}

func (r *Routes) Register(res http.ResponseWriter, req *http.Request) {
	_, err := r.getUserFromSession(req)
	if err == nil {
		http.Redirect(res, req, "/", http.StatusFound)
		return
	}

	switch req.Method {
	case "GET":
		r.template.ExecuteTemplate(res, "register.html", nil)
		return

	case "POST":
		req.ParseForm()
		username := req.Form.Get("username")
		email := req.Form.Get("email")
		password := req.Form.Get("password")
		passwordConfirm := req.Form.Get("password_confirm")
		if password != passwordConfirm {
			res.WriteHeader(http.StatusBadRequest)
			r.template.ExecuteTemplate(res, "register.html", struct{ Message string }{Message: "Passwords do not match"})
			return
		}

		err := r.user.Register(username, password, []string{user.RoleUser}, email)
		if err != nil {
			res.WriteHeader(http.StatusBadRequest)
			r.template.ExecuteTemplate(res, "register.html", struct{ Message string }{Message: err.Error()})
		}

		res.WriteHeader(http.StatusCreated)
		r.template.ExecuteTemplate(res, "register_success.html", nil)

		return

	default:
		res.WriteHeader(http.StatusMethodNotAllowed)
		r.template.ExecuteTemplate(res, "register.html", nil)
		return
	}
}
