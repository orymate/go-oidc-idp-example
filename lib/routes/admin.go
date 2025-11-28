package routes

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/oklog/ulid/v2"
)

func (r *Routes) AdminPanel(res http.ResponseWriter, req *http.Request) {
	user, err := r.getUserFromSession(req)
	if err != nil {
		http.Redirect(res, req, "/login", http.StatusFound)
		return
	}

	if !r.user.IsAdmin(user) {
		http.Error(res, "Forbidden: Admin access required", http.StatusForbidden)
		return
	}

	users, err := r.user.AdminList(user.ID)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	r.template.ExecuteTemplate(res, "admin.html", struct {
		Username string
		Users    any
	}{
		Username: user.Username,
		Users:    users,
	})
}

func (r *Routes) AdminRegister(res http.ResponseWriter, req *http.Request) {
	user, err := r.getUserFromSession(req)
	if err != nil {
		http.Redirect(res, req, "/login", http.StatusFound)
		return
	}

	if !r.user.IsAdmin(user) {
		http.Error(res, "Forbidden: Admin access required", http.StatusForbidden)
		return
	}

	switch req.Method {
	case http.MethodGet:
		r.template.ExecuteTemplate(res, "admin_register.html", struct{ Username string }{Username: user.Username})
		return

	case http.MethodPost:
		req.ParseForm()
		username := req.Form.Get("username")
		email := req.Form.Get("email")
		password := req.Form.Get("password")
		groups := req.Form["groups"]

		if err := r.user.AdminRegister(user.ID, username, password, groups, email); err != nil {
			res.WriteHeader(http.StatusBadRequest)
			r.template.ExecuteTemplate(res, "admin_register.html", struct {
				Username string
				Message  string
			}{
				Username: user.Username,
				Message:  err.Error(),
			})
			return
		}

		if err := r.user.SaveUsers(); err != nil {
			res.WriteHeader(http.StatusInternalServerError)
			r.template.ExecuteTemplate(res, "admin_register.html", struct {
				Username string
				Message  string
			}{
				Username: user.Username,
				Message:  err.Error(),
			})
			return
		}

		slog.Info("admin registered new user", "admin", user.Username, "new_user", username)

		http.Redirect(res, req, "/admin", http.StatusSeeOther)
		return

	default:
		res.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func (r *Routes) AdminDeleteUser(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		res.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	user, err := r.getUserFromSession(req)
	if err != nil {
		http.Error(res, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if !r.user.IsAdmin(user) {
		http.Error(res, "Forbidden: Admin access required", http.StatusForbidden)
		return
	}

	req.ParseForm()
	userId, err := ulid.Parse(req.Form.Get("user_id"))
	if err != nil {
		http.Error(res, "Invalid user ID", http.StatusBadRequest)
		return
	}

	if err := r.user.AdminDelete(user.ID, userId); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	if err := r.user.SaveUsers(); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("admin deleted user", "admin", user.Username, "deleted_user_id", userId.String())

	http.Redirect(res, req, "/admin", http.StatusSeeOther)
}

func (r *Routes) AdminResetPassword(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		res.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	user, err := r.getUserFromSession(req)
	if err != nil {
		http.Error(res, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if !r.user.IsAdmin(user) {
		http.Error(res, "Forbidden: Admin access required", http.StatusForbidden)
		return
	}

	req.ParseForm()
	userId, err := ulid.Parse(req.Form.Get("user_id"))
	if err != nil {
		http.Error(res, "Invalid user ID", http.StatusBadRequest)
		return
	}

	newPassword := req.Form.Get("new_password")
	if newPassword == "" {
		http.Error(res, "New password is required", http.StatusBadRequest)
		return
	}

	if err := r.user.AdminResetPassword(user.ID, userId, newPassword); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	if err := r.user.SaveUsers(); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("admin reset user password", "admin", user.Username, "target_user_id", userId.String())

	http.Redirect(res, req, "/admin", http.StatusSeeOther)
}

func (r *Routes) AdminUsersAPI(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		res.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	user, err := r.getUserFromSession(req)
	if err != nil {
		http.Error(res, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if !r.user.IsAdmin(user) {
		http.Error(res, "Forbidden: Admin access required", http.StatusForbidden)
		return
	}

	users, err := r.user.AdminList(user.ID)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	json.NewEncoder(res).Encode(users)
}
