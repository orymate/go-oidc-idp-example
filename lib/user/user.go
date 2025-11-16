package user

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"os"
	"slices"

	"github.com/oklog/ulid/v2"
)

const (
	RoleAdmin = "Admin"
	RoleUser  = "User"
)

type UserInfo struct {
	ID       ulid.ULID
	Username string
	Password []byte
	Groups   []string
	Email    string
}

type User struct {
	users     []UserInfo
	usersPath string
}

func New(users []UserInfo, usersPath string) *User {
	return &User{
		users:     users,
		usersPath: usersPath,
	}
}

func (u *User) Get(id ulid.ULID) (UserInfo, bool) {
	i := slices.IndexFunc(u.users, func(u UserInfo) bool {
		return u.ID == id
	})
	if i == -1 {
		return UserInfo{}, false
	}

	return u.users[i], true
}

func (u *User) Register(username string, password string, groups []string, email string) error {
	if slices.IndexFunc(u.users, func(u UserInfo) bool {
		return u.Username == username
	}) != -1 {
		return errors.New("username already exists")
	}

	id := ulid.Make()
	u.users = append(u.users, UserInfo{
		ID:       id,
		Username: username,
		Email:    email,
		Password: hash([]byte(id.String()), password),
		Groups:   groups,
	})

	return nil
}

func (u *User) Authenticate(username, password string) (UserInfo, bool) {
	i := slices.IndexFunc(u.users, func(u UserInfo) bool {
		return u.Username == username
	})
	if i == -1 {
		return UserInfo{}, false
	}

	user := u.users[i]

	return user, subtle.ConstantTimeCompare(hash([]byte(user.ID.String()), password), user.Password) == 1
}

func (u *User) SaveUsers() (err error) {
	if u.usersPath == "" {
		return
	}

	data, err := json.Marshal(u.users)
	if err != nil {
		return
	}

	file, err := os.Create(u.usersPath + "~")
	if err != nil {
		return
	}

	_, err = file.Write(data)
	if err != nil {
		file.Close()
		return
	}

	err = file.Close()
	if err != nil {
		return
	}

	err = os.Rename(u.usersPath+"~", u.usersPath)
	return
}

func (u *User) LoadUsers() (err error) {
	if u.usersPath == "" {
		return
	}

	data, err := os.ReadFile(u.usersPath)
	if err != nil {
		return
	}

	err = json.Unmarshal(data, &u.users)
	return
}
