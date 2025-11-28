package user

import (
	"errors"

	"slices"

	"github.com/oklog/ulid/v2"
)

func (u *User) IsAdmin(userInfo *UserInfo) bool {
	if u.UserAdminGroup == "" {
		return false
	}

	return slices.Contains(userInfo.Groups, u.UserAdminGroup)
}

func (u *User) AdminRegister(adminID ulid.ULID, username string, password string, groups []string, email string) error {
	if !u.getAndVerifyAdmin(adminID) {
		return errors.New("user is not an admin")
	}

	return u.Register(username, password, groups, email)
}

func (u *User) AdminList(adminID ulid.ULID) ([]UserInfo, error) {
	if !u.getAndVerifyAdmin(adminID) {
		return nil, errors.New("user is not an admin")
	}

	users := make([]UserInfo, len(u.users))
	copy(users, u.users)
	for i := range users {
		users[i].Password = nil
	}

	return users, nil
}

func (u *User) AdminDelete(adminID ulid.ULID, targetID ulid.ULID) error {
	if !u.getAndVerifyAdmin(adminID) {
		return errors.New("user is not an admin")
	}

	if adminID == targetID {
		return errors.New("are you trying to delete yourself?")
	}

	i, ok := u.getIndex(targetID)
	if !ok {
		return errors.New("target user not found")
	}

	u.users = slices.Delete(u.users, i, i+1)
	return nil
}

func (u *User) AdminResetPassword(adminID ulid.ULID, targetID ulid.ULID, newPassword string) error {
	if !u.getAndVerifyAdmin(adminID) {
		return errors.New("user is not an admin")
	}

	i, ok := u.getIndex(targetID)
	if !ok {
		return errors.New("target user not found")
	}

	u.users[i].Password = hash([]byte(targetID.String()), newPassword)
	return nil
}

func (u *User) AdminUpdateUserGroups(adminID ulid.ULID, targetID ulid.ULID, groups []string) error {
	if !u.getAndVerifyAdmin(adminID) {
		return errors.New("user is not an admin")
	}

	i, ok := u.getIndex(targetID)
	if !ok {
		return errors.New("target user not found")
	}

	u.users[i].Groups = groups
	return nil
}

func (u *User) getAndVerifyAdmin(adminID ulid.ULID) bool {
	admin, ok := u.Get(adminID)
	if !ok {
		return false
	}

	return u.IsAdmin(&admin)
}
