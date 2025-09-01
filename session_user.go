package nethsm

import (
	"errors"
	"fmt"

	"github.com/borud/nethsm/api"
)

// AddUser creates a new user.
//
// TODO(borud): replace role string type with api.UserRole
func (s *Session) AddUser(userID string, realname string, role string, passphrase string) error {
	roleValue := api.UserRole(role)
	if !roleValue.IsValid() {
		return fmt.Errorf("invalid user role [%s], valid roles are: %v", role, api.AllowedUserRoleEnumValues)
	}

	userPostData := api.NewUserPostData(realname, roleValue, passphrase)
	resp, err := s.client.UsersUserIDPut(s.authCtx, userID).UserPostData(*userPostData).Execute()
	defer closeBody(resp)
	if err != nil {
		return errors.Join(ErrUserCreateFailed, asError(resp), err)
	}

	return nil
}

// GetUser gets the user data for user identified by userID
func (s *Session) GetUser(userID string) (*api.UserData, error) {
	userData, resp, err := s.client.UsersUserIDGet(s.authCtx, userID).Execute()
	defer closeBody(resp)
	if err != nil {
		return nil, errors.Join(ErrUserGetFailed, asError(resp), err)
	}

	return userData, nil
}

// ListUsers lists usernames.  If the namespace is set it lists the users for that namespace.
func (s *Session) ListUsers() ([]string, error) {
	users, resp, err := s.client.UsersGet(s.authCtx).Execute()
	defer closeBody(resp)
	if err != nil {
		return []string{}, errors.Join(ErrUsersListFailed, asError(resp), err)
	}

	userList := make([]string, len(users))
	for i, user := range users {
		userList[i] = user.User
	}

	return userList, nil
}

// DeleteUser deletes user identified by userID.
func (s *Session) DeleteUser(userID string) error {
	resp, err := s.client.UsersUserIDDelete(s.authCtx, userID).Execute()
	defer closeBody(resp)
	if err != nil {
		return errors.Join(ErrUserDeleteFailed, asError(resp))
	}

	return nil
}
