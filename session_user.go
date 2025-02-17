package nethsm

import (
	"fmt"

	"github.com/borud/nethsm/api"
)

// AddUser creates a new user.
func (s *Session) AddUser(userID string, realname string, role string, passphrase string) error {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return err
	}

	roleValue := api.UserRole(role)
	if !roleValue.IsValid() {
		return fmt.Errorf("invalid user role [%s], valid roles are: %v", role, api.AllowedUserRoleEnumValues)
	}

	userPostData := api.NewUserPostData(realname, roleValue, passphrase)
	res, err := client.UsersUserIDPut(ctx, userID).UserPostData(*userPostData).Execute()
	if err != nil {
		return fmt.Errorf("failed to create user [%s] res[%+v]: %w", userID, res, err)
	}

	return nil
}

// GetUser gets the user data for user identified by userID
//
// TODO(borud): should replace the api.UserData return value with a type from this package
func (s *Session) GetUser(userID string) (*api.UserData, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return nil, err
	}

	userData, _, err := client.UsersUserIDGet(ctx, userID).Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to get user [%s]: %w", userID, err)
	}

	return userData, nil
}

// ListUsers lists usernames.  If the namespace is set it lists the users for that namespace.
func (s *Session) ListUsers() ([]string, error) {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return []string{}, err
	}

	users, _, err := client.UsersGet(ctx).Execute()
	if err != nil {
		return []string{}, fmt.Errorf("failed to list users: %w", err)
	}

	userList := make([]string, len(users))
	for i, user := range users {
		userList[i] = user.User
	}

	return userList, nil
}

// DeleteUser deletes user identified by userID.
func (s *Session) DeleteUser(userID string) error {
	client, ctx, err := s.newClientAndContext()
	if err != nil {
		return err
	}

	_, err = client.UsersUserIDDelete(ctx, userID).Execute()
	if err != nil {
		return fmt.Errorf("failed to delete user [%s]: %w", userID, err)
	}

	return nil
}
