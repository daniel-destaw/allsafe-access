package user

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

// User represents the structure of a user entry in the users.json file.
type User struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	Password string   `json:"password"`
}

// UserManager manages a collection of loaded users.
type UserManager struct {
	users map[string]User
}

// NewUserManager creates and initializes a UserManager by reading a JSON file
// with a list of user configurations.
func NewUserManager(filePath string) (*UserManager, error) {
	manager := &UserManager{
		users: make(map[string]User),
	}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("user config file not found: %s", filePath)
		}
		return nil, fmt.Errorf("failed to read user config file %s: %w", filePath, err)
	}

	var users []User
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user JSON from %s: %w", filePath, err)
	}

	for _, u := range users {
		manager.users[u.Username] = u
	}

	return manager, nil
}

// GetUser retrieves a user by their username.
func (um *UserManager) GetUser(username string) (User, bool) {
	user, found := um.users[username]
	return user, found
}
