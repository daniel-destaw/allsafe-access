package user

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// User represents a user from users.json
type User struct {
	Username string   `json:"username"`
	Logins   []string `json:"logins"` // Unix logins the user is allowed to use directly
	Roles    []string `json:"roles"`
	Password string   `json:"password"` // IMPORTANT: In a real system, store hashed passwords!
}

// UserManager handles loading and retrieving user data.
type UserManager struct {
	users map[string]User // 'users' is unexported (private)
	mu    sync.RWMutex    // Mutex to protect concurrent access to the users map
}

// NewUserManager creates and initializes a UserManager by loading user data from the specified directory.
func NewUserManager(configDir string) (*UserManager, error) {
	um := &UserManager{}
	if err := um.loadUsers(configDir); err != nil {
		return nil, fmt.Errorf("failed to load users from %s: %w", configDir, err)
	}
	log.Printf("UserManager: Loaded %d users.", len(um.users))
	return um, nil
}

// GetUserByUsername retrieves a user by their username.
func (um *UserManager) GetUserByUsername(username string) (*User, bool) {
	um.mu.RLock()
	defer um.mu.RUnlock()
	user, ok := um.users[username]
	return &user, ok // Return a copy of the User struct
}

// UserCount returns the number of users loaded by the UserManager.
// This is a public (exported) method to safely access the count of private 'users' map.
func (um *UserManager) UserCount() int {
	um.mu.RLock()
	defer um.mu.RUnlock()
	return len(um.users)
}

// loadUsers reads user data from a JSON file.
func (um *UserManager) loadUsers(dir string) error {
	um.mu.Lock()
	defer um.mu.Unlock()
	um.users = make(map[string]User)

	filePath := filepath.Join(dir, "users.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read users.json from %s: %w", filePath, err)
	}

	var userList []User
	if err := json.Unmarshal(data, &userList); err != nil {
		return fmt.Errorf("failed to parse users.json from %s: %w", filePath, err)
	}

	for _, u := range userList {
		um.users[u.Username] = u
	}
	return nil
}