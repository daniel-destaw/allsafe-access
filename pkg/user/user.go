package user

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// User represents the structure of a user entry from the database.
type User struct {
	ID           int64
	Username     string
	PasswordHash sql.NullString // Use sql.NullString to handle NULL values
	Role         string         // Changed to a single role string
}

// UserManager manages user data from the database.
type UserManager struct {
	dbPath string
	users  map[string]*User
	mutex  sync.RWMutex
}

// NewUserManager initializes a new UserManager and loads users from the database.
func NewUserManager(dbPath string) (*UserManager, error) {
	um := &UserManager{
		dbPath: dbPath,
		users:  make(map[string]*User),
	}
	if err := um.InitDB(); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	if err := um.LoadUsers(); err != nil {
		return nil, fmt.Errorf("failed to load users into UserManager: %w", err)
	}
	return um, nil
}

// InitDB ensures the necessary database tables exist.
func (um *UserManager) InitDB() error {
	conn, err := sql.Open("sqlite3", um.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database for initialization: %w", err)
	}
	defer conn.Close()

	// Create users table
	createUserTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT,
		role TEXT NOT NULL,
		invite_token TEXT UNIQUE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := conn.ExecContext(context.Background(), createUserTableSQL); err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}
	
	// Create mfa_devices table
	createMFATableSQL := `
	CREATE TABLE IF NOT EXISTS mfa_devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		config TEXT NOT NULL,
		is_enabled INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);`
	if _, err := conn.ExecContext(context.Background(), createMFATableSQL); err != nil {
		return fmt.Errorf("failed to create mfa_devices table: %w", err)
	}
	
	return nil
}

// LoadUsers loads all users and their roles from the database into the cache.
func (um *UserManager) LoadUsers() error {
	conn, err := sql.Open("sqlite3", um.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database for user loading: %w", err)
	}
	defer conn.Close()

	um.mutex.Lock()
	defer um.mutex.Unlock()
	um.users = make(map[string]*User) // Clear existing cache

	rows, err := conn.QueryContext(context.Background(), `SELECT id, username, password_hash, role FROM users`)
	if err != nil {
		return fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role); err != nil {
			return fmt.Errorf("failed to scan user row: %w", err)
		}
		um.users[u.Username] = u
	}

	if err = rows.Err(); err != nil {
		return fmt.Errorf("error after scanning user rows: %w", err)
	}
	return nil
}

// GetUser retrieves a user by username from the cache.
func (um *UserManager) GetUser(username string) (User, bool) {
	um.mutex.RLock()
	defer um.mutex.RUnlock()
	u, found := um.users[username]
	if !found {
		return User{}, false
	}
	// Return a copy to prevent external modification of cached data
	userCopy := *u
	return userCopy, true
}