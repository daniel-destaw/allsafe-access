package user

import (
    "database/sql"
    "fmt"

    _ "github.com/mattn/go-sqlite3" // SQLite driver
)

// User represents the structure of a user entry from the database.
// It maps to the relevant columns in your 'users' table.
type User struct {
    Username string
    // The password is no longer a plain text field; it's a hash.
    // We will use this to verify the provided password.
    PasswordHash string
    Roles        []string
}

// UserManager manages a connection to the user database.
type UserManager struct {
    db *sql.DB
}

// NewUserManager creates and initializes a UserManager by opening an SQLite database connection.
func NewUserManager(dbPath string) (*UserManager, error) {
    db, err := sql.Open("sqlite3", dbPath)
    if err != nil {
        return nil, fmt.Errorf("failed to open database %s: %w", dbPath, err)
    }

    if err := db.Ping(); err != nil {
        db.Close()
        return nil, fmt.Errorf("failed to ping database %s: %w", dbPath, err)
    }

    return &UserManager{db: db}, nil
}

// GetUser retrieves a user by their username from the database.
// This function now correctly queries for 'username', 'password_hash', and 'role'
// from your specific 'users' table schema.
func (um *UserManager) GetUser(username string) (User, bool) {
    var u User
    var roleStr string // Use a temporary variable for the single role string

    row := um.db.QueryRow("SELECT username, password_hash, role FROM users WHERE username = ?", username)

    // Scan the results into the User struct and the temporary role string.
    err := row.Scan(&u.Username, &u.PasswordHash, &roleStr)
    if err != nil {
        if err == sql.ErrNoRows {
            return User{}, false // User not found
        }
        fmt.Printf("Error querying user %s: %v\n", username, err)
        return User{}, false
    }

    // Your 'role' column is a single string. We convert it to a slice
    // to match the `User` struct's `Roles` field.
    u.Roles = []string{roleStr}

    return u, true
}