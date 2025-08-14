package db

import (
    "database/sql"
    "fmt"
    "log"

    _ "github.com/mattn/go-sqlite3"
)

// Database encapsulates the database connection.
type Database struct {
    *sql.DB
}

// NewDatabase creates a new database connection and ensures the schema exists.
func NewDatabase(dbPath string) (*Database, error) {
    db, err := sql.Open("sqlite3", dbPath)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %w", err)
    }

    if err := createDatabaseSchema(db); err != nil {
        db.Close()
        return nil, fmt.Errorf("failed to create database schema: %w", err)
    }

    return &Database{db}, nil
}

// createDatabaseSchema ensures the necessary tables exist in the database.
func createDatabaseSchema(db *sql.DB) error {
    usersTableSQL := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL,
        password_hash TEXT,
        invite_token TEXT UNIQUE,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    );`

    auditLogsTableSQL := `
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        actor_username TEXT,
        target_username TEXT,
        details TEXT,
        timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    );`

    _, err := db.Exec(usersTableSQL)
    if err != nil {
        log.Printf("Failed to create 'users' table: %v", err)
        return err
    }
    
    _, err = db.Exec(auditLogsTableSQL)
    if err != nil {
        log.Printf("Failed to create 'audit_logs' table: %v", err)
        return err
    }

    return nil
}