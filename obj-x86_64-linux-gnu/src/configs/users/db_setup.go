package main

import (
	"database/sql"
	"flag"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

// setupDatabase opens the database connection and creates the necessary tables.
func setupDatabase(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	createUsersTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT,
		role TEXT NOT NULL,
		invite_token TEXT UNIQUE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	createAuditLogsTableSQL := `
	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		action TEXT NOT NULL,
		actor_username TEXT NOT NULL,
		target_username TEXT,
		details TEXT
	);`

	log.Println("Creating tables...")

	_, err = db.Exec(createUsersTableSQL)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(createAuditLogsTableSQL)
	if err != nil {
		return nil, err
	}

	log.Println("Database setup complete.")
	return db, nil
}

func main() {
	// Define a command-line flag for the database path.
	dbPath := flag.String("db", "./allsafe_admin.db", "Path to the SQLite database file")
	flag.Parse()

	db, err := setupDatabase(*dbPath)
	if err != nil {
		log.Fatalf("Failed to setup database: %v", err)
	}
	defer db.Close()

	log.Println("Database connection is ready.")
}
