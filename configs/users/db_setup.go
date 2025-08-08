package main

import (
	"database/sql"
	"log"

	// This is the SQLite driver. The underscore `_` tells Go to import the package
	// and execute its init() function, but not to use its exported functions directly.
	// This makes the driver available to the standard `database/sql` package.
	_ "github.com/mattn/go-sqlite3"
)

// setupDatabase opens the database connection and creates the necessary tables.
func setupDatabase(dbPath string) (*sql.DB, error) {
	// Open a connection to the SQLite database file.
	// If the file does not exist, it will be created.
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// SQL statements to create the users and audit_logs tables.
	// The `IF NOT EXISTS` clause prevents errors if the tables already exist.
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

	// Execute the SQL statements to create the tables.
	// We use db.Exec() for operations that do not return a set of rows.
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
	// Define the path to your database file.
	dbPath := "./allsafe_admin.db"

	// Call the setup function to create the database and tables.
	db, err := setupDatabase(dbPath)
	if err != nil {
		log.Fatalf("Failed to setup database: %v", err)
	}
	defer db.Close()

	log.Println("Database connection is ready.")
}

