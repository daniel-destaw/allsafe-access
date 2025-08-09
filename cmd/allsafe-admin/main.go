package main

import (
    "bufio"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "database/sql"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "os"
    "strings"

    "github.com/spf13/cobra"
    _ "github.com/mattn/go-sqlite3"
    "gopkg.in/yaml.v2"
)

// dbPath is the hardcoded path to the SQLite database file.
var dbPath = "./allsafe_admin.db"

// role will hold the value of the --role flag for user creation.
var role string

// passwordPolicy will hold the value of the --policy flag for user creation.
var passwordPolicy string

// New flag to hold the proxy's URL
var proxyURL string

// secretKey is used for signing the invitation token.
var secretKey = []byte("a-very-long-and-secure-secret-key-for-signing-tokens")

// tokenPayload is the structure for the invitation token payload.
type tokenPayload struct {
    Username       string `json:"username"`
    PasswordPolicy string `json:"policy"`
    Nonce          string `json:"nonce"`
}

// Config represents the structure of the allsafe-proxy.yaml file.
type Config struct {
    ListenAddress string `yaml:"listen_address"`
}

// rootCmd represents the base command for the admin CLI.
var rootCmd = &cobra.Command{
    Use:   "allsafe-admin",
    Short: "A CLI to manage Allsafe Access users and services",
    Long: `allsafe-admin is a command-line tool for administrators to manage
users, view audit logs, and control active sessions on the Allsafe Access
proxy.`,
}

// userCmd is the parent command for all user-related actions.
var userCmd = &cobra.Command{
    Use:   "user",
    Short: "Manage user accounts",
    Long:  "Commands for adding, deleting, and managing users.",
}

// userAddCmd adds a new user with a generated invitation token.
var userAddCmd = &cobra.Command{
    Use:   "add [username]",
    Short: "Add a new user with an invitation URL",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        username := args[0]
        log.Printf("Attempting to add new user: %s with role: %s and policy: %s\n", username, role, passwordPolicy)

        db, err := sql.Open("sqlite3", dbPath)
        if err != nil {
            log.Fatalf("Failed to open database: %v", err)
        }
        defer db.Close()

        // Generate a new, unique nonce for the token.
        nonceBytes := make([]byte, 16)
        if _, err := rand.Read(nonceBytes); err != nil {
            log.Fatalf("Failed to generate nonce: %v", err)
        }
        nonce := base64.URLEncoding.EncodeToString(nonceBytes)

        // Create a signed token that includes the policy.
        token, err := createSignedToken(username, passwordPolicy, nonce)
        if err != nil {
            log.Fatalf("Failed to create signed token: %v", err)
        }

        insertSQL := `INSERT INTO users (username, role, invite_token) VALUES (?, ?, ?)`
        _, err = db.Exec(insertSQL, username, role, token)
        if err != nil {
            if strings.Contains(err.Error(), "UNIQUE constraint failed: users.username") {
                log.Fatalf("Error: User '%s' already exists.", username)
            }
            log.Fatalf("Failed to insert new user: %v", err)
        }

        auditLogSQL := `INSERT INTO audit_logs (action, actor_username, target_username, details) VALUES (?, ?, ?, ?)`
        actorUsername := "admin"
        details := fmt.Sprintf(`{"invite_token": "%s", "role": "%s", "password_policy": "%s"}`, token, role, passwordPolicy)
        _, err = db.Exec(auditLogSQL, "user_add", actorUsername, username, details)
        if err != nil {
            log.Printf("Warning: Failed to write to audit logs: %v", err)
        }

        // The invitation URL now points to the proxy server
        inviteURL := fmt.Sprintf("%s/invite?token=%s", proxyURL, token)

        fmt.Printf("User '%s' added successfully with role '%s' and password policy '%s'!\n", username, role, passwordPolicy)
        fmt.Printf("Invitation URL: %s\n", inviteURL)
    },
}

// userDeleteCmd deletes a user.
var userDeleteCmd = &cobra.Command{
    Use:   "delete [username]",
    Short: "Delete a user account",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        username := args[0]
        log.Printf("Attempting to delete user: %s\n", username)

        // Confirmation prompt
        fmt.Printf("Are you sure you want to delete user '%s'? This action cannot be undone. (yes/no): ", username)
        reader := bufio.NewReader(os.Stdin)
        response, _ := reader.ReadString('\n')
        if strings.ToLower(strings.TrimSpace(response)) != "yes" {
            fmt.Println("User deletion canceled.")
            return
        }

        db, err := sql.Open("sqlite3", dbPath)
        if err != nil {
            log.Fatalf("Failed to open database: %v", err)
        }
        defer db.Close()

        // Delete the user from the 'users' table.
        deleteSQL := `DELETE FROM users WHERE username = ?`
        result, err := db.Exec(deleteSQL, username)
        if err != nil {
            log.Fatalf("Failed to delete user: %v", err)
        }

        rowsAffected, _ := result.RowsAffected()
        if rowsAffected == 0 {
            log.Fatalf("Error: User '%s' not found.", username)
        }

        // Log the action in the 'audit_logs' table.
        auditLogSQL := `INSERT INTO audit_logs (action, actor_username, target_username, details) VALUES (?, ?, ?, ?)`
        actorUsername := "admin"
        _, err = db.Exec(auditLogSQL, "user_delete", actorUsername, username, "{}")
        if err != nil {
            log.Printf("Warning: Failed to write to audit logs: %v", err)
        }

        fmt.Printf("User '%s' deleted successfully.\n", username)
    },
}

// userResetPasswordCmd resets a user's password by generating a new invite token.
var userResetPasswordCmd = &cobra.Command{
    Use:   "reset-password [username]",
    Short: "Generate a new password reset URL for a user",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        username := args[0]
        log.Printf("Attempting to reset password for user: %s\n", username)

        db, err := sql.Open("sqlite3", dbPath)
        if err != nil {
            log.Fatalf("Failed to open database: %v", err)
        }
        defer db.Close()

        // Check if the user exists first.
        var exists bool
        querySQL := `SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)`
        err = db.QueryRow(querySQL, username).Scan(&exists)
        if err != nil || !exists {
            log.Fatalf("Error: User '%s' not found.", username)
        }
        
        // Generate a new, unique nonce for the token.
        nonceBytes := make([]byte, 16)
        if _, err := rand.Read(nonceBytes); err != nil {
            log.Fatalf("Failed to generate nonce: %v", err)
        }
        nonce := base64.URLEncoding.EncodeToString(nonceBytes)

        // Create a new signed token.
        token, err := createSignedToken(username, "none", nonce)
        if err != nil {
            log.Fatalf("Failed to create signed token: %v", err)
        }

        // Update the user's record with the new token and null password hash.
        updateSQL := `UPDATE users SET password_hash = NULL, invite_token = ? WHERE username = ?`
        _, err = db.Exec(updateSQL, token, username)
        if err != nil {
            log.Fatalf("Failed to reset password for user: %v", err)
        }

        // Log the action in the 'audit_logs' table.
        auditLogSQL := `INSERT INTO audit_logs (action, actor_username, target_username, details) VALUES (?, ?, ?, ?)`
        actorUsername := "admin"
        details := fmt.Sprintf(`{"invite_token": "%s"}`, token)
        _, err = db.Exec(auditLogSQL, "password_reset", actorUsername, username, details)
        if err != nil {
            log.Printf("Warning: Failed to write to audit logs: %v", err)
        }

        inviteURL := fmt.Sprintf("%s/invite?token=%s", proxyURL, token)

        fmt.Printf("Password reset successfully for user '%s'!\n", username)
        fmt.Printf("New password reset URL: %s\n", inviteURL)
    },
}

// userListCmd lists all users in the database.
var userListCmd = &cobra.Command{
    Use:   "list",
    Short: "List all users",
    Run: func(cmd *cobra.Command, args []string) {
        log.Println("Attempting to list all users...")

        db, err := sql.Open("sqlite3", dbPath)
        if err != nil {
            log.Fatalf("Failed to open database: %v", err)
        }
        defer db.Close()

        rows, err := db.Query(`SELECT id, username, role FROM users`)
        if err != nil {
            log.Fatalf("Failed to query users: %v", err)
        }
        defer rows.Close()

        fmt.Printf("ID\tUsername\tRole\n")
        fmt.Println("--------------------------------")

        for rows.Next() {
            var id int
            var username, role string
            if err := rows.Scan(&id, &username, &role); err != nil {
                log.Fatalf("Failed to scan row: %v", err)
            }
            fmt.Printf("%d\t%s\t\t%s\n", id, username, role)
        }

        if err := rows.Err(); err != nil {
            log.Fatalf("Error during rows iteration: %v", err)
        }
    },
}

// userGetCmd retrieves and displays detailed information about a single user.
var userGetCmd = &cobra.Command{
    Use:   "get [username]",
    Short: "Get details for a specific user",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        username := args[0]
        log.Printf("Attempting to get user details for: %s\n", username)

        db, err := sql.Open("sqlite3", dbPath)
        if err != nil {
            log.Fatalf("Failed to open database: %v", err)
        }
        defer db.Close()

        var id int
        var passwordHash, inviteToken sql.NullString
        var role, createdAt string

        querySQL := `SELECT id, role, password_hash, invite_token, created_at FROM users WHERE username = ?`
        err = db.QueryRow(querySQL, username).Scan(&id, &role, &passwordHash, &inviteToken, &createdAt)
        if err != nil {
            if err == sql.ErrNoRows {
                log.Fatalf("Error: User '%s' not found.", username)
            }
            log.Fatalf("Failed to get user details: %v", err)
        }

        fmt.Printf("User Details for '%s'\n", username)
        fmt.Println("--------------------------------")
        fmt.Printf("ID:\t\t%d\n", id)
        fmt.Printf("Username:\t%s\n", username)
        fmt.Printf("Role:\t\t%s\n", role)
        fmt.Printf("Created At:\t%s\n", createdAt)

        if passwordHash.Valid {
            fmt.Printf("Password Hash:\t(Set)\n")
        } else {
            fmt.Printf("Password Hash:\t(Not set)\n")
        }

        if inviteToken.Valid {
            fmt.Printf("Invite Token:\t(Set)\n")
        } else {
            fmt.Printf("Invite Token:\t(NULL - Password is set)\n")
        }
    },
}

// createSignedToken generates a base64-encoded, HMAC-signed token.
func createSignedToken(username, policy, nonce string) (string, error) {
    payload := tokenPayload{
        Username:       username,
        PasswordPolicy: policy,
        Nonce:          nonce,
    }
    payloadBytes, err := json.Marshal(payload)
    if err != nil {
        return "", err
    }

    h := hmac.New(sha256.New, secretKey)
    h.Write(payloadBytes)
    signature := h.Sum(nil)

    token := fmt.Sprintf("%s.%s",
        base64.URLEncoding.EncodeToString(payloadBytes),
        base64.URLEncoding.EncodeToString(signature))

    return token, nil
}


// createDatabaseSchema ensures the database and tables exist.
func createDatabaseSchema() {
    db, err := sql.Open("sqlite3", dbPath)
    if err != nil {
        log.Fatalf("Failed to open database for schema creation: %v", err)
    }
    defer db.Close()

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

    _, err = db.Exec(usersTableSQL)
    if err != nil {
        log.Fatalf("Failed to create 'users' table: %v", err)
    }
    
    _, err = db.Exec(auditLogsTableSQL)
    if err != nil {
        log.Fatalf("Failed to create 'audit_logs' table: %v", err)
    }
}

func init() {
    // Read the allsafe-proxy.yaml file to get the listen_address
    yamlFile, err := ioutil.ReadFile("../../allsafe-proxy.yaml")
    if err != nil {
        // Log a warning and use the default value if the file can't be read
        log.Printf("Warning: Failed to read allsafe-proxy.yaml. Using default proxy URL. Error: %v", err)
        proxyURL = "https://10.195.130.14:8080"
    } else {
        var config struct {
            ListenAddress string `yaml:"listen_address"`
        }
        err = yaml.Unmarshal(yamlFile, &config)
        if err != nil {
            log.Printf("Warning: Failed to unmarshal allsafe-proxy.yaml. Using default proxy URL. Error: %v", err)
            proxyURL = "https://10.195.130.14:8080"
        } else {
            // Split the listen_address to get just the host and port
            parts := strings.Split(config.ListenAddress, ":")
            if len(parts) == 2 {
                proxyURL = fmt.Sprintf("https://%s:%s", parts[0], parts[1])
            } else {
                // Handle cases where the address is just a hostname or invalid
                proxyURL = fmt.Sprintf("https://%s", config.ListenAddress)
            }
            log.Printf("Successfully loaded proxy URL from config: %s", proxyURL)
        }
    }

    rootCmd.AddCommand(userCmd)

    userCmd.AddCommand(userAddCmd)
    userCmd.AddCommand(userDeleteCmd)
    userCmd.AddCommand(userResetPasswordCmd)
    userCmd.AddCommand(userListCmd)
    userCmd.AddCommand(userGetCmd)

    userAddCmd.Flags().StringVar(&role, "role", "user", "The role of the new user")
    userAddCmd.Flags().StringVar(&passwordPolicy, "policy", "none", "The password complexity policy (none, medium, hard)")

    // New persistent flag for the proxy URL.
    // The default is now set dynamically above.
    rootCmd.PersistentFlags().StringVar(&proxyURL, "proxy-url", proxyURL, "The base URL of the Allsafe Proxy server for invitation links")
}

func main() {
    createDatabaseSchema()
    
    if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}