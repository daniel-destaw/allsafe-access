package main

import (
    "bufio"
    "bytes"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "database/sql"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "strings"
    "time"

    "github.com/spf13/cobra"
    _ "github.com/mattn/go-sqlite3"
    "gopkg.in/yaml.v2"
    "allsafe-access/pkg/mfa"
)

// dbPath is the hardcoded path to the SQLite database file.
var dbPath = "./allsafe_admin.db"

// role will hold the value of the --role flag for user creation.
var role string

// passwordPolicy will hold the value of the --policy flag for user creation.
var passwordPolicy string

// mfaType will hold the value of the --mfa flag for user creation.
var mfaType string

// New flag to hold the proxy's URL
var proxyURL string

// caCertPath will hold the path to the CA certificate file.
var caCertPath string

// secretKey is used for signing the invitation token.
var secretKey = []byte("a-very-long-and-secure-secret-key-for-signing-tokens")

// adminToken is a simple, hardcoded token for the admin CLI to authenticate with the proxy's admin endpoints.
const adminToken = "a-very-secret-admin-token-for-proxy-communication"

// tokenPayload is the structure for the invitation token payload.
type tokenPayload struct {
    Username       string `json:"username"`
    PasswordPolicy string `json:"policy"`
    MfaSecret      string `json:"mfa_secret,omitempty"`
    Nonce          string `json:"nonce"`
}

// Config represents the structure of the allsafe-proxy.yaml file.
type Config struct {
    ListenAddress string `yaml:"listen_address"`
}

// ActiveSession represents a session returned by the proxy's /admin/sessions endpoint.
type ActiveSession struct {
    UserID string `json:"user_id"`
    NodeID string `json:"node_id"`
    LoginUser string `json:"login_user"`
    StartTime time.Time `json:"start_time"`
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

// sessionsCmd is the parent command for all session-related actions.
var sessionsCmd = &cobra.Command{
    Use: "sessions",
    Short: "Manage active user sessions and authenticated users",
    Long: "Commands for listing and terminating active user sessions, and listing all authenticated users.",
}

// userAddCmd adds a new user with a generated invitation token.
var userAddCmd = &cobra.Command{
    Use:   "add [username]",
    Short: "Add a new user with an invitation URL",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        username := args[0]
        log.Printf("Attempting to add new user: %s with role: %s, policy: %s, and MFA: %s\n", username, role, passwordPolicy, mfaType)

        db, err := sql.Open("sqlite3", dbPath)
        if err != nil {
            log.Fatalf("Failed to open database: %v", err)
        }
        defer db.Close()

        tx, err := db.Begin()
        if err != nil {
            log.Fatalf("Failed to begin transaction: %v", err)
        }
        defer tx.Rollback()

        var mfaSecret string
        if mfaType == "totp" {
            mfaSecret, err = mfa.GenerateTOTPSecret()
            if err != nil {
                log.Fatalf("Failed to generate TOTP secret: %v", err)
            }
        }

        // Generate a new, unique nonce for the token.
        nonceBytes := make([]byte, 16)
        if _, err := rand.Read(nonceBytes); err != nil {
            log.Fatalf("Failed to generate nonce: %v", err)
        }
        nonce := base64.URLEncoding.EncodeToString(nonceBytes)

        // Create a signed token that includes the policy and MFA secret.
        token, err := createSignedToken(username, passwordPolicy, mfaSecret, nonce)
        if err != nil {
            log.Fatalf("Failed to create signed token: %v", err)
        }

        // Insert user without the mfa_enabled column, since it does not exist in your schema.
        insertUserSQL := `INSERT INTO users (username, role, invite_token) VALUES (?, ?, ?)`
        _, err = tx.Exec(insertUserSQL, username, role, token)
        if err != nil {
            if strings.Contains(err.Error(), "UNIQUE constraint failed: users.username") {
                log.Fatalf("Error: User '%s' already exists.", username)
            }
            log.Fatalf("Failed to insert new user: %v", err)
        }

        if mfaType == "totp" {
            insertMfaSQL := `INSERT INTO mfa_devices (user_id, mfa_type_id, config, is_enabled) 
                            VALUES ((SELECT id FROM users WHERE username = ?), (SELECT id FROM mfa_types WHERE type_name = ?), ?, ?)`
            _, err = tx.Exec(insertMfaSQL, username, mfaType, mfaSecret, 0)
            if err != nil {
                log.Fatalf("Failed to insert MFA device: %v", err)
            }
        }

        auditLogSQL := `INSERT INTO audit_logs (action, actor_username, target_username, details) VALUES (?, ?, ?, ?)`
        actorUsername := "admin"
        details := fmt.Sprintf(`{"invite_token": "%s", "role": "%s", "password_policy": "%s", "mfa_type": "%s"}`, token, role, passwordPolicy, mfaType)
        _, err = tx.Exec(auditLogSQL, "user_add", actorUsername, username, details)
        if err != nil {
            log.Printf("Warning: Failed to write to audit logs: %v", err)
        }

        err = tx.Commit()
        if err != nil {
            log.Fatalf("Failed to commit transaction: %v", err)
        }

        inviteURL := fmt.Sprintf("%s/invite?token=%s", proxyURL, token)

        fmt.Printf("User '%s' added successfully with role '%s', password policy '%s', and MFA '%s'!\n", username, role, passwordPolicy, mfaType)
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

        tx, err := db.Begin()
        if err != nil {
            log.Fatalf("Failed to begin transaction: %v", err)
        }
        defer tx.Rollback()

        // Delete the user from the 'users' table.
        deleteSQL := `DELETE FROM users WHERE username = ?`
        result, err := tx.Exec(deleteSQL, username)
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
        _, err = tx.Exec(auditLogSQL, "user_delete", actorUsername, username, "{}")
        if err != nil {
            log.Printf("Warning: Failed to write to audit logs: %v", err)
        }

        err = tx.Commit()
        if err != nil {
            log.Fatalf("Failed to commit transaction: %v", err)
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

        tx, err := db.Begin()
        if err != nil {
            log.Fatalf("Failed to begin transaction: %v", err)
        }
        defer tx.Rollback()

        // Check if the user exists first.
        var exists bool
        querySQL := `SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)`
        err = tx.QueryRow(querySQL, username).Scan(&exists)
        if err != nil || !exists {
            log.Fatalf("Error: User '%s' not found.", username)
        }

        // Generate a new, unique nonce for the token.
        nonceBytes := make([]byte, 16)
        if _, err := rand.Read(nonceBytes); err != nil {
            log.Fatalf("Failed to generate nonce: %v", err)
        }
        nonce := base64.URLEncoding.EncodeToString(nonceBytes)

        // Create a new signed token without MFA secret for password reset.
        token, err := createSignedToken(username, "none", "", nonce)
        if err != nil {
            log.Fatalf("Failed to create signed token: %v", err)
        }

        // Update the user's record with the new token and null password hash.
        updateSQL := `UPDATE users SET password_hash = NULL, invite_token = ? WHERE username = ?`
        _, err = tx.Exec(updateSQL, token, username)
        if err != nil {
            log.Fatalf("Failed to reset password for user: %v", err)
        }

        // Log the action in the 'audit_logs' table.
        auditLogSQL := `INSERT INTO audit_logs (action, actor_username, target_username, details) VALUES (?, ?, ?, ?)`
        actorUsername := "admin"
        details := fmt.Sprintf(`{"invite_token": "%s"}`, token)
        _, err = tx.Exec(auditLogSQL, "password_reset", actorUsername, username, details)
        if err != nil {
            log.Printf("Warning: Failed to write to audit logs: %v", err)
        }

        err = tx.Commit()
        if err != nil {
            log.Fatalf("Failed to commit transaction: %v", err)
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

        // Querying without the mfa_enabled column.
        rows, err := db.Query(`SELECT id, username, role FROM users`)
        if err != nil {
            log.Fatalf("Failed to query users: %v", err)
        }
        defer rows.Close()

        fmt.Printf("ID\tUsername\tRole\n")
        fmt.Println("-------------------------------------------------")

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
        var mfaEnabled sql.NullBool // Using NullBool to handle potential absence of the column

        // Query for mfa status separately from the users table.
        querySQL := `SELECT id, role, password_hash, invite_token, created_at FROM users WHERE username = ?`
        err = db.QueryRow(querySQL, username).Scan(&id, &role, &passwordHash, &inviteToken, &createdAt)
        if err != nil {
            if err == sql.ErrNoRows {
                log.Fatalf("Error: User '%s' not found.", username)
            }
            log.Fatalf("Failed to get user details: %v", err)
        }

        // Check if MFA is enabled by querying the mfa_devices table
        mfaEnabled = sql.NullBool{Bool: false, Valid: true}
        var mfaTypeCount int
        mfaQuerySQL := `SELECT COUNT(*) FROM mfa_devices WHERE user_id = ? AND is_enabled = 1`
        err = db.QueryRow(mfaQuerySQL, id).Scan(&mfaTypeCount)
        if err != nil {
            log.Printf("Warning: Failed to check MFA status for user '%s': %v", username, err)
        } else if mfaTypeCount > 0 {
            mfaEnabled.Bool = true
        }

        fmt.Printf("User Details for '%s'\n", username)
        fmt.Println("--------------------------------")
        fmt.Printf("ID:\t\t%d\n", id)
        fmt.Printf("Username:\t%s\n", username)
        fmt.Printf("Role:\t\t%s\n", role)
        fmt.Printf("MFA Enabled:\t%t\n", mfaEnabled.Bool)
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

// createHTTPClientWithCA configures an HTTP client to trust a specific CA certificate.
func createHTTPClientWithCA() *http.Client {
    if caCertPath == "" {
        // Fallback to default behavior if no CA cert is specified.
        return &http.Client{}
    }

    caCert, err := ioutil.ReadFile(caCertPath)
    if err != nil {
        log.Fatalf("Failed to read CA certificate: %v", err)
    }

    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
        log.Fatalf("Failed to append CA certificate to pool")
    }

    tlsConfig := &tls.Config{
        RootCAs: caCertPool,
    }

    transport := &http.Transport{
        TLSClientConfig: tlsConfig,
    }

    return &http.Client{Transport: transport}
}

// terminateCmd terminates an active session for a given user.
var terminateCmd = &cobra.Command{
    Use:   "terminate [username]",
    Short: "Terminate all active sessions for a user",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        username := args[0]
        log.Printf("Attempting to terminate sessions for user: %s\n", username)

        if proxyURL == "" {
            log.Fatal("Error: Proxy URL is not set. Use the --proxy-url flag or set it in the config.")
        }

        terminateURL := fmt.Sprintf("%s/admin/terminate-session", proxyURL)
        requestBody, err := json.Marshal(map[string]string{"username": username})
        if err != nil {
            log.Fatalf("Failed to marshal request body: %v", err)
        }

        client := createHTTPClientWithCA()
        req, err := http.NewRequest("POST", terminateURL, bytes.NewBuffer(requestBody))
        if err != nil {
            log.Fatalf("Failed to create request: %v", err)
        }
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("X-Admin-Token", adminToken)

        resp, err := client.Do(req)
        if err != nil {
            log.Fatalf("Failed to connect to proxy: %v", err)
        }
        defer resp.Body.Close()

        bodyBytes, _ := ioutil.ReadAll(resp.Body)
        
        // Handle the case where no active sessions are found gracefully
        if resp.StatusCode == http.StatusBadRequest {
            responseBody := string(bodyBytes)
            if strings.Contains(responseBody, "No active sessions found for user") {
                fmt.Printf("User '%s' did not have an active session to terminate.\n", username)
                return
            }
        }
        
        if resp.StatusCode != http.StatusOK {
            log.Fatalf("Proxy returned an error: %s", string(bodyBytes))
        }

        var result map[string]string
        if err := json.Unmarshal(bodyBytes, &result); err != nil {
            log.Fatalf("Failed to parse response from proxy: %v", err)
        }

        fmt.Println(result["message"])
    },
}

// listActiveSessionsCmd lists all active sessions. This has been modified to list all authenticated users.
var listActiveSessionsCmd = &cobra.Command{
    Use: "active",
    Short: "List all authenticated users",
    Run: func(cmd *cobra.Command, args []string) {
        log.Println("Attempting to list authenticated users...")

        if proxyURL == "" {
            log.Fatal("Error: Proxy URL is not set. Use the --proxy-url flag or set it in the config.")
        }

        listURL := fmt.Sprintf("%s/admin/authenticated-users", proxyURL)

        client := createHTTPClientWithCA()
        req, err := http.NewRequest("GET", listURL, nil)
        if err != nil {
            log.Fatalf("Failed to create request: %v", err)
        }
        req.Header.Set("X-Admin-Token", adminToken)

        resp, err := client.Do(req)
        if err != nil {
            log.Fatalf("Failed to connect to proxy: %v", err)
        }
        defer resp.Body.Close()

        bodyBytes, _ := ioutil.ReadAll(resp.Body)

        if resp.StatusCode != http.StatusOK {
            log.Fatalf("Proxy returned an error: %s", string(bodyBytes))
        }

        var users []string
        if err := json.Unmarshal(bodyBytes, &users); err != nil {
            log.Fatalf("Failed to parse response from proxy: %v", err)
        }

        if len(users) == 0 {
            fmt.Println("No users are currently authenticated.")
            return
        }

        fmt.Println("Authenticated Users:")
        fmt.Println("--------------------")
        for _, user := range users {
            fmt.Println(user)
        }
    },
}


// createSignedToken generates a base64-encoded, HMAC-signed token.
func createSignedToken(username, policy, mfaSecret, nonce string) (string, error) {
    payload := tokenPayload{
        Username:       username,
        PasswordPolicy: policy,
        MfaSecret:      mfaSecret,
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

    // The users table definition now matches your existing schema.
    usersTableSQL := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT,
        role TEXT NOT NULL,
        invite_token TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`

    auditLogsTableSQL := `
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        action TEXT NOT NULL,
        actor_username TEXT NOT NULL,
        target_username TEXT,
        details TEXT
    );`

    mfaTypesTableSQL := `
    CREATE TABLE IF NOT EXISTS mfa_types (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type_name TEXT NOT NULL UNIQUE
    );`

    mfaDevicesTableSQL := `
    CREATE TABLE IF NOT EXISTS mfa_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        mfa_type_id INTEGER NOT NULL,
        config TEXT NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        is_enabled INTEGER NOT NULL DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (mfa_type_id) REFERENCES mfa_types(id)
    );`

    _, err = db.Exec(usersTableSQL)
    if err != nil {
        log.Fatalf("Failed to create 'users' table: %v", err)
    }

    _, err = db.Exec(auditLogsTableSQL)
    if err != nil {
        log.Fatalf("Failed to create 'audit_logs' table: %v", err)
    }

    _, err = db.Exec(mfaTypesTableSQL)
    if err != nil {
        log.Fatalf("Failed to create 'mfa_types' table: %v", err)
    }

    _, err = db.Exec(mfaDevicesTableSQL)
    if err != nil {
        log.Fatalf("Failed to create 'mfa_devices' table: %v", err)
    }

    // Insert default MFA types if they don't exist
    insertMfaTypesSQL := `INSERT OR IGNORE INTO mfa_types (type_name) VALUES ('totp'), ('hotp');`
    _, err = db.Exec(insertMfaTypesSQL)
    if err != nil {
        log.Fatalf("Failed to insert default MFA types: %v", err)
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
    rootCmd.AddCommand(sessionsCmd)

    userCmd.AddCommand(userAddCmd)
    userCmd.AddCommand(userDeleteCmd)
    userCmd.AddCommand(userResetPasswordCmd)
    userCmd.AddCommand(userListCmd)
    userCmd.AddCommand(userGetCmd)

    sessionsCmd.AddCommand(terminateCmd)
    sessionsCmd.AddCommand(listActiveSessionsCmd)

    userAddCmd.Flags().StringVar(&role, "role", "user", "The role of the new user")
    userAddCmd.Flags().StringVar(&passwordPolicy, "policy", "none", "The password complexity policy (none, medium, hard)")
    userAddCmd.Flags().StringVar(&mfaType, "mfa", "none", "The MFA type for the new user (totp, hotp, none)")

    // New persistent flag for the proxy URL.
    rootCmd.PersistentFlags().StringVar(&proxyURL, "proxy-url", proxyURL, "The base URL of the Allsafe Proxy server for invitation links")
    // New persistent flag for the CA certificate path.
    rootCmd.PersistentFlags().StringVar(&caCertPath, "cacert", "", "Path to the CA certificate file to trust for proxy connections")
}

func main() {
    createDatabaseSchema()

    if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}