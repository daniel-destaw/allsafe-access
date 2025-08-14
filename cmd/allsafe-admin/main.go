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
	"path/filepath"
	"strings"
	"time"

	"allsafe-access/pkg/mfa"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// dbPath is the hardcoded path to the SQLite database file.
var dbPath = "./allsafe_admin.db"

// role will hold the value of the --role flag for user creation.
var role string

// passwordPolicy will hold the value of the --policy flag for user creation.
var passwordPolicy string

// mfaType will hold the value of the --mfa flag for user creation.
var mfaType string

// proxyURL holds the proxy's URL from the configuration or flag.
var proxyURL string

// caCertPath will hold the path to the CA certificate file.
var caCertPath string

// secretKey is used for signing the invitation token. This is no longer hardcoded.
var secretKey []byte

// adminToken is a simple token for the admin CLI. This is no longer hardcoded.
var adminToken string

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
	UserID    string `json:"user_id"`
	NodeID    string `json:"node_id"`
	LoginUser string `json:"login_user"`
	Duration  string `json:"duration"`
}

// AuditEvent represents an audit log entry.
type AuditEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	ComponentID string    `json:"component_id"`
	UserID      string    `json:"user_id"`
	EventType   string    `json:"event_type"`
	Action      string    `json:"action"`
	Details     string    `json:"details"`
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
	Use:   "sessions",
	Short: "Manage active user sessions",
	Long:  "Commands for listing and terminating active user sessions.",
}

// auditCmd is the parent command for all audit log-related actions.
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Manage and view audit logs",
	Long:  "Commands for fetching and filtering audit logs.",
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

		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			log.Fatalf("Failed to generate nonce: %v", err)
		}
		nonce := base64.URLEncoding.EncodeToString(nonceBytes)

		token, err := createSignedToken(username, passwordPolicy, mfaSecret, nonce)
		if err != nil {
			log.Fatalf("Failed to create signed token: %v", err)
		}

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

		err = tx.Commit()
		if err != nil {
			log.Fatalf("Failed to commit transaction: %v", err)
		}

		inviteURL := fmt.Sprintf("%s/invite?token=%s", proxyURL, token)

		fmt.Printf("User '%s' added successfully with role '%s', policy '%s', and MFA '%s'!\n", username, role, passwordPolicy, mfaType)
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

		deleteSQL := `DELETE FROM users WHERE username = ?`
		result, err := tx.Exec(deleteSQL, username)
		if err != nil {
			log.Fatalf("Failed to delete user: %v", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			log.Fatalf("Error: User '%s' not found.", username)
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

		var exists bool
		querySQL := `SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)`
		err = tx.QueryRow(querySQL, username).Scan(&exists)
		if err != nil || !exists {
			log.Fatalf("Error: User '%s' not found.", username)
		}

		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			log.Fatalf("Failed to generate nonce: %v", err)
		}
		nonce := base64.URLEncoding.EncodeToString(nonceBytes)

		token, err := createSignedToken(username, "none", "", nonce)
		if err != nil {
			log.Fatalf("Failed to create signed token: %v", err)
		}

		updateSQL := `UPDATE users SET password_hash = NULL, invite_token = ? WHERE username = ?`
		_, err = tx.Exec(updateSQL, token, username)
		if err != nil {
			log.Fatalf("Failed to reset password for user: %v", err)
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
		var mfaEnabled sql.NullBool

		querySQL := `SELECT id, role, password_hash, invite_token, created_at FROM users WHERE username = ?`
		err = db.QueryRow(querySQL, username).Scan(&id, &role, &passwordHash, &inviteToken, &createdAt)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Fatalf("Error: User '%s' not found.", username)
			}
			log.Fatalf("Failed to get user details: %v", err)
		}

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

		if proxyURL == "" || adminToken == "" {
			log.Fatal("Error: Proxy URL or Admin Token is not set. Please ensure `allsafe-proxy.yaml` is configured and available.")
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

// listActiveSessionsCmd now fetches and displays detailed active sessions.
var listActiveSessionsCmd = &cobra.Command{
	Use:   "list-active",
	Short: "List all active sessions with details",
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Attempting to list active sessions...")

		if proxyURL == "" || adminToken == "" {
			log.Fatal("Error: Proxy URL or Admin Token is not set. Please ensure `allsafe-proxy.yaml` is configured and available.")
		}

		listURL := fmt.Sprintf("%s/admin/sessions", proxyURL)

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

		var sessions []ActiveSession
		if err := json.Unmarshal(bodyBytes, &sessions); err != nil {
			log.Fatalf("Failed to parse response from proxy: %v", err)
		}

		if len(sessions) == 0 {
			fmt.Println("No active sessions found.")
			return
		}

		fmt.Println("Active Sessions:")
		fmt.Println("----------------------------------------------------------------------")
		fmt.Printf("%-15s %-15s %-20s %s\n", "USER ID", "NODE ID", "LOGIN USER", "DURATION")
		fmt.Println("----------------------------------------------------------------------")
		for _, session := range sessions {
			fmt.Printf("%-15s %-15s %-20s %s\n",
				session.UserID,
				session.NodeID,
				session.LoginUser,
				session.Duration)
		}
	},
}

// listAuthenticatedUsersCmd is the new command to list all currently authenticated users.
var listAuthenticatedUsersCmd = &cobra.Command{
	Use:   "list-authenticated",
	Short: "List all users who have an active authentication token",
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Attempting to list authenticated users...")

		if proxyURL == "" || adminToken == "" {
			log.Fatal("Error: Proxy URL or Admin Token is not set. Please ensure `allsafe-proxy.yaml` is configured and available.")
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

		var authenticatedUsers []string
		if err := json.Unmarshal(bodyBytes, &authenticatedUsers); err != nil {
			log.Fatalf("Failed to parse response from proxy: %v", err)
		}

		if len(authenticatedUsers) == 0 {
			fmt.Println("No users are currently authenticated.")
			return
		}

		fmt.Println("Authenticated Users:")
		fmt.Println("--------------------")
		for _, username := range authenticatedUsers {
			fmt.Println(username)
		}
	},
}

var (
	auditEventType string
	auditUserID    string
	auditLimit     int
	auditSearch    string
)

// listAuditLogsCmd now fetches and displays audit logs from the local database.
var listAuditLogsCmd = &cobra.Command{
	Use:   "list",
	Short: "List audit logs from the local database",
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Attempting to fetch audit logs from local database...")

		db, err := sql.Open("sqlite3", dbPath)
		if err != nil {
			log.Fatalf("Failed to open database: %v", err)
		}
		defer db.Close()

		var queryBuilder strings.Builder
		queryBuilder.WriteString("SELECT timestamp, component_id, user_id, event_type, action, details FROM audit_events")

		var whereClauses []string
		var queryArgs []interface{}

		if auditEventType != "" {
			whereClauses = append(whereClauses, "event_type = ?")
			queryArgs = append(queryArgs, auditEventType)
		}
		if auditUserID != "" {
			whereClauses = append(whereClauses, "user_id = ?")
			queryArgs = append(queryArgs, auditUserID)
		}
		if auditSearch != "" {
			whereClauses = append(whereClauses, "(action LIKE ? OR details LIKE ?)")
			searchTerm := fmt.Sprintf("%%%s%%", auditSearch)
			queryArgs = append(queryArgs, searchTerm, searchTerm)
		}

		if len(whereClauses) > 0 {
			queryBuilder.WriteString(" WHERE ")
			queryBuilder.WriteString(strings.Join(whereClauses, " AND "))
		}

		queryBuilder.WriteString(" ORDER BY timestamp DESC")

		if auditLimit > 0 {
			queryBuilder.WriteString(" LIMIT ?")
			queryArgs = append(queryArgs, auditLimit)
		}

		query := queryBuilder.String()

		rows, err := db.Query(query, queryArgs...)
		if err != nil {
			log.Fatalf("Failed to query audit logs: %v", err)
		}
		defer rows.Close()

		var auditEvents []AuditEvent
		for rows.Next() {
			var event AuditEvent
			var userID, details sql.NullString
			if err := rows.Scan(&event.Timestamp, &event.ComponentID, &userID, &event.EventType, &event.Action, &details); err != nil {
				log.Fatalf("Failed to scan row: %v", err)
			}
			event.UserID = userID.String
			event.Details = details.String
			auditEvents = append(auditEvents, event)
		}

		if err := rows.Err(); err != nil {
			log.Fatalf("Error during rows iteration: %v", err)
		}

		if len(auditEvents) == 0 {
			fmt.Println("No audit logs found matching the criteria.")
			return
		}

		fmt.Println("Audit Logs:")
		fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
		fmt.Printf("%-20s | %-15s | %-15s | %-18s | %-15s | %s\n", "TIMESTAMP", "COMPONENT", "USER", "EVENT TYPE", "ACTION", "DETAILS")
		fmt.Println("---------------------------------------------------------------------------------------------------------------------------")
		for _, event := range auditEvents {
			fmt.Printf("%-20s | %-15s | %-15s | %-18s | %-15s | %s\n",
				event.Timestamp.Format("2006-01-02 15:04:05"),
				event.ComponentID,
				event.UserID,
				event.EventType,
				event.Action,
				event.Details)
		}
	},
}

// createSignedToken generates a base64-encoded, HMAC-signed token.
func createSignedToken(username, policy, mfaSecret, nonce string) (string, error) {
	if len(secretKey) == 0 {
		return "", fmt.Errorf("secretKey is not set. Cannot create a signed token.")
	}

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

	usersTableSQL := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT,
        role TEXT NOT NULL,
        invite_token TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

	componentsTableSQL := `
    CREATE TABLE IF NOT EXISTS components (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        labels TEXT,
        last_seen_at DATETIME NOT NULL
    );`

	auditEventsTableSQL := `
    CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        component_id TEXT NOT NULL,
        user_id TEXT,
        event_type TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT
    );`

	_, err = db.Exec(usersTableSQL)
	if err != nil {
		log.Fatalf("Failed to create 'users' table: %v", err)
	}

	_, err = db.Exec(mfaTypesTableSQL)
	if err != nil {
		log.Fatalf("Failed to create 'mfa_types' table: %v", err)
	}

	_, err = db.Exec(mfaDevicesTableSQL)
	if err != nil {
		log.Fatalf("Failed to create 'mfa_devices' table: %v", err)
	}

	_, err = db.Exec(componentsTableSQL)
	if err != nil {
		log.Fatalf("Failed to create 'components' table: %v", err)
	}

	_, err = db.Exec(auditEventsTableSQL)
	if err != nil {
		log.Fatalf("Failed to create 'audit_events' table: %v", err)
	}

	insertMfaTypesSQL := `INSERT OR IGNORE INTO mfa_types (type_name) VALUES ('totp'), ('hotp');`
	_, err = db.Exec(insertMfaTypesSQL)
	if err != nil {
		log.Fatalf("Failed to insert default MFA types: %v", err)
	}
}

func init() {
	var cfgFile string
	// Set up Viper to read configuration
	cobra.OnInitialize(func() {
		if cfgFile != "" {
			viper.SetConfigFile(cfgFile)
		} else {
			viper.AddConfigPath(".")
			viper.AddConfigPath(filepath.Join(".."))
			viper.AddConfigPath(filepath.Join("/etc", "allsafe-proxy"))
			viper.SetConfigName("allsafe-proxy")
		}
		viper.SetConfigType("yaml")
		viper.AutomaticEnv()
		viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

		if err := viper.ReadInConfig(); err == nil {
			log.Printf("Using config file: %s", viper.ConfigFileUsed())
		} else {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				log.Fatalf("Fatal: No config file found. 'allsafe-proxy.yaml' must be configured for the admin CLI to function.")
			} else {
				log.Fatalf("Fatal: Error reading config file: %v", err)
			}
		}

		// Read the secrets and other configuration values from Viper
		secretKey = []byte(viper.GetString("secret_key"))
		adminToken = viper.GetString("admin_token")
		listenAddress := viper.GetString("listen_address")
		caCertPath = viper.GetString("ca_cert_file")

		// Validate that the required secrets are set
		if len(secretKey) == 0 {
			log.Fatal("Fatal: 'secret_key' is not set in the configuration.")
		}
		if len(adminToken) == 0 {
			log.Fatal("Fatal: 'admin_token' is not set in the configuration.")
		}

		// Construct the proxyURL
		parts := strings.Split(listenAddress, ":")
		if len(parts) == 2 {
			proxyURL = fmt.Sprintf("https://%s:%s", parts[0], parts[1])
		} else {
			proxyURL = fmt.Sprintf("https://%s", listenAddress)
		}
		log.Printf("Proxy URL for admin CLI is set to: %s", proxyURL)
	})

	rootCmd.AddCommand(userCmd)
	rootCmd.AddCommand(sessionsCmd)
	rootCmd.AddCommand(auditCmd)

	userCmd.AddCommand(userAddCmd)
	userCmd.AddCommand(userDeleteCmd)
	userCmd.AddCommand(userResetPasswordCmd)
	userCmd.AddCommand(userListCmd)
	userCmd.AddCommand(userGetCmd)

	sessionsCmd.AddCommand(terminateCmd)
	sessionsCmd.AddCommand(listActiveSessionsCmd)
	sessionsCmd.AddCommand(listAuthenticatedUsersCmd)

	auditCmd.AddCommand(listAuditLogsCmd)

	userAddCmd.Flags().StringVar(&role, "role", "user", "The role of the new user")
	userAddCmd.Flags().StringVar(&passwordPolicy, "policy", "none", "The password complexity policy (none, medium, hard)")
	userAddCmd.Flags().StringVar(&mfaType, "mfa", "none", "The MFA type for the new user (totp, hotp, none)")

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./allsafe-proxy.yaml or ../allsafe-proxy.yaml)")
	rootCmd.PersistentFlags().StringVar(&caCertPath, "cacert", "", "Path to the CA certificate file to trust for proxy connections")

	listAuditLogsCmd.Flags().StringVar(&auditEventType, "event-type", "", "Filter logs by event type (e.g., MEDIUM_AUDIT, ADMIN_ACTION)")
	listAuditLogsCmd.Flags().StringVar(&auditUserID, "user-id", "", "Filter logs by user ID")
	listAuditLogsCmd.Flags().StringVar(&auditSearch, "search", "", "Search logs for a keyword in the action or details fields")
	listAuditLogsCmd.Flags().IntVar(&auditLimit, "limit", 10, "Limit the number of results returned (default 10)")
}

func main() {
	createDatabaseSchema()

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}