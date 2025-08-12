package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"allsafe-access/pkg/auth"
	"allsafe-access/pkg/mfa"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ProxyConfig defines the structure for proxy.yaml configuration
type ProxyConfig struct {
	ListenAddress                string `mapstructure:"listen_address"`
	CertFile                     string `mapstructure:"cert_file"`
	KeyFile                      string `mapstructure:"key_file"`
	CACertFile                   string `mapstructure:"ca_cert_file"`
	AgentListenPort              int    `mapstructure:"agent_listen_port"`
	AgentHeartbeatTimeoutMinutes int    `mapstructure:"agent_heartbeat_timeout_minutes"`
	RegistrationToken            string `mapstructure:"registration_token"`
	RequireClientCertForCLI      bool   `mapstructure:"require_client_cert_for_cli"`
	UsersConfigPath              string `mapstructure:"users_config_path"`
	RolesConfigDir               string `mapstructure:"roles_config_dir"`
	InviteURLBase                string `mapstructure:"invite_url_base"`
}

var proxyCfg ProxyConfig
var cfgFile string
var authChecker *auth.AuthChecker
var authenticatedUsers = make(map[string]*auth.UserPermissions)
var authMutex sync.RWMutex
var database *sql.DB

// Moved constants and variables from allsafe-admin
var secretKey = []byte("a-very-long-and-secure-secret-key-for-signing-tokens")
var passwordPolicyDetails = map[string]struct {
	MinLength    int
	HasUppercase bool
	HasNumber    bool
	HasSpecial   bool
}{
	"none": {MinLength: 0},
	"medium": {
		MinLength:    8,
		HasUppercase: true,
		HasNumber:    true,
	},
	"hard": {
		MinLength:    12,
		HasUppercase: true,
		HasNumber:    true,
		HasSpecial:   true,
	},
}

// tokenPayload is the structure for the invitation token payload, now including MFA.
type tokenPayload struct {
	Username       string `json:"username"`
	PasswordPolicy string `json:"policy"`
	MfaSecret      string `json:"mfa_secret,omitempty"`
	Nonce          string `json:"nonce"`
}

// inviteForm is the data structure for the invite_form.html template.
type inviteForm struct {
	Username       string
	Token          string
	PasswordPolicy string
	MfaEnabled     bool
	MfaQRCodeURL   string
}

func initConfig(appName string) {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(fmt.Sprintf("/etc/%s", appName))
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(filepath.Join(home, fmt.Sprintf(".%s", appName)))
		}
		viper.AddConfigPath(".")
		viper.SetConfigName(appName)
	}

	viper.SetConfigType("yaml")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Printf("No config file found for %s. Using defaults or flags. Error: %v\n", appName, err)
		} else {
			log.Fatalf("Error reading config file for %s: %v\n", appName, err)
		}
	}
}

// Constants for API endpoints
const (
	registerEndpoint           = "/register"
	heartbeatEndpoint          = "/heartbeat"
	runCommandEndpoint         = "/run-command"
	cliShellEndpoint           = "/cli/shell"
	interactiveSessionEndpoint = "/agent/interactive"
	authEndpoint               = "/cli/auth"
	listNodesEndpoint          = "/cli/nodes"
	inviteEndpoint             = "/invite"
	setPasswordEndpoint        = "/set-password"
)

type AgentInfo struct {
	ID            string            `json:"ID"`
	IPAddress     string            `json:"IPAddress"`
	Labels        map[string]string `json:"Labels"`
	LastHeartbeat time.Time         `json:"LastHeartbeat"`
}

var (
	agents        = make(map[string]AgentInfo)
	agentsMutex   sync.RWMutex
	tlsConfig     *tls.Config
	agentWsDialer *websocket.Dialer
	inviteTemplate *template.Template
)

func init() {
	cobra.OnInitialize(func() {
		initConfig("allsafe-proxy")
		var err error
		inviteTemplate, err = template.ParseFiles("cmd/allsafe-proxy/templates/invite_form.html")
		if err != nil {
			log.Fatalf("Failed to parse invitation template: %v", err)
		}
	})
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/allsafe-proxy/allsafe-proxy.yaml or $HOME/.allsafe-proxy/allsafe-proxy.yaml)")
	rootCmd.Flags().String("listen-address", "", "Address for the proxy to listen on (e.g., :8080)")
	viper.BindPFlag("listen_address", rootCmd.Flags().Lookup("listen-address"))
	rootCmd.Flags().String("cert", "", "Path to proxy's TLS certificate file")
	viper.BindPFlag("cert_file", rootCmd.Flags().Lookup("cert"))
	rootCmd.Flags().String("key", "", "Path to proxy's TLS private key file")
	viper.BindPFlag("key_file", rootCmd.Flags().Lookup("key"))
	rootCmd.Flags().String("cacert", "", "Path to CA certificate file")
	viper.BindPFlag("ca_cert_file", rootCmd.Flags().Lookup("cacert"))
	rootCmd.Flags().Int("agent-port", 0, "Port agents listen on for proxy-initiated connections (e.g., 8081)")
	viper.BindPFlag("agent_listen_port", rootCmd.Flags().Lookup("agent-port"))
	rootCmd.Flags().Int("heartbeat-timeout", 0, "Timeout in minutes for agent heartbeats")
	viper.BindPFlag("agent_heartbeat_timeout_minutes", rootCmd.Flags().Lookup("heartbeat-timeout"))
	rootCmd.Flags().String("registration-token", "", "Token expected from agents during registration")
	viper.BindPFlag("registration_token", rootCmd.Flags().Lookup("registration-token"))
	rootCmd.Flags().Bool("require-cli-cert", false, "Require client certificates for CLI connections (default: false)")
	viper.BindPFlag("require_client_cert_for_cli", rootCmd.Flags().Lookup("require-cli-cert"))
	rootCmd.Flags().String("users-db", "", "Path to the allsafe_admin.db file for users")
	viper.BindPFlag("users_config_path", rootCmd.Flags().Lookup("users-db"))
	rootCmd.Flags().String("roles-dir", "", "Directory containing the roles/*.yaml files")
	viper.BindPFlag("roles_config_dir", rootCmd.Flags().Lookup("roles-dir"))
	rootCmd.Flags().String("invite-url-base", "", "The base URL for the invitation links (e.g., https://localhost:8080)")
	viper.BindPFlag("invite_url_base", rootCmd.Flags().Lookup("invite-url-base"))

	viper.SetDefault("listen_address", ":8080")
	viper.SetDefault("cert_file", "/etc/allsafe-proxy/proxy.crt")
	viper.SetDefault("key_file", "/etc/allsafe-proxy/proxy.key")
	viper.SetDefault("ca_cert_file", "/etc/allsafe-proxy/ca.crt")
	viper.SetDefault("agent_listen_port", 8081)
	viper.SetDefault("agent_heartbeat_timeout_minutes", 5)
	viper.SetDefault("registration_token", "")
	viper.SetDefault("require_client_cert_for_cli", false)
	viper.SetDefault("users_config_path", "./allsafe_admin.db")
	viper.SetDefault("roles_config_dir", "./configs/roles")
	viper.SetDefault("invite_url_base", "https://localhost:8080")
}

var rootCmd = &cobra.Command{
	Use:   "allsafe-proxy",
	Short: "Allsafe Proxy",
	Long:  `Allsafe Proxy manages agents and forwards commands.`,
	Run:   runProxy,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runProxy(cmd *cobra.Command, args []string) {
	if err := viper.Unmarshal(&proxyCfg); err != nil {
		log.Fatalf("Unable to decode proxy config into struct: %v", err)
	}

	log.Printf("Loaded Proxy Config: %+v\n", proxyCfg)

	var err error
	database, err = sql.Open("sqlite3", proxyCfg.UsersConfigPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()
	log.Println("Database connection established.")

	authMutex.Lock()
	authChecker, err = auth.NewAuthChecker(proxyCfg.UsersConfigPath, proxyCfg.RolesConfigDir)
	authMutex.Unlock()
	if err != nil {
		log.Fatalf("Failed to initialize AuthChecker: %v", err)
	}

	tlsConfig, err = loadAndSetupTLSServer(proxyCfg.CertFile, proxyCfg.KeyFile, proxyCfg.CACertFile, proxyCfg.RequireClientCertForCLI)
	if err != nil {
		log.Fatalf("Failed to load TLS configuration: %v", err)
	}

	proxyClientCert, err := tls.LoadX509KeyPair(proxyCfg.CertFile, proxyCfg.KeyFile)
	if err != nil {
		log.Fatalf("Failed to load proxy client certificate for agent dialer: %v", err)
	}
	caCertAgentDialer, err := os.ReadFile(proxyCfg.CACertFile)
	if err != nil {
		log.Fatalf("Failed to read CA certificate for agent dialer: %v", err)
	}
	caCertPoolAgentDialer := x509.NewCertPool()
	if !caCertPoolAgentDialer.AppendCertsFromPEM(caCertAgentDialer) {
		log.Fatalf("Failed to append CA certificate for agent dialer")
	}

	agentWsDialer = &websocket.Dialer{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{proxyClientCert},
			RootCAs:      caCertPoolAgentDialer,
		},
		HandshakeTimeout: 45 * time.Second,
	}

	mux := http.NewServeMux()

	mux.HandleFunc(registerEndpoint, handleRegister)
	mux.HandleFunc(heartbeatEndpoint, handleHeartbeat)
	mux.HandleFunc(runCommandEndpoint, handleRunCommand)
	mux.HandleFunc(authEndpoint, handleAuth)
	mux.HandleFunc(listNodesEndpoint, handleListNodes)
	mux.HandleFunc(cliShellEndpoint, handleCLIInteractiveRequest)
	mux.HandleFunc(inviteEndpoint, handleInvite)
	mux.HandleFunc(setPasswordEndpoint, handleSetPassword)
	
	fs := http.FileServer(http.Dir("cmd/allsafe-proxy/templates"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	server := &http.Server{
		Addr:      proxyCfg.ListenAddress,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	go func() {
		log.Printf("Allsafe Proxy listening on https://%s...", server.Addr)
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Proxy server failed: %v", err)
		}
	}()

	go cleanupOldAgents()
	go reloadConfigsPeriodically()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Shutting down proxy...")
	server.Shutdown(context.Background())
}

func handleInvite(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Invitation token is missing.", http.StatusBadRequest)
		return
	}

	payload, err := validateAndDecodeToken(token)
	if err != nil {
		http.Error(w, "Invalid or expired invitation token.", http.StatusForbidden)
		log.Printf("Token validation failed: %v", err)
		return
	}

	dbConnection, err := sql.Open("sqlite3", proxyCfg.UsersConfigPath)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("Failed to open database: %v", err)
		return
	}
	defer dbConnection.Close()

	var storedToken sql.NullString
	querySQL := `SELECT invite_token FROM users WHERE username = ? AND password_hash IS NULL`
	err = dbConnection.QueryRow(querySQL, payload.Username).Scan(&storedToken)
	if err != nil || !storedToken.Valid || storedToken.String != token {
		http.Error(w, "Invalid or expired invitation token.", http.StatusForbidden)
		if err == sql.ErrNoRows {
			log.Printf("User '%s' not found or token already used.", payload.Username)
		} else {
			log.Printf("Failed to query user by token for '%s': %v", payload.Username, err)
		}
		return
	}

	var mfaQRCodeURL string
	mfaEnabled := payload.MfaSecret != ""
	if mfaEnabled {
		mfaQRCodeURL, err = mfa.GenerateTOTPQRCodeURL("Allsafe Access", payload.Username, payload.MfaSecret)
		if err != nil {
			log.Printf("Failed to generate MFA QR code: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	data := struct {
		Token          string
		PasswordPolicy string
		Username       string
		MfaEnabled     bool
		MfaQRCodeURL   string
	}{
		Token:          token,
		PasswordPolicy: payload.PasswordPolicy,
		Username:       payload.Username,
		MfaEnabled:     mfaEnabled,
		MfaQRCodeURL:   mfaQRCodeURL,
	}

	w.Header().Set("Content-Type", "text/html")
	if err := inviteTemplate.Execute(w, data); err != nil {
		log.Printf("Failed to execute template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func handleSetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()
	token := r.FormValue("token")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")
	mfaCode := r.FormValue("mfa_code")

	if token == "" || password == "" || confirmPassword == "" {
		http.Error(w, "Token, password, or confirm password missing.", http.StatusBadRequest)
		return
	}

	if password != confirmPassword {
		http.Error(w, "Passwords do not match.", http.StatusBadRequest)
		return
	}

	payload, err := validateAndDecodeToken(token)
	if err != nil {
		http.Error(w, "Invalid or expired invitation token.", http.StatusForbidden)
		log.Printf("Token validation failed: %v", err)
		return
	}

	if payload.MfaSecret != "" {
		if mfaCode == "" {
			http.Error(w, "MFA code is required.", http.StatusBadRequest)
			return
		}
		if !mfa.ValidateTOTP(mfaCode, payload.MfaSecret) {
			http.Error(w, "Invalid MFA code.", http.StatusUnauthorized)
			return
		}
	}

	dbConnection, err := sql.Open("sqlite3", proxyCfg.UsersConfigPath)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("Failed to open database: %v", err)
		return
	}
	defer dbConnection.Close()

	var storedToken sql.NullString
	querySQL := `SELECT invite_token FROM users WHERE username = ? AND password_hash IS NULL`
	err = dbConnection.QueryRow(querySQL, payload.Username).Scan(&storedToken)
	if err != nil || !storedToken.Valid || storedToken.String != token {
		http.Error(w, "Invalid token or password already set.", http.StatusForbidden)
		return
	}

	if err := validatePasswordComplexity(password, payload.PasswordPolicy); err != nil {
		log.Printf("Password validation failed for user '%s': %v", payload.Username, err)
		http.Error(w, fmt.Sprintf("Password validation failed: %v", err), http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		log.Printf("Failed to hash password: %v", err)
		return
	}

	tx, err := dbConnection.Begin()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("Failed to begin transaction: %v", err)
		return
	}
	defer tx.Rollback()

	updateSQL := `UPDATE users SET password_hash = ?, invite_token = NULL WHERE username = ? AND invite_token = ? AND password_hash IS NULL`
	result, err := tx.ExecContext(context.Background(), updateSQL, hashedPassword, payload.Username, token)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("Failed to update password: %v", err)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Invalid token or password already set.", http.StatusForbidden)
		return
	}
	
	if payload.MfaSecret != "" {
		updateMfaSQL := `UPDATE mfa_devices SET is_enabled = 1 WHERE user_id = (SELECT id FROM users WHERE username = ?) AND config = ?`
		_, err = tx.ExecContext(context.Background(), updateMfaSQL, payload.Username, payload.MfaSecret)
		if err != nil {
			log.Printf("Failed to enable MFA device: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("Failed to commit transaction: %v", err)
		return
	}

	fmt.Fprintf(w, `
		<!DOCTYPE html>
		<html>
		<head>
			<title>Success</title>
			<script src="https://cdn.tailwindcss.com"></script>
		</head>
		<body class="bg-gray-100 flex items-center justify-center min-h-screen p-4">
			<div class="max-w-md w-full bg-white rounded-lg shadow-xl p-8 text-center">
				<h1 class="text-3xl font-bold text-green-600 mb-4">Success!</h1>
				<p class="text-gray-700">Your password has been set. You can now close this page and log in.</p>
			</div>
		</body>
		</html>
	`)
}

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

func validateAndDecodeToken(token string) (*tokenPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	payloadBytes, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	signature, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	h := hmac.New(sha256.New, secretKey)
	h.Write(payloadBytes)
	expectedSignature := h.Sum(nil)

	if !hmac.Equal(signature, expectedSignature) {
		return nil, fmt.Errorf("invalid token signature")
	}

	var payload tokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	return &payload, nil
}

func validatePasswordComplexity(password, policy string) error {
	details, ok := passwordPolicyDetails[policy]
	if !ok {
		return fmt.Errorf("unknown password policy: %s", policy)
	}

	if len(password) < details.MinLength {
		return fmt.Errorf("password must be at least %d characters long", details.MinLength)
	}

	if details.HasUppercase {
		hasUppercase := false
		for _, char := range password {
			if 'A' <= char && char <= 'Z' {
				hasUppercase = true
				break
			}
		}
		if !hasUppercase {
			return fmt.Errorf("password must contain at least one uppercase letter")
		}
	}

	if details.HasNumber {
		hasNumber := false
		for _, char := range password {
			if '0' <= char && char <= '9' {
				hasNumber = true
				break
			}
		}
		if !hasNumber {
			return fmt.Errorf("password must contain at least one number")
		}
	}

	if details.HasSpecial {
		hasSpecial := false
		specialChars := `!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`
		for _, char := range password {
			if strings.ContainsRune(specialChars, char) {
				hasSpecial = true
				break
			}
		}
		if !hasSpecial {
			return fmt.Errorf("password must contain at least one special character")
		}
	}

	return nil
}

func reloadConfigsPeriodically() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		log.Println("Proxy: Attempting to reload user and role configurations...")
		newAuthChecker, err := auth.NewAuthChecker(proxyCfg.UsersConfigPath, proxyCfg.RolesConfigDir)
		if err != nil {
			log.Printf("Proxy: Failed to reload AuthChecker: %v. Using old configuration.", err)
			continue
		}

		authMutex.Lock()
		authChecker = newAuthChecker
		authMutex.Unlock()

		log.Println("Proxy: Successfully reloaded user and role configurations.")
	}
}

func loadAndSetupTLSServer(certFile, keyFile, caCertFile string, requireClientCertForCLI bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate for client auth: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate for client auth")
	}

	clientAuthType := tls.NoClientCert
	if requireClientCertForCLI {
		clientAuthType = tls.RequireAndVerifyClientCert
		log.Printf("Proxy: Server configured to REQUIRE client certificates from CLI.")
	} else {
		log.Printf("Proxy: Server configured to NOT require client certificates from CLI.")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   clientAuthType,
	}, nil
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TotpCode string `json:"totp_code,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Proxy: Auth failed - could not decode body: %v", err)
		return
	}

	authMutex.RLock()
	userObj, permissions, err := authChecker.VerifyUserAndGetPermissions(req.Username, req.Password)
	authMutex.RUnlock()
	if err != nil {
		http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
		log.Printf("Proxy: Authentication failed for user '%s': %v", req.Username, err)
		return
	}

	mfaEnabled, mfaSecret, err := mfa.IsTOTPEnabledForUser(database, userObj.ID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("Proxy: Failed to check MFA status for user '%s': %v", req.Username, err)
		return
	}

	if mfaEnabled {
		if req.TotpCode == "" {
			http.Error(w, "MFA required", http.StatusForbidden)
			log.Printf("Proxy: Authentication failed for user '%s' - MFA required but not provided.", req.Username)
			return
		}
		if !mfa.ValidateTOTP(req.TotpCode, mfaSecret) {
			http.Error(w, "Invalid TOTP code", http.StatusUnauthorized)
			log.Printf("Proxy: Authentication failed for user '%s' - invalid TOTP code.", req.Username)
			return
		}
	}

	authMutex.Lock()
	authenticatedUsers[userObj.Username] = permissions
	authMutex.Unlock()

	response := map[string]string{
		"message": "Authentication successful",
		"username": userObj.Username,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	log.Printf("Proxy: Authentication successful for user '%s'.", req.Username)
}

func handleListNodes(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Auth-Token")
	if username == "" {
		http.Error(w, "Authentication token is missing", http.StatusUnauthorized)
		log.Printf("Proxy: List nodes failed - no auth token provided.")
		return
	}

	authMutex.RLock()
	permissions, ok := authenticatedUsers[username]
	authMutex.RUnlock()

	if !ok {
		http.Error(w, "Authorization failed: User not authenticated", http.StatusForbidden)
		log.Printf("Proxy: List nodes failed - user '%s' not found in authenticated sessions.", username)
		return
	}

	agentsMutex.RLock()
	defer agentsMutex.RUnlock()

	var authorizedAgents []AgentInfo
	timeout := time.Duration(proxyCfg.AgentHeartbeatTimeoutMinutes) * time.Minute

	for _, agent := range agents {
		if time.Since(agent.LastHeartbeat) > timeout {
			continue
		}

		isAuthorized := false
		for _, rule := range permissions.Permissions {
			if rule.Node == "*" || rule.Node == agent.ID {
				isAuthorized = true
				break
			}
		}

		if isAuthorized {
			authorizedAgents = append(authorizedAgents, agent)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(authorizedAgents); err != nil {
		log.Printf("Proxy: Failed to encode authorized agent list: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func handleCLIInteractiveRequest(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	userID := r.URL.Query().Get("user_id")
	loginUser := r.URL.Query().Get("login_user")

	if nodeID == "" || userID == "" || loginUser == "" {
		http.Error(w, "Node ID, User ID, and Login User are required", http.StatusBadRequest)
		log.Printf("Proxy: Interactive request missing required parameters.")
		return
	}

	authMutex.RLock()
	permissions, ok := authenticatedUsers[userID]
	authMutex.RUnlock()

	if !ok {
		http.Error(w, "Authorization failed: User not authenticated", http.StatusForbidden)
		log.Printf("Proxy: Interactive session failed - user '%s' not found in authenticated sessions.", userID)
		return
	}

	agentsMutex.RLock()
	agent, ok := agents[nodeID]
	agentsMutex.RUnlock()

	if !ok {
		http.Error(w, "Node not found or not active", http.StatusNotFound)
		log.Printf("Proxy: Attempted interactive session with unknown node: %s", nodeID)
		return
	}

	isAuthorized := false
	for _, rule := range permissions.Permissions {
		if rule.Node == "*" || rule.Node == nodeID {
			for _, allowedLogin := range rule.Logins {
				if allowedLogin == loginUser {
					isAuthorized = true
					break
				}
			}
		}
		if isAuthorized {
			break
		}
	}

	if !isAuthorized {
		http.Error(w, fmt.Sprintf("User '%s' is not authorized to access node '%s' as user '%s'.", userID, nodeID, loginUser), http.StatusForbidden)
		log.Printf("Proxy: User '%s' is not authorized to access node '%s' as '%s' based on their role.", userID, nodeID, loginUser)
		return
	}

	log.Printf("Proxy: Establishing interactive session for user '%s' (remote login: %s) with agent %s (%s)...", userID, loginUser, agent.ID, agent.IPAddress)

	upgrader := websocket.Upgrader{
		CheckOrigin:     func(r *http.Request) bool { return true },
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	cliWs, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Proxy: Failed to upgrade CLI connection to WebSocket: %v", err)
		return
	}
	defer cliWs.Close()

	agentWsURL := fmt.Sprintf("wss://%s:%d%s?user_id=%s&login_user=%s",
		agent.IPAddress,
		proxyCfg.AgentListenPort,
		interactiveSessionEndpoint,
		url.QueryEscape(userID),
		url.QueryEscape(loginUser),
	)

	log.Printf("Proxy: Attempting to dial agent %s interactive session at %s", agent.ID, agentWsURL)
	agentWs, resp, err := agentWsDialer.Dial(agentWsURL, nil)
	if err != nil {
		if resp != nil {
			bodyBytes, _ := io.ReadAll(resp.Body)
			log.Printf("Proxy: Failed to dial agent %s interactive session. Status: %d, Body: %s, Error: %v", agent.ID, resp.StatusCode, string(bodyBytes), err)
			cliWs.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Error: Could not connect to agent %s interactive session (Agent response: %s). Proxy error: %v\n", agent.ID, string(bodyBytes), err)))
		} else {
			log.Printf("Proxy: Failed to dial agent %s interactive session: %v", agent.ID, err)
			cliWs.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Error: Could not connect to agent %s interactive session. Proxy error: %v\n", agent.ID, err)))
		}
		return
	}
	defer agentWs.Close()

	log.Printf("Proxy: Bidirectional relay started between CLI and Agent %s (%s) for user '%s' (remote login: %s).", agent.ID, agent.IPAddress, userID, loginUser)

	var wg sync.WaitGroup
	wg.Add(2)

	// This goroutine reads from the CLI and forwards to the agent.
	go func() {
		defer wg.Done()
		for {
			messageType, message, err := cliWs.ReadMessage()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					log.Printf("Proxy: CLI WebSocket for agent %s (user %s) closed normally: %v", agent.ID, userID, err)
				} else {
					log.Printf("Proxy: Error reading from CLI WebSocket for agent %s (user %s): %v", agent.ID, userID, err)
				}
				agentWs.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Client disconnected"))
				return
			}
			if err := agentWs.WriteMessage(messageType, message); err != nil {
				log.Printf("Proxy: Error writing to Agent WebSocket for agent %s (user %s): %v", agent.ID, userID, err)
				return
			}
		}
	}()

	// This is the corrected goroutine. It reads from the agent and forwards to the CLI.
	go func() {
		defer wg.Done()
		for {
			messageType, message, err := agentWs.ReadMessage()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					log.Printf("Proxy: Agent WebSocket for agent %s (user %s) closed normally: %v", agent.ID, userID, err)
				} else {
					log.Printf("Proxy: Error reading from Agent WebSocket for agent %s (user %s): %v", agent.ID, userID, err)
				}
				cliWs.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Agent disconnected"))
				return
			}
			// Write the message back to the CLI WebSocket connection
			if err := cliWs.WriteMessage(messageType, message); err != nil {
				log.Printf("Proxy: Error writing to CLI WebSocket for agent %s (user %s): %v", agent.ID, userID, err)
				return
			}
		}
	}()

	wg.Wait()
	log.Printf("Proxy: Interactive session with agent %s (%s) for user '%s' (remote login: %s) ended.", agent.ID, agent.IPAddress, userID, loginUser)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     string            `json:"id"`
		Token  string            `json:"token"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Proxy: Failed to decode register request: %v", err)
		return
	}

	log.Printf("Proxy: Received registration from Agent ID: %s", req.ID)

	if proxyCfg.RegistrationToken != "" {
		if req.Token == "" {
			log.Printf("Proxy: WARNING: Agent %s did not provide a token, but proxy expects one.", req.ID)
			http.Error(w, "Registration token required", http.StatusUnauthorized)
			return
		}
		if req.Token != proxyCfg.RegistrationToken {
			log.Printf("Proxy: Agent %s provided invalid token.", req.ID)
			http.Error(w, "Invalid registration token", http.StatusUnauthorized)
			return
		}
		log.Printf("Proxy: Agent %s token validation successful.", req.ID)
	} else {
		if req.Token != "" {
			log.Printf("Proxy: WARNING: Agent %s provided a token '%s', but proxy is not configured to require one.", req.ID, req.Token)
		} else {
			log.Printf("Proxy: Agent %s registered without a token (not required by proxy).", req.ID)
		}
	}

	agentIP := r.RemoteAddr
	if colon := strings.LastIndex(agentIP, ":"); colon != -1 {
		agentIP = agentIP[:colon]
	}

	agentsMutex.Lock()
	agents[req.ID] = AgentInfo{
		ID:            req.ID,
		IPAddress:     agentIP,
		Labels:        req.Labels,
		LastHeartbeat: time.Now(),
	}
	agentsMutex.Unlock()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "registered", "agent_id": req.ID})
}

func handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Proxy: Failed to decode heartbeat request: %v", err)
		return
	}

	agentsMutex.Lock()
	if info, ok := agents[req.ID]; ok {
		info.LastHeartbeat = time.Now()
		agents[req.ID] = info
		log.Printf("Proxy: Heartbeat from Agent ID: %s", req.ID)
	} else {
		log.Printf("Proxy: Heartbeat from unknown Agent ID: %s. Agent must register first.", req.ID)
		http.Error(w, "Agent not registered", http.StatusNotFound)
		agentsMutex.Unlock()
		return
	}
	agentsMutex.Unlock()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "heartbeat_received"})
}

func handleRunCommand(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID  string   `json:"node_id"`
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		log.Printf("Proxy: Failed to read run command request body: %v", err)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Proxy: Failed to decode run command request: %v", err)
		return
	}

	nodeID := req.NodeID

	agentsMutex.RLock()
	agent, ok := agents[nodeID]
	agentsMutex.RUnlock()

	if !ok {
		http.Error(w, "Node not found or not active", http.StatusNotFound)
		log.Printf("Proxy: Attempted to run command on unknown node: %s", nodeID)
		return
	}

	log.Printf("Proxy: Forwarding command '%s %v' to agent %s (%s)", req.Command, req.Args, agent.ID, agent.IPAddress)

	tr := &http.Transport{
		TLSClientConfig: agentWsDialer.TLSClientConfig,
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	commandReq := map[string]interface{}{
		"command": req.Command,
		"args":    req.Args,
	}
	jsonData, err := json.Marshal(commandReq)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("Proxy: Failed to marshal command data: %v", err)
		return
	}

	resp, err := client.Post(fmt.Sprintf("https://%s:%d%s", agent.IPAddress, proxyCfg.AgentListenPort, runCommandEndpoint), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(w, "Failed to forward command to agent", http.StatusBadGateway)
		log.Printf("Proxy: Error forwarding command to agent %s (%s): %v", agent.ID, agent.IPAddress, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("Proxy: Agent %s returned non-OK status %d: %s", agent.ID, resp.StatusCode, string(bodyBytes))
		http.Error(w, fmt.Sprintf("Agent returned error: %s", string(bodyBytes)), resp.StatusCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Proxy: Failed to copy agent response to client: %v", err)
	}
}

func cleanupOldAgents() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		agentsMutex.Lock()
		now := time.Now()
		for id, agent := range agents {
			if now.Sub(agent.LastHeartbeat) > time.Duration(proxyCfg.AgentHeartbeatTimeoutMinutes)*time.Minute {
				log.Printf("Proxy: Agent %s (%s) has not sent a heartbeat for %v. Removing from active list.", id, agent.IPAddress, now.Sub(agent.LastHeartbeat))
				delete(agents, id)
			}
		}
		agentsMutex.Unlock()
	}
}