// cmd/allsafe-cli/main.go
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall" // For terminal raw mode (Unix-like systems)
	"time"
	"unsafe" // Required for syscall.Syscall6 with unsafe.Pointer

	"github.com/fatih/color" // For colored output
	"github.com/gorilla/websocket" // For WebSocket communication
	"github.com/spf13/cobra" // For CLI command parsing
	"github.com/spf13/viper" // For configuration management

	"allsafe-access/pkg/auth"
	"allsafe-access/pkg/user"
	"allsafe-access/pkg/session"
)

// CLIConfig defines the structure for cli.yaml configuration
type CLIConfig struct {
	ProxyURL   string `mapstructure:"proxy_url"`
	CertFile   string `mapstructure:"cert_file"`
	KeyFile    string `mapstructure:"key_file"`
	CACertFile string `mapstructure:"ca_cert_file"`
}

var cliCfg CLIConfig           // Global variable to hold CLI configuration
var cfgFile string             // Global variable to hold config file path from --config flag
var tlsClientConfig *tls.Config // TLS config for CLI's HTTP/WebSocket client

// --- Global AUTH and Session variables ---
var authChecker *auth.AuthChecker
var sessionManager session.Manager
var loggedInUser *user.User
var userPermissions *auth.UserPermissions
// --- END Global AUTH and Session variables ---


// initConfig sets up Viper to read configuration from a file.
func initConfig(appName string) {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Look for config in /etc/<appName>, ~/.<appName>, and current directory
		viper.AddConfigPath(fmt.Sprintf("/etc/%s", appName))
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(filepath.Join(home, fmt.Sprintf(".%s", appName)))
		}
		viper.AddConfigPath(".") // Current directory
		viper.SetConfigName(appName)
	}

	viper.SetConfigType("yaml") // Expect YAML config file
	viper.AutomaticEnv()        // Read environment variables (e.g., ALLSAFE_CLI_PROXY_URL)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_")) // Replace . and - with _ for env vars

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, not necessarily an error if defaults/flags are used
			log.Printf("No config file found for %s. Using defaults or flags. Error: %v\n", appName, err)
		} else {
			// Real error reading config file
			log.Fatalf("Error reading config file for %s: %v", appName, err)
		}
	}

	// Initialize session manager
	homeDir, _ := os.UserHomeDir()
	if homeDir == "" {
		log.Fatal("Could not determine user home directory for session file.")
	}
	sessionDir := filepath.Join(homeDir, ".allsafe-cli")
	
	var err error
	sessionManager, err = session.NewFileSessionManager(sessionDir)
	if err != nil {
		log.Fatalf("Failed to initialize session manager: %v", err)
	}
}

// Constants for API endpoints
const (
	listNodesEndpoint  = "/list-nodes"
	runCommandEndpoint = "/run-command"
	cliShellEndpoint   = "/cli/shell"
)

func init() {
	// Initialize Viper before Cobra commands execute
	cobra.OnInitialize(func() { initConfig("allsafe-cli") })

	// Define global persistent flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/allsafe-cli/allsafe-cli.yaml or $HOME/.allsafe-cli/allsafe-cli.yaml)")

	// Set default values for config
	homeDir, _ := os.UserHomeDir()
	viper.SetDefault("proxy_url", "https://localhost:8080")
	viper.SetDefault("cert_file", filepath.Join(homeDir, ".allsafe-cli", "cli.crt"))
	viper.SetDefault("key_file", filepath.Join(homeDir, ".allsafe-cli", "cli.key"))
	viper.SetDefault("ca_cert_file", filepath.Join(homeDir, ".allsafe-cli", "ca.crt"))
}

var rootCmd = &cobra.Command{
	Use:   "allsafe-cli",
	Short: "Allsafe CLI for managing agents and running commands.",
	Long:  `The Allsafe CLI allows users to list registered agents, execute commands remotely, and establish interactive shell sessions.`,
	// PersistentPreRunE runs before any subcommand's RunE, useful for shared setup
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Unmarshal config into struct
		if err := viper.Unmarshal(&cliCfg); err != nil {
			return fmt.Errorf("unable to decode CLI config into struct: %w", err)
		}

		// Expand home directory in paths if needed
		homeDir, _ := os.UserHomeDir()
		if strings.HasPrefix(cliCfg.CertFile, "~/") {
			cliCfg.CertFile = filepath.Join(homeDir, cliCfg.CertFile[2:])
		}
		if strings.HasPrefix(cliCfg.KeyFile, "~/") {
			cliCfg.KeyFile = filepath.Join(homeDir, cliCfg.KeyFile[2:])
		}
		if strings.HasPrefix(cliCfg.CACertFile, "~/") {
			cliCfg.CACertFile = filepath.Join(homeDir, cliCfg.CACertFile[2:])
		}

		log.Printf("Loaded CLI Config: %+v\n", cliCfg)

		// Setup TLS client for HTTP/WebSocket connections
		if err := loadAndSetupTLSClient(); err != nil {
			return fmt.Errorf("failed to load TLS configuration: %w", err)
		}

		// Initialize AuthChecker
		usersConfigDir := "configs/users"
		rolesConfigDir := "configs/roles"

		var err error
		authChecker, err = auth.NewAuthChecker(usersConfigDir, rolesConfigDir)
		if err != nil {
			return fmt.Errorf("failed to initialize AuthChecker: %w", err)
		}
		log.Println("AuthChecker initialized for CLI.")

		// Load existing session
		sessionContent, err := sessionManager.LoadSession()
		if err != nil {
			// It's normal for session file not to exist initially
			if !os.IsNotExist(err) && !strings.Contains(err.Error(), "empty session file") && !strings.Contains(err.Error(), "no such file or directory") {
				log.Printf("Warning: Could not load previous session: %v", err)
			}
			loggedInUser = nil
			userPermissions = nil
		} else {
			loggedInUser = sessionContent.User
			userPermissions = sessionContent.Permissions
			log.Printf("Session loaded for user: %s", loggedInUser.Username)
		}

		// Enforce login for most commands unless it's login/logout itself
		// This check is relevant when running commands directly (e.g., `allsafe-cli list-nodes`)
		// and less so within the interactive shell, where login state is maintained.
		if cmd.Use != loginCmd.Use && cmd.Use != logoutCmd.Use && loggedInUser == nil {
			return fmt.Errorf("please login first using 'allsafe-cli login'")
		}

		return nil
	},
}

func main() {
	// Add all commands to the root command
	rootCmd.AddCommand(listNodesCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(accessCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)

	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// loadAndSetupTLSClient loads certs and configures the default HTTP client for TLS
func loadAndSetupTLSClient() error {
	// Load CLI client certificate and key
	cert, err := tls.LoadX509KeyPair(cliCfg.CertFile, cliCfg.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load CLI client certificate from %s/%s: %w", cliCfg.CertFile, cliCfg.KeyFile, err)
	}

	// Load CA certificate to verify proxy's server certificate
	caCert, err := os.ReadFile(cliCfg.CACertFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate from %s: %w", cliCfg.CACertFile, err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to append CA certificate from %s", cliCfg.CACertFile)
	}

	// Create TLS configuration for client
	tlsClientConfig = &tls.Config{
		Certificates: []tls.Certificate{cert}, // Client's own certificate
		RootCAs:      caCertPool,             // CA pool to verify server's certificate
	}

	// Configure default HTTP client to use this TLS config
	http.DefaultClient.Transport = &http.Transport{
		TLSClientConfig: tlsClientConfig,
	}
	http.DefaultClient.Timeout = 30 * time.Second // Set a reasonable timeout

	return nil
}

// promptForCredentials prompts the user for username and password securely
func promptForCredentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("Password: ")
	// Using ReadString is not secure for passwords as it echoes to screen
	// For production, consider using term.ReadPassword or similar.
	password, _ := reader.ReadString('\n') // For simplicity, reading normally
	password = strings.TrimSpace(password)

	return username, password
}

// runInteractiveShell provides an interactive prompt for CLI commands
func runInteractiveShell(root *cobra.Command) { // Accepts root command to execute subcommands
	reader := bufio.NewScanner(os.Stdin)
	green := color.New(color.FgGreen).SprintFunc() // For green colored prompt
	
	fmt.Printf("Welcome to the %s CLI! Type 'help' for commands, 'exit' to quit.\n", green("Allsafe"))

	for { // Main shell loop
		promptUser := "allsafe"
		if loggedInUser != nil {
			promptUser = fmt.Sprintf("%s@%s", loggedInUser.Username, promptUser)
		}
		
		fmt.Printf("%s> ", green(promptUser)) // Print the colored prompt

		if !reader.Scan() { // Read a line of input
			if err := reader.Err(); err != nil {
				log.Printf("Error reading input: %v", err)
			}
			break // EOF or error, exit shell
		}

		line := strings.TrimSpace(reader.Text())
		if line == "" {
			continue // Empty line, prompt again
		}

		if line == "exit" || line == "quit" { // Handle exit command
			if loggedInUser != nil {
				fmt.Println("Logging out...")
				if err := sessionManager.ClearSession(); err != nil {
					log.Printf("Error during logout: %v", err)
				}
				loggedInUser = nil
				userPermissions = nil
			}
			fmt.Println("Exiting Allsafe CLI.")
			break // Exit the loop
		}

		args := strings.Fields(line) // Split input into command and arguments
		
		// Capture stdout/stderr to isolate the command's output from the shell's prompt
		oldStdout := os.Stdout
		oldStderr := os.Stderr
		
		r, w, _ := os.Pipe()
		os.Stdout = w
		os.Stderr = w

		// Execute the command using the passed-in root command
		root.SetArgs(args) // Set the arguments for Cobra to parse
		executeErr := root.Execute() // Execute the command

		w.Close() // Close pipe writer to signal EOF for reader
		out, _ := io.ReadAll(r) // Read all captured output
		os.Stdout = oldStdout   // Restore original stdout
		os.Stderr = oldStderr   // Restore original stderr
		
		if executeErr != nil {
			// Cobra typically prints its own errors (like unknown command).
			// We only print if it's not the "unknown command" error, as Cobra already handles that.
			if !strings.Contains(executeErr.Error(), "unknown command") { 
				fmt.Fprintf(os.Stderr, "Command error: %v\n", executeErr)
			}
		}
		fmt.Print(string(out)) // Print captured output to the actual stdout

		root.SetArgs([]string{}) // Clear args after execution to prevent them from persisting for next loop iteration
	}
}

// loginCmd handles user authentication and session creation
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to the Allsafe system",
	Long:  `Authenticates the user with the Allsafe system and saves the session locally. Upon successful login, it enters an interactive shell.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if loggedInUser != nil {
			fmt.Printf("Already logged in as %s. Entering interactive shell.\n", loggedInUser.Username)
			runInteractiveShell(cmd.Root()) // Pass the root command to the shell
			return nil
		}

		username, password := promptForCredentials()

		user, perms, err := authChecker.VerifyUserAndGetPermissions(username, password)
		if err != nil {
			return fmt.Errorf("login failed: %v", err)
		}

		// Create and save session
		sessionContent := &session.SessionTokenContent{
			User:        user,
			Permissions: perms,
		}
		if err := sessionManager.CreateSession(sessionContent); err != nil {
			return fmt.Errorf("failed to save session: %w", err)
		}
		loggedInUser = user // Update global logged-in user
		userPermissions = perms

		fmt.Printf("Successfully logged in as %s.\n", loggedInUser.Username)
		fmt.Printf("Your effective permissions include Max Session TTL: %s, SSH File Copy: %t.\n",
			userPermissions.MaxSessionTTL, userPermissions.SSHFileCopy)
		
		runInteractiveShell(cmd.Root()) // Enter interactive shell after successful login
		return nil
	},
}

// logoutCmd clears the local session
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout from the Allsafe system",
	Long:  `Clears the local session, requiring re-login for subsequent commands.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sessionManager.ClearSession(); err != nil {
			return fmt.Errorf("failed to logout: %w", err)
		}
		loggedInUser = nil // Clear global logged-in user
		userPermissions = nil
		fmt.Println("You have been successfully logged out.")
		return nil
	},
}

// listNodesCmd fetches and displays active agent nodes
var listNodesCmd = &cobra.Command{
	Use:   "list-nodes",
	Short: "List all registered and active agent nodes",
	RunE: func(cmd *cobra.Command, args []string) error {
		req, err := http.NewRequest("GET", cliCfg.ProxyURL+listNodesEndpoint, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}
		if loggedInUser != nil {
			req.Header.Set("X-Allsafe-User", loggedInUser.Username)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to connect to proxy at %s: %w", cliCfg.ProxyURL, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("error listing nodes (Status: %d): %s", resp.StatusCode, string(bodyBytes))
		}

		var nodes []map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		if len(nodes) == 0 {
			fmt.Println("No active nodes found.")
			return nil
		}

		fmt.Println("Active Nodes:")
		for _, node := range nodes {
			id, _ := node["ID"].(string)
			ipAddress, _ := node["IPAddress"].(string)
			labels, _ := node["Labels"].(map[string]interface{})
			lastHeartbeatStr, _ := node["LastHeartbeat"].(string)
			var lastHeartbeatTime time.Time
			if t, err := time.Parse(time.RFC3339, lastHeartbeatStr); err == nil {
				lastHeartbeatTime = t
			} else {
				lastHeartbeatTime = time.Time{}
			}

			fmt.Printf("  ID: %s, IP: %s, Labels: %v, Last Heartbeat: %s (%.0f sec ago)\n",
				id, ipAddress, labels, lastHeartbeatTime.Format("2006-01-02 15:04:05 MST"), time.Since(lastHeartbeatTime).Seconds())
		}
		return nil
	},
}

// runCmd executes a command on a remote agent
var runCmd = &cobra.Command{
	Use:   "run [node-id] [command] [args...]",
	Short: "Run a command on a specific agent node",
	Args:  cobra.MinimumNArgs(2), // Requires node-id and command
	RunE: func(cmd *cobra.Command, args []string) error {
		nodeID := args[0]
		command := args[1]
		cmdArgs := args[2:]

		requestBody := map[string]interface{}{
			"node_id": nodeID,
			"command": command,
			"args":    cmdArgs,
		}
		jsonData, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}

		req, err := http.NewRequest("POST", cliCfg.ProxyURL+runCommandEndpoint, bytes.NewBuffer(jsonData))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if loggedInUser != nil {
			req.Header.Set("X-Allsafe-User", loggedInUser.Username)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send command to proxy at %s: %w", cliCfg.ProxyURL, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("error running command (Status: %d): %s", resp.StatusCode, string(bodyBytes))
		}

		var responseBody map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&responseBody); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		fmt.Println("Command Output:")
		fmt.Println(responseBody["output"])
		return nil
	},
}

// accessCmd establishes an interactive shell session with an agent
var accessCmd = &cobra.Command{
	Use:   "access [node-id]",
	Short: "Establish an interactive shell session with an agent node",
	Args:  cobra.ExactArgs(1), // Requires exactly one argument: node-id
	RunE: func(cmd *cobra.Command, args []string) error {
		nodeID := args[0]
		fmt.Printf("Attempting to establish interactive session with node %s...\n", nodeID)

		// Construct WebSocket URL
		wsURL := fmt.Sprintf("%s%s?node_id=%s", strings.Replace(cliCfg.ProxyURL, "https", "wss", 1), cliShellEndpoint, nodeID)
		u, err := url.Parse(wsURL)
		if err != nil {
			return fmt.Errorf("invalid WebSocket URL: %w", err)
		}

		// Set custom headers (e.g., for user identification)
		header := make(http.Header)
		if loggedInUser != nil {
			header.Set("X-Allsafe-User", loggedInUser.Username)
		}

		// Create WebSocket dialer with TLS configuration
		dialer := websocket.Dialer{
			TLSClientConfig:  tlsClientConfig, // Use the pre-configured TLS settings
			HandshakeTimeout: 45 * time.Second, // Timeout for the WebSocket handshake
		}
		
		log.Printf("CLI: Attempting WebSocket dial to %s with headers: %+v", u.String(), header) // DEBUG LOG
		conn, resp, err := dialer.Dial(u.String(), header) // Capture full response for debugging
		if err != nil {
			if resp != nil {
                bodyBytes, _ := io.ReadAll(resp.Body)
                log.Printf("CLI: WebSocket handshake failed. Status: %d, Body: %s", resp.StatusCode, string(bodyBytes)) // DEBUG LOG
            }
			return fmt.Errorf("failed to connect to agent via proxy at %s: %w", wsURL, err)
		}
		defer conn.Close() // Ensure connection is closed on function exit
		log.Println("CLI: WebSocket connection established. Proceeding to raw mode.") // DEBUG LOG

		fmt.Println("Connected to interactive session. Type 'exit' to quit.")

		// --- Terminal Raw Mode Configuration (Unix-specific) ---
		oldState, err := enableRawMode(os.Stdin.Fd())
		if err != nil {
			log.Printf("CLI: Error enabling raw mode: %v", err) // DEBUG LOG
			return fmt.Errorf("failed to enable raw mode: %w", err)
		}
		defer disableRawMode(os.Stdin.Fd(), oldState) // Restore terminal state on exit
		log.Println("CLI: Raw mode enabled. Starting I/O loops.") // DEBUG LOG

		done := make(chan struct{}) // Channel to signal when to stop I/O loops

		// Goroutine to read from Stdin and write to WebSocket
		go func() {
			buf := make([]byte, 1024)
			for {
				// log.Println("CLI: Goroutine: Reading from stdin...") // Uncomment for very verbose stdin debugging
				n, err := os.Stdin.Read(buf) // Read from terminal input
				if err != nil {
					log.Printf("CLI: Stdin read error: %v", err) // DEBUG LOG
					if err == io.EOF {
						log.Println("CLI: Stdin EOF, closing WebSocket send.")
					} else {
						log.Printf("CLI: Error reading from stdin: %v", err)
					}
					// Send a close message to the WebSocket if stdin closes/errors
					conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Client exited."))
					close(done) // Signal main loop to exit
					return
				}
				if n > 0 {
					if err := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil { // Write to WebSocket
						log.Printf("CLI: Error writing to WebSocket: %v", err) // DEBUG LOG
						close(done) // Signal main loop to exit
						return
					}
				}
			}
		}()

		// Main loop to read from WebSocket and write to Stdout
		log.Println("CLI: Starting WebSocket read loop.") // DEBUG LOG
		for {
			select {
			case <-done: // Exit if done channel is closed (e.g., stdin goroutine exited)
				log.Println("CLI: 'done' channel closed, exiting WebSocket read loop.") // DEBUG LOG
				return nil
			default:
				// Read a message from the WebSocket
				messageType, message, err := conn.ReadMessage()
				if err != nil {
					log.Printf("CLI: WebSocket read error: %v", err) // DEBUG LOG
					if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
						log.Println("CLI: WebSocket connection closed by remote.")
					} else {
						log.Printf("CLI: Error reading from WebSocket: %v", err)
					}
					return err // Exit on error or connection close
				}
				if messageType == websocket.TextMessage || messageType == websocket.BinaryMessage {
					os.Stdout.Write(message) // Write received message to terminal output
				}
			}
		}
	},
}

// terminalState holds the original terminal settings
type terminalState struct {
	State *syscall.Termios
}

// enableRawMode puts the terminal into raw mode (Unix-like systems)
func enableRawMode(fd uintptr) (*terminalState, error) {
	oldState := new(syscall.Termios)
	// Get current terminal attributes
	if _, _, err := syscall.Syscall6(syscall.SYS_IOCTL, fd, uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(oldState)), 0, 0, 0); err != 0 {
		return nil, os.NewSyscallError("TCGETS", err)
	}

	rawState := *oldState
	// Disable ECHO (don't echo typed characters), ICANON (canonical mode, buffer lines), ISIG (process signals)
	rawState.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG
	// Disable IXON (XON/XOFF flow control), ICRNL (map CR to NL)
	rawState.Iflag &^= syscall.IXON | syscall.ICRNL
	// Set character size to 8 bits
	rawState.Cflag &^= syscall.CSIZE | syscall.PARENB
	rawState.Cflag |= syscall.CS8
	// Set minimum number of characters for a read to return to 1, and no timeout
	rawState.Cc[syscall.VMIN] = 1
	rawState.Cc[syscall.VTIME] = 0

	// Set new terminal attributes
	if _, _, err := syscall.Syscall6(syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&rawState)), 0, 0, 0); err != 0 {
		return nil, os.NewSyscallError("TCSETS", err)
	}

	return &terminalState{State: oldState}, nil
}

// disableRawMode restores the terminal to its original state (Unix-like systems)
func disableRawMode(fd uintptr, state *terminalState) {
	if state != nil && state.State != nil {
		syscall.Syscall6(syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(state.State)), 0, 0, 0)
	}
}