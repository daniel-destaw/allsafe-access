package main

import (
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
	"syscall"
	"time"
	"unsafe" // Added for syscall.Syscall6 for raw mode (Windows might need different approach)

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CLIConfig defines the structure for cli.yaml configuration
type CLIConfig struct {
	ProxyURL   string `mapstructure:"proxy_url"`
	CertFile   string `mapstructure:"cert_file"`
	KeyFile    string `mapstructure:"key_file"`
	CACertFile string `mapstructure:"ca_cert_file"`
}

var cliCfg CLIConfig   // Global variable to hold CLI configuration
var cfgFile string     // Global variable to hold config file path from --config flag
var tlsClientConfig *tls.Config // TLS config for CLI's HTTP/WebSocket client

// initConfig sets up Viper to read configuration from a file.
// It searches in specific paths and sets up automatic environment variable reading.
func initConfig(appName string) {
	if cfgFile != "" {
		// Use config file from the flag if provided
		viper.SetConfigFile(cfgFile)
	} else {
		// Define default config paths and file name
		// Search paths in order: /etc/<appName>/, $HOME/.<appName>/, current directory
		viper.AddConfigPath(fmt.Sprintf("/etc/%s", appName)) // e.g., /etc/allsafe-cli
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(filepath.Join(home, fmt.Sprintf(".%s", appName))) // e.g., $HOME/.allsafe-cli
		}
		viper.AddConfigPath(".")      // Current directory
		viper.SetConfigName(appName)  // Config file name, e.g., 'allsafe-cli.yaml'
	}

	viper.SetConfigType("yaml") // Expects YAML files

	// Automatically read environment variables that match Viper keys
	// e.g., ALLSAFE_CLI_PROXY_URL will map to 'proxy_url' in config
	viper.AutomaticEnv()
	// Replace dots and hyphens with underscores for env variable matching (e.g., "proxy-url" -> "PROXY_URL")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Printf("No config file found for %s. Using defaults or flags. Error: %v\n", appName, err)
		} else {
			log.Fatalf("Error reading config file for %s: %v", appName, err)
		}
	}
}

// Constants for API endpoints
const (
	listNodesEndpoint  = "/list-nodes"
	runCommandEndpoint = "/run-command"
	cliShellEndpoint   = "/cli/shell"
)

// init function for Cobra commands and Viper setup
func init() {
	// Call initConfig with the specific app name "allsafe-cli"
	cobra.OnInitialize(func() { initConfig("allsafe-cli") })

	// Define persistent flag for config file
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/allsafe-cli/allsafe-cli.yaml or $HOME/.allsafe-cli/allsafe-cli.yaml)")

	// Define and bind persistent flags to Viper keys for optional override
	rootCmd.PersistentFlags().String("proxy-url", "", "URL of the Allsafe Proxy (e.g., https://10.195.130.14:8080)")
	viper.BindPFlag("proxy_url", rootCmd.PersistentFlags().Lookup("proxy-url"))

	rootCmd.PersistentFlags().String("cert", "", "Path to CLI's TLS certificate file")
	viper.BindPFlag("cert_file", rootCmd.PersistentFlags().Lookup("cert"))

	rootCmd.PersistentFlags().String("key", "", "Path to CLI's TLS private key file")
	viper.BindPFlag("key_file", rootCmd.PersistentFlags().Lookup("key"))

	rootCmd.PersistentFlags().String("cacert", "", "Path to CA certificate file")
	viper.BindPFlag("ca_cert_file", rootCmd.PersistentFlags().Lookup("cacert"))

	// Set defaults for Viper keys (these will be overridden by config file or flags)
	homeDir, _ := os.UserHomeDir() // Get user's home directory for portable defaults
	viper.SetDefault("proxy_url", "https://localhost:8080") // Fallback default
	viper.SetDefault("cert_file", filepath.Join(homeDir, ".allsafe-cli", "cli.crt"))
	viper.SetDefault("key_file", filepath.Join(homeDir, ".allsafe-cli", "cli.key"))
	viper.SetDefault("ca_cert_file", filepath.Join(homeDir, ".allsafe-cli", "ca.crt"))
}

var rootCmd = &cobra.Command{
	Use:   "allsafe-cli",
	Short: "Allsafe CLI for managing agents and running commands.",
	Long:  `The Allsafe CLI allows users to list registered agents, execute commands remotely, and establish interactive shell sessions.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error { // Use PersistentPreRunE to return error
		// Unmarshal the configuration into the struct after initConfig has run
		if err := viper.Unmarshal(&cliCfg); err != nil {
			return fmt.Errorf("unable to decode CLI config into struct: %w", err)
		}

		// Expand home directory for cert paths if they start with "~/"
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

		log.Printf("Loaded CLI Config: %+v\n", cliCfg) // For debugging the loaded config

		// Load and setup TLS configuration for all HTTP/WebSocket client operations
		if err := loadAndSetupTLSClient(); err != nil {
			return fmt.Errorf("failed to load TLS configuration: %w", err)
		}
		return nil
	},
}

func main() {
	rootCmd.AddCommand(listNodesCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(accessCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// loadAndSetupTLSClient loads client certificate/key and CA certificate for mTLS.
func loadAndSetupTLSClient() error {
	// Load client cert
	cert, err := tls.LoadX509KeyPair(cliCfg.CertFile, cliCfg.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load CLI client certificate from %s/%s: %w", cliCfg.CertFile, cliCfg.KeyFile, err)
	}

	// Load CA cert
	caCert, err := os.ReadFile(cliCfg.CACertFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate from %s: %w", cliCfg.CACertFile, err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to append CA certificate from %s", cliCfg.CACertFile)
	}

	tlsClientConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	// Assign the custom transport with TLS config to http.DefaultClient
	http.DefaultClient.Transport = &http.Transport{
		TLSClientConfig: tlsClientConfig,
	}
	http.DefaultClient.Timeout = 30 * time.Second

	return nil
}

var listNodesCmd = &cobra.Command{
	Use:   "list-nodes",
	Short: "List all registered and active agent nodes",
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := http.DefaultClient.Get(cliCfg.ProxyURL + listNodesEndpoint) // Use cliCfg.ProxyURL
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to connect to proxy at %s: %v\n", cliCfg.ProxyURL, err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			fmt.Fprintf(os.Stderr, "Error listing nodes (Status: %d): %s\n", resp.StatusCode, string(bodyBytes))
			return
		}

		var nodes []map[string]interface{} // Using map[string]interface{} for dynamic fields
		if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse response: %v\n", err)
			return
		}

		if len(nodes) == 0 {
			fmt.Println("No active nodes found.")
			return
		}

		fmt.Println("Active Nodes:")
		for _, node := range nodes {
			// Ensure safe access to map keys as they might be missing or nil
			id, _ := node["ID"].(string)
			ipAddress, _ := node["IPAddress"].(string)
			labels, _ := node["Labels"].(map[string]interface{})
			lastHeartbeatStr, _ := node["LastHeartbeat"].(string)
			var lastHeartbeatTime time.Time
			if t, err := time.Parse(time.RFC3339, lastHeartbeatStr); err == nil {
				lastHeartbeatTime = t
			} else {
				lastHeartbeatTime = time.Time{} // Default to zero time on parse error
			}

			fmt.Printf("  ID: %s, IP: %s, Labels: %v, Last Heartbeat: %s (%.0f sec ago)\n",
				id, ipAddress, labels, lastHeartbeatTime.Format("2006-01-02 15:04:05 MST"), time.Since(lastHeartbeatTime).Seconds())
		}
	},
}

var runCmd = &cobra.Command{
	Use:   "run [node-id] [command] [args...]",
	Short: "Run a command on a specific agent node",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
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
			fmt.Fprintf(os.Stderr, "Failed to marshal request: %v\n", err)
			return
		}

		resp, err := http.DefaultClient.Post(cliCfg.ProxyURL+runCommandEndpoint, "application/json", bytes.NewBuffer(jsonData)) // Use cliCfg.ProxyURL
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to send command to proxy at %s: %v\n", cliCfg.ProxyURL, err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			fmt.Fprintf(os.Stderr, "Error running command (Status: %d): %s\n", resp.StatusCode, string(bodyBytes))
			return
		}

		var responseBody map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&responseBody); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse response: %v\n", err)
			return
		}

		fmt.Println("Command Output:")
		fmt.Println(responseBody["output"])
	},
}

var accessCmd = &cobra.Command{
	Use:   "access [node-id]",
	Short: "Establish an interactive shell session with an agent node",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		nodeID := args[0]
		fmt.Printf("Attempting to establish interactive session with node %s...\n", nodeID)

		// 1. Build WebSocket URL from cliCfg.ProxyURL
		// Replace "https" with "wss" for WebSocket over TLS
		wsURL := fmt.Sprintf("%s%s?node_id=%s", strings.Replace(cliCfg.ProxyURL, "https", "wss", 1), cliShellEndpoint, nodeID)
		u, err := url.Parse(wsURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid WebSocket URL: %v\n", err)
			return
		}

		// 2. Establish WebSocket connection with mTLS
		dialer := websocket.Dialer{
			TLSClientConfig: tlsClientConfig, // Use the shared TLS client config
			HandshakeTimeout: 45 * time.Second,
		}
		conn, _, err := dialer.Dial(u.String(), nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to connect to agent via proxy at %s: %v\n", wsURL, err)
			return
		}
		defer conn.Close()

		fmt.Println("Connected to interactive session. Type 'exit' to quit.")

		// Set up raw mode for stdin
		oldState, err := enableRawMode(os.Stdin.Fd())
		if err != nil {
			log.Fatalf("Failed to enable raw mode: %v", err)
		}
		defer disableRawMode(os.Stdin.Fd(), oldState)

		// Create a channel to signal when the session is done
		done := make(chan struct{})

		// Goroutine to read from stdin and send to WebSocket
		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := os.Stdin.Read(buf)
				if err != nil {
					if err == io.EOF {
						log.Println("Stdin EOF, closing WebSocket send.")
					} else {
						log.Printf("Error reading from stdin: %v", err)
					}
					// Send a close message to the server
					conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Client exited."))
					close(done) // Signal done if stdin fails or EOF
					return
				}
				if n > 0 {
					if err := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
						log.Printf("Error writing to WebSocket: %v", err)
						close(done) // Signal done if WebSocket write fails
						return
					}
				}
			}
		}()

		// Goroutine to read from WebSocket and write to stdout
		for {
			select {
			case <-done:
				// Stdin reader finished, so close gracefully
				return
			default:
				messageType, message, err := conn.ReadMessage()
				if err != nil {
					if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
						log.Println("WebSocket connection closed by remote.")
					} else {
						log.Printf("Error reading from WebSocket: %v", err)
					}
					return // Exit loop on error or close
				}
				if messageType == websocket.TextMessage || messageType == websocket.BinaryMessage {
					os.Stdout.Write(message)
				}
			}
		}
	},
}

// Helper functions for raw mode (ensure these are present and correct for your OS)
// These are primarily for Unix-like systems. Windows will require different syscalls or external libraries.
type terminalState struct {
	State *syscall.Termios
}

// enableRawMode sets stdin to raw mode
func enableRawMode(fd uintptr) (*terminalState, error) {
	oldState := new(syscall.Termios)
	// TCGETS is a system call to get terminal attributes
	if _, _, err := syscall.Syscall6(syscall.SYS_IOCTL, fd, uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(oldState)), 0, 0, 0); err != 0 {
		return nil, os.NewSyscallError("TCGETS", err)
	}

	rawState := *oldState
	// Disable echo (ECHO), canonical mode (ICANON), and signal characters (ISIG)
	rawState.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG
	// Disable XON/XOFF flow control (IXON) and carriage return to newline translation (ICRNL)
	rawState.Iflag &^= syscall.IXON | syscall.ICRNL
	// Clear character size (CSIZE) and parity enable (PARENB)
	rawState.Cflag &^= syscall.CSIZE | syscall.PARENB
	// Set character size to 8 bits (CS8)
	rawState.Cflag |= syscall.CS8
	rawState.Cc[syscall.VMIN] = 1 // Read returns after 1 byte
	rawState.Cc[syscall.VTIME] = 0 // No timeout

	// TCSETS is a system call to set terminal attributes
	if _, _, err := syscall.Syscall6(syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&rawState)), 0, 0, 0); err != 0 {
		return nil, os.NewSyscallError("TCSETS", err)
	}

	return &terminalState{State: oldState}, nil
}

// disableRawMode restores stdin to its original mode
func disableRawMode(fd uintptr, state *terminalState) {
	if state != nil && state.State != nil {
		syscall.Syscall6(syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(state.State)), 0, 0, 0)
	}
}