package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty" // For interactive sessions
	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// AgentConfig defines the structure for agent.yaml configuration
type AgentConfig struct {
	ID                       string            `mapstructure:"id"`
	ProxyURL                 string            `mapstructure:"proxy_url"`
	ListenAddress            string            `mapstructure:"listen_address"`
	CertFile                 string            `mapstructure:"cert_file"`
	KeyFile                  string            `mapstructure:"key_file"`
	CACertFile               string            `mapstructure:"ca_cert_file"`
	RegistrationToken        string            `mapstructure:"registration_token"`
	Labels                   map[string]string `mapstructure:"labels"`
	HeartbeatIntervalSeconds int               `mapstructure:"heartbeat_interval_seconds"`
}

var agentCfg AgentConfig // Global variable to hold agent configuration
var cfgFile string       // Global variable to hold config file path from --config flag

// initConfig sets up Viper to read configuration from a file.
// It searches in specific paths and sets up automatic environment variable reading.
func initConfig(appName string) {
	if cfgFile != "" {
		// Use config file from the flag if provided
		viper.SetConfigFile(cfgFile)
	} else {
		// Define default config paths and file name
		// Search paths in order: /etc/<appName>/, $HOME/.<appName>/, current directory
		viper.AddConfigPath(fmt.Sprintf("/etc/%s", appName)) // e.g., /etc/allsafe-agent
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(filepath.Join(home, fmt.Sprintf(".%s", appName))) // e.g., $HOME/.allsafe-agent
		}
		viper.AddConfigPath(".")      // Current directory
		viper.SetConfigName(appName)  // Config file name, e.g., 'allsafe-agent.yaml'
	}

	viper.SetConfigType("yaml") // Expects YAML files

	// Automatically read environment variables that match Viper keys
	// e.g., ALLSAFE_AGENT_LISTEN_ADDRESS will map to 'listen_address' in config
	viper.AutomaticEnv()
	// Replace dots and hyphens with underscores for env variable matching (e.g., "listen-address" or "listen.address" -> "LISTEN_ADDRESS")
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
	interactiveSessionEndpoint = "/agent/interactive"
)

type Agent struct {
	ID            string
	ProxyURL      string
	Labels        map[string]string
	CertFile      string
	KeyFile       string
	CACertFile    string
	TlsConfig     *tls.Config // TLS config for the agent's server (for proxy incoming connections)
	LastHeartbeat time.Time
}

// init function for Cobra commands and Viper setup
func init() {
	// Call initConfig with the specific app name "allsafe-agent"
	cobra.OnInitialize(func() { initConfig("allsafe-agent") })

	// Define persistent flag for config file
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/allsafe-agent/allsafe-agent.yaml or $HOME/.allsafe-agent/allsafe-agent.yaml)")

	// Define and bind specific flags to Viper keys for optional override
	rootCmd.Flags().String("id", "", "Agent ID (required)")
	viper.BindPFlag("id", rootCmd.Flags().Lookup("id"))

	rootCmd.Flags().String("proxy-url", "", "URL of the Allsafe Proxy (e.g., https://10.195.130.14:8080) (required)")
	viper.BindPFlag("proxy_url", rootCmd.Flags().Lookup("proxy-url"))

	rootCmd.Flags().String("listen-address", "", "Address for the agent to listen on for proxy connections (e.g., :8081)")
	viper.BindPFlag("listen_address", rootCmd.Flags().Lookup("listen-address"))

	rootCmd.Flags().String("cert", "", "Path to agent's TLS certificate file")
	viper.BindPFlag("cert_file", rootCmd.Flags().Lookup("cert"))

	rootCmd.Flags().String("key", "", "Path to agent's TLS private key file")
	viper.BindPFlag("key_file", rootCmd.Flags().Lookup("key"))

	rootCmd.Flags().String("cacert", "", "Path to CA certificate file")
	viper.BindPFlag("ca_cert_file", rootCmd.Flags().Lookup("cacert"))

	rootCmd.Flags().String("token", "", "Registration token to send to the proxy")
	viper.BindPFlag("registration_token", rootCmd.Flags().Lookup("token"))

	rootCmd.Flags().StringToString("labels", nil, "Comma-separated labels for the agent (key=value,key2=value2)")
	viper.BindPFlag("labels", rootCmd.Flags().Lookup("labels"))

	rootCmd.Flags().Int("heartbeat-interval", 0, "Heartbeat interval in seconds")
	viper.BindPFlag("heartbeat_interval_seconds", rootCmd.Flags().Lookup("heartbeat-interval"))

	// Set defaults for Viper keys
	viper.SetDefault("listen_address", ":8081")
	viper.SetDefault("cert_file", "/etc/allsafe-agent/agent.crt")
	viper.SetDefault("key_file", "/etc/allsafe-agent/agent.key")
	viper.SetDefault("ca_cert_file", "/etc/allsafe-agent/ca.crt")
	viper.SetDefault("heartbeat_interval_seconds", 30)
	viper.SetDefault("labels", map[string]string{}) // Empty map default for labels
	viper.SetDefault("registration_token", "")      // Default to no token sent
}

var rootCmd = &cobra.Command{
	Use:   "allsafe-agent",
	Short: "Allsafe Agent",
	Long:  `Allsafe Agent registers with a proxy and executes commands.`,
	Args:  cobra.NoArgs, // All args handled by flags or config
	Run:   runAgent,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runAgent(cmd *cobra.Command, args []string) {
	// Unmarshal the configuration into the struct after initConfig has run
	if err := viper.Unmarshal(&agentCfg); err != nil {
		log.Fatalf("Unable to decode agent config into struct: %v", err)
	}

	// Perform checks for required configuration
	if agentCfg.ID == "" {
		log.Fatal("Agent ID is required. Please provide it via 'id' in config file or --id flag.")
	}
	if agentCfg.ProxyURL == "" {
		log.Fatal("Proxy URL is required. Please provide it via 'proxy_url' in config file or --proxy-url flag.")
	}
	// Note: RegistrationToken is optional, depending on proxy config

	log.Printf("Loaded Agent Config: %+v\n", agentCfg) // For debugging the loaded config

	// Create Agent instance using loaded config
	agent := &Agent{
		ID:         agentCfg.ID,
		ProxyURL:   agentCfg.ProxyURL,
		Labels:     agentCfg.Labels,
		CertFile:   agentCfg.CertFile,
		KeyFile:    agentCfg.KeyFile,
		CACertFile: agentCfg.CACertFile,
	}

	// Set up mTLS client for agent to proxy communication (http.DefaultClient)
	clientCert, err := tls.LoadX509KeyPair(agentCfg.CertFile, agentCfg.KeyFile)
	if err != nil {
		log.Fatalf("Failed to load agent client certificate: %v", err)
	}
	caCert, err := os.ReadFile(agentCfg.CACertFile)
	if err != nil {
		log.Fatalf("Failed to read CA certificate for agent: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("Failed to append CA certificate for agent")
	}

	http.DefaultClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caCertPool,
		},
	}
	http.DefaultClient.Timeout = 30 * time.Second // Set a reasonable timeout

	// Load and setup TLS for agent's incoming connections from proxy
	if err := agent.loadAndSetupAgentTLSServer(); err != nil {
		log.Fatalf("Failed to load agent server TLS configuration: %v", err)
	}

	// Attempt initial registration
	if err := agent.register(agentCfg.RegistrationToken); err != nil {
		log.Printf("Agent initial registration failed: %v. Will retry registration via heartbeat.", err)
	}

	// Setup HTTP handlers for incoming proxy requests
	mux := http.NewServeMux()
	mux.HandleFunc(runCommandEndpoint, agent.handleRunCommand)
	mux.HandleFunc(interactiveSessionEndpoint, agent.handleInteractiveSession)

	server := &http.Server{
		Addr:      agentCfg.ListenAddress, // Use config value
		Handler:   mux,
		TLSConfig: agent.TlsConfig, // From loadAndSetupAgentTLSServer
	}

	// Start agent server in a goroutine
	go func() {
		log.Printf("Agent %s listening for proxy connections on %s...", agent.ID, server.Addr)
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Agent server failed: %v", err)
		}
	}()

	// Start heartbeat routine
	go agent.startHeartbeat() // Uses agentCfg.HeartbeatIntervalSeconds

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Shutting down agent...")
	server.Shutdown(context.Background())
}

// loadAndSetupAgentTLSServer loads server certificate/key and CA certificate for mTLS on the agent.
func (a *Agent) loadAndSetupAgentTLSServer() error {
	cert, err := tls.LoadX509KeyPair(a.CertFile, a.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load agent server certificate: %w", err)
	}

	caCert, err := os.ReadFile(a.CACertFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate for agent server: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to append CA certificate for agent server")
	}

	a.TlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // Require mTLS from proxy
	}
	return nil
}

// register sends initial registration information to the proxy.
func (a *Agent) register(token string) error {
	registrationData := map[string]interface{}{
		"id":     a.ID,
		"token":  token,
		"labels": a.Labels,
	}
	jsonData, err := json.Marshal(registrationData)
	if err != nil {
		return fmt.Errorf("failed to marshal registration data: %w", err)
	}

	resp, err := http.DefaultClient.Post(a.ProxyURL+registerEndpoint, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send registration request to %s: %w", a.ProxyURL+registerEndpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	log.Printf("Agent %s successfully registered with proxy.", a.ID)
	return nil
}

// startHeartbeat periodically sends heartbeats to the proxy.
func (a *Agent) startHeartbeat() {
	ticker := time.NewTicker(time.Duration(agentCfg.HeartbeatIntervalSeconds) * time.Second) // Use config value
	defer ticker.Stop()

	for range ticker.C {
		heartbeatData := map[string]string{"id": a.ID}
		jsonData, err := json.Marshal(heartbeatData)
		if err != nil {
			log.Printf("Failed to marshal heartbeat data for agent %s: %v", a.ID, err)
			continue
		}

		resp, err := http.DefaultClient.Post(a.ProxyURL+heartbeatEndpoint, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			log.Printf("Failed to send heartbeat for agent %s: %v", a.ID, err)
			// If heartbeat fails, try to re-register
			if registerErr := a.register(agentCfg.RegistrationToken); registerErr != nil {
				log.Printf("Failed to re-register agent %s after heartbeat failure: %v", a.ID, registerErr)
			} else {
				log.Printf("Agent %s successfully re-registered after heartbeat failure.", a.ID)
			}
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("Heartbeat failed for agent %s with status: %d", a.ID, resp.StatusCode)
			// If heartbeat fails, try to re-register
			if registerErr := a.register(agentCfg.RegistrationToken); registerErr != nil {
				log.Printf("Failed to re-register agent %s after heartbeat failure (status %d): %v", a.ID, resp.StatusCode, registerErr)
			} else {
				log.Printf("Agent %s successfully re-registered after heartbeat failure (status %d).", a.ID, resp.StatusCode)
			}
		} else {
			log.Printf("Heartbeat sent for agent %s.", a.ID)
			a.LastHeartbeat = time.Now()
		}
	}
}

// handleRunCommand executes a command received from the proxy.
func (a *Agent) handleRunCommand(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Agent %s: Failed to decode run command request: %v", a.ID, err)
		return
	}

	log.Printf("Agent %s: Executing command '%s %v'", a.ID, req.Command, req.Args)

	cmd := exec.Command(req.Command, req.Args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		errMsg := fmt.Sprintf("Error executing command '%s': %v\nOutput:\n%s", req.Command, err, string(output))
		http.Error(w, errMsg, http.StatusInternalServerError)
		log.Printf("Agent %s: %s", a.ID, errMsg)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"output": string(output), "status": "success"})
	log.Printf("Agent %s: Command '%s' executed successfully.", a.ID, req.Command)
}

// handleInteractiveSession manages a WebSocket-based interactive shell session.
func (a *Agent) handleInteractiveSession(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true }, // Allow all origins for simplicity in demo
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Agent %s: Failed to upgrade HTTP to WebSocket: %v", a.ID, err)
		return
	}
	defer conn.Close()
	log.Printf("Agent %s: WebSocket connection for interactive session established.", a.ID)

	// Start a shell (e.g., /bin/bash or /bin/sh)
	// You might want to make this configurable in agent.yaml
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash" // Fallback to bash if SHELL env var is not set
	}
	c := exec.Command(shell)

	// Start the command with a PTY
	ptmx, err := pty.Start(c)
	if err != nil {
		log.Printf("Agent %s: Failed to start PTY for interactive session: %v", a.ID, err)
		conn.WriteMessage(websocket.TextMessage, []byte("Error: Failed to start interactive shell.\n"))
		return
	}
	defer func() {
		_ = ptmx.Close() // Close PTY
		// Wait for the command to finish. This is important to prevent zombie processes.
		if c.ProcessState == nil || !c.ProcessState.Exited() {
			_ = c.Process.Kill()
		}
		_ = c.Wait()
		log.Printf("Agent %s: PTY and shell process for interactive session closed.", a.ID)
	}()

	// Handle incoming messages from the WebSocket (user input from CLI)
	go func() {
		for {
			mt, message, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					log.Printf("Agent %s: WebSocket closed by client: %v", a.ID, err)
				} else {
					log.Printf("Agent %s: Error reading from WebSocket: %v", a.ID, err)
				}
				// Signal to close the PTY, but not necessarily return immediately
				// as the PTY-to-WebSocket goroutine might still be running.
				return
			}
			if mt == websocket.TextMessage || mt == websocket.BinaryMessage {
				if _, err := ptmx.Write(message); err != nil {
					log.Printf("Agent %s: Error writing to PTY: %v", a.ID, err)
					return // Stop writing if PTY fails
				}
			}
		}
	}()

	// Handle outgoing messages from the PTY (shell output to CLI)
	buf := make([]byte, 1024)
	for {
		n, err := ptmx.Read(buf)
		if err != nil {
			if err == io.EOF {
				log.Printf("Agent %s: PTY EOF. Shell exited.", a.ID)
			} else {
				log.Printf("Agent %s: Error reading from PTY: %v", a.ID, err)
			}
			// Send close message to client or just let the connection close
			conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Shell exited."))
			return // Exit loop on PTY read error
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
			log.Printf("Agent %s: Error writing to WebSocket: %v", a.ID, err)
			return // Exit loop on WebSocket write error
		}
	}
}

// Helper functions for raw mode (only for CLI, not Agent itself, but kept for context if needed elsewhere)
// For agent, `pty.Start` handles much of the terminal setup automatically.
// These functions are usually for the client (CLI) side.
// Removed them from agent `main.go` as they are not directly used by agent.