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
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ProxyConfig defines the structure for proxy.yaml configuration
type ProxyConfig struct {
	ListenAddress               string            `mapstructure:"listen_address"`
	CertFile                    string            `mapstructure:"cert_file"`
	KeyFile                     string            `mapstructure:"key_file"`
	CACertFile                  string            `mapstructure:"ca_cert_file"`
	AgentListenPort             int               `mapstructure:"agent_listen_port"`
	AgentHeartbeatTimeoutMinutes int               `mapstructure:"agent_heartbeat_timeout_minutes"`
	RegistrationToken           string            `mapstructure:"registration_token"` // For proxy to validate agents
}

var proxyCfg ProxyConfig // Global variable to hold proxy configuration
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
		viper.AddConfigPath(fmt.Sprintf("/etc/%s", appName)) // e.g., /etc/allsafe-proxy
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(filepath.Join(home, fmt.Sprintf(".%s", appName))) // e.g., $HOME/.allsafe-cli
		}
		viper.AddConfigPath(".")      // Current directory
		viper.SetConfigName(appName)  // Config file name, e.g., 'allsafe-proxy.yaml'
	}

	viper.SetConfigType("yaml") // Expects YAML files

	// Automatically read environment variables that match Viper keys
	// e.g., ALLSAFE_PROXY_LISTEN_ADDRESS will map to 'listen_address' in config
	viper.AutomaticEnv()
	// Replace dots and hyphens with underscores for env variable matching (e.g., "listen-address" or "listen.address" -> "LISTEN_ADDRESS")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if not critical, defaults/flags will be used
			log.Printf("No config file found for %s. Using defaults or flags. Error: %v\n", appName, err)
		} else {
			// Config file was found but another error was produced (e.g., parse error)
			log.Fatalf("Error reading config file for %s: %v\n", appName, err)
		}
	}
}

// Constants for API endpoints
const (
	registerEndpoint           = "/register"
	heartbeatEndpoint          = "/heartbeat"
	runCommandEndpoint         = "/run-command"
	listNodesEndpoint          = "/list-nodes"
	cliShellEndpoint           = "/cli/shell"
	interactiveSessionEndpoint = "/agent/interactive"
)

type AgentInfo struct {
	ID            string
	IPAddress     string
	Labels        map[string]string
	LastHeartbeat time.Time
}

var (
	agents        = make(map[string]AgentInfo)
	agentsMutex   sync.RWMutex
	tlsConfig     *tls.Config
	agentWsDialer *websocket.Dialer // Dialer for proxy -> agent WebSocket connections
)

// init function for Cobra commands and Viper setup
func init() {
	// Call initConfig with the specific app name "allsafe-proxy"
	cobra.OnInitialize(func() { initConfig("allsafe-proxy") })

	// Define persistent flag for config file
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/allsafe-proxy/allsafe-proxy.yaml or $HOME/.allsafe-proxy/allsafe-proxy.yaml)")

	// Define and bind specific flags to Viper keys for optional override
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

	// Set defaults for Viper keys (these will be overridden by config file or flags)
	viper.SetDefault("listen_address", ":8080")
	viper.SetDefault("cert_file", "/etc/allsafe-proxy/proxy.crt")
	viper.SetDefault("key_file", "/etc/allsafe-proxy/proxy.key")
	viper.SetDefault("ca_cert_file", "/etc/allsafe-proxy/ca.crt")
	viper.SetDefault("agent_listen_port", 8081)
	viper.SetDefault("agent_heartbeat_timeout_minutes", 5) // 5 minutes default
	viper.SetDefault("registration_token", "")              // Default to no token required, but highly recommended to set a strong one
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
	// Unmarshal the configuration into the struct after initConfig has run
	if err := viper.Unmarshal(&proxyCfg); err != nil {
		log.Fatalf("Unable to decode proxy config into struct: %v", err)
	}

	log.Printf("Loaded Proxy Config: %+v\n", proxyCfg) // For debugging the loaded config

	var err error
	tlsConfig, err = loadAndSetupTLSServer(proxyCfg.CertFile, proxyCfg.KeyFile, proxyCfg.CACertFile)
	if err != nil {
		log.Fatalf("Failed to load TLS configuration: %v", err)
	}

	// Setup agent WebSocket dialer with mTLS for proxy-to-agent communication
	proxyClientCert, err := tls.LoadX509KeyPair(proxyCfg.CertFile, proxyCfg.KeyFile)
	if err != nil {
		log.Fatalf("Failed to load proxy client certificate for agent dialer: %v", err)
	}
	caCert, err := os.ReadFile(proxyCfg.CACertFile)
	if err != nil {
		log.Fatalf("Failed to read CA certificate for agent dialer: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("Failed to append CA certificate for agent dialer")
	}

	agentWsDialer = &websocket.Dialer{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{proxyClientCert},
			RootCAs:      caCertPool,
		},
		HandshakeTimeout: 45 * time.Second,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(registerEndpoint, handleRegister)
	mux.HandleFunc(heartbeatEndpoint, handleHeartbeat)
	mux.HandleFunc(runCommandEndpoint, handleRunCommand)
	mux.HandleFunc(listNodesEndpoint, handleListNodes)
	mux.HandleFunc(cliShellEndpoint, handleCLIInteractiveRequest)

	server := &http.Server{
		Addr:      proxyCfg.ListenAddress, // Use configured listen address
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	go func() {
		log.Printf("Allsafe Proxy listening on https://%s...", server.Addr)
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Proxy server failed: %v", err)
		}
	}()

	go cleanupOldAgents() // This will now use proxyCfg.AgentHeartbeatTimeoutMinutes

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Shutting down proxy...")
	server.Shutdown(context.Background())
}

// loadAndSetupTLSServer loads server certificate/key and CA certificate for mTLS.
func loadAndSetupTLSServer(certFile, keyFile, caCertFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

// handleRegister processes new agent registrations.
func handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     string            `json:"id"`
		Token  string            `json:"token"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Failed to decode register request: %v", err)
		return
	}

	log.Printf("Received registration from Agent ID: %s", req.ID)

	// Validate the registration token if configured
	if proxyCfg.RegistrationToken != "" && req.Token != proxyCfg.RegistrationToken {
		log.Printf("Agent %s provided invalid token.", req.ID)
		http.Error(w, "Invalid registration token", http.StatusUnauthorized)
		return
	} else if proxyCfg.RegistrationToken == "" && req.Token != "" {
		log.Printf("WARNING: Agent %s provided a token '%s', but proxy is not configured to require one.", req.ID, req.Token)
	} else if proxyCfg.RegistrationToken != "" && req.Token == "" {
		log.Printf("WARNING: Agent %s did not provide a token, but proxy expects one.", req.ID)
		http.Error(w, "Registration token required", http.StatusUnauthorized)
		return
	} else {
        log.Printf("Agent %s token validation successful (or not required).", req.ID)
    }

	// Extract client IP. r.RemoteAddr usually gives "IP:Port".
	// For production, consider X-Forwarded-For if behind a load balancer.
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

// handleHeartbeat updates the last heartbeat time for an agent.
func handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Failed to decode heartbeat request: %v", err)
		return
	}

	agentsMutex.Lock()
	if info, ok := agents[req.ID]; ok {
		info.LastHeartbeat = time.Now()
		agents[req.ID] = info
		log.Printf("Heartbeat from Agent ID: %s", req.ID)
	} else {
		log.Printf("Heartbeat from unknown Agent ID: %s. Agent must register first.", req.ID)
		http.Error(w, "Agent not registered", http.StatusNotFound)
		agentsMutex.Unlock()
		return
	}
	agentsMutex.Unlock()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "heartbeat_received"})
}

// handleListNodes returns a list of currently active agents.
func handleListNodes(w http.ResponseWriter, r *http.Request) {
	agentsMutex.RLock()
	defer agentsMutex.RUnlock()

	var activeAgents []AgentInfo
	timeout := time.Duration(proxyCfg.AgentHeartbeatTimeoutMinutes) * time.Minute
	for _, agent := range agents {
		if time.Since(agent.LastHeartbeat) < timeout {
			activeAgents = append(activeAgents, agent)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(activeAgents); err != nil {
		log.Printf("Failed to encode agent list: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleRunCommand forwards a command request to an agent and returns its output.
func handleRunCommand(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID  string   `json:"node_id"`
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Failed to decode run command request: %v", err)
		return
	}

	agentsMutex.RLock()
	agent, ok := agents[req.NodeID]
	agentsMutex.RUnlock()

	if !ok {
		http.Error(w, "Node not found or not active", http.StatusNotFound)
		log.Printf("Attempted to run command on unknown node: %s", req.NodeID)
		return
	}

	log.Printf("Forwarding command '%s %v' to agent %s (%s)", req.Command, req.Args, agent.ID, agent.IPAddress)

	// Forward command to agent using HTTP POST with mTLS (DefaultClient configured)
	commandReq := map[string]interface{}{
		"command": req.Command,
		"args":    req.Args,
	}
	jsonData, err := json.Marshal(commandReq)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("Failed to marshal command data: %v", err)
		return
	}

	resp, err := http.DefaultClient.Post(fmt.Sprintf("https://%s:%d%s", agent.IPAddress, proxyCfg.AgentListenPort, runCommandEndpoint), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(w, "Failed to forward command to agent", http.StatusBadGateway)
		log.Printf("Error forwarding command to agent %s (%s): %v", agent.ID, agent.IPAddress, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("Agent %s returned non-OK status %d: %s", agent.ID, resp.StatusCode, string(bodyBytes))
		http.Error(w, fmt.Sprintf("Agent returned error: %s", string(bodyBytes)), resp.StatusCode)
		return
	}

	// Read and forward agent's response back to CLI
	w.Header().Set("Content-Type", "application/json")
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Failed to copy agent response to client: %v", err)
	}
}

// handleCLIInteractiveRequest establishes a bidirectional WebSocket session between CLI and Agent.
func handleCLIInteractiveRequest(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		http.Error(w, "Node ID is required", http.StatusBadRequest)
		return
	}

	agentsMutex.RLock()
	agent, ok := agents[nodeID]
	agentsMutex.RUnlock()

	if !ok {
		http.Error(w, "Node not found or not active", http.StatusNotFound)
		log.Printf("Attempted interactive session with unknown node: %s", nodeID)
		return
	}

	log.Printf("Establishing interactive session with agent %s (%s)...", agent.ID, agent.IPAddress)

	// 1. Upgrade HTTP request from CLI to WebSocket for proxy
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true }, // Allow all origins for simplicity in demo
	}
	cliWs, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade CLI connection to WebSocket: %v", err)
		return
	}
	defer cliWs.Close()

	// 2. Establish WebSocket connection to Agent's interactive endpoint (using mTLS dialer)
	agentWsURL := fmt.Sprintf("wss://%s:%d%s", agent.IPAddress, proxyCfg.AgentListenPort, interactiveSessionEndpoint)
	agentWs, _, err := agentWsDialer.Dial(agentWsURL, nil)
	if err != nil {
		log.Printf("Failed to dial agent %s interactive session: %v", agent.ID, err)
		cliWs.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Error: Could not connect to agent %s interactive session.\n", agent.ID)))
		return
	}
	defer agentWs.Close()

	log.Printf("Interactive session established between CLI and Agent %s (%s)", agent.ID, agent.IPAddress)

	// 3. Bidirectionally relay messages between CLI and Agent WebSockets
	var wg sync.WaitGroup
	wg.Add(2)

	// CLI to Agent
	go func() {
		defer wg.Done()
		for {
			mt, message, err := cliWs.ReadMessage()
			if err != nil {
				log.Printf("Error reading from CLI WebSocket for agent %s: %v", agent.ID, err)
				return
			}
			if err := agentWs.WriteMessage(mt, message); err != nil {
				log.Printf("Error writing to Agent WebSocket for agent %s: %v", agent.ID, err)
				return
			}
		}
	}()

	// Agent to CLI
	go func() {
		defer wg.Done()
		for {
			mt, message, err := agentWs.ReadMessage()
			if err != nil {
				log.Printf("Error reading from Agent WebSocket for agent %s: %v", agent.ID, err)
				return
			}
			if err := cliWs.WriteMessage(mt, message); err != nil {
				log.Printf("Error writing to CLI WebSocket for agent %s: %v", agent.ID, err)
				return
			}
		}
	}()

	wg.Wait()
	log.Printf("Interactive session with agent %s (%s) closed.", agent.ID, agent.IPAddress)
}

// cleanupOldAgents periodically removes agents that haven't sent heartbeats within the timeout.
func cleanupOldAgents() {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	for range ticker.C {
		agentsMutex.Lock()
		now := time.Now()
		for id, agent := range agents {
			if now.Sub(agent.LastHeartbeat) > time.Duration(proxyCfg.AgentHeartbeatTimeoutMinutes)*time.Minute {
				log.Printf("Agent %s (%s) has not sent a heartbeat for %v. Removing from active list.", id, agent.IPAddress, now.Sub(agent.LastHeartbeat))
				delete(agents, id)
			}
		}
		agentsMutex.Unlock()
	}
}