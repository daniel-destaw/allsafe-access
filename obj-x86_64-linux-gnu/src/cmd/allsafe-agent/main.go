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
    "os/user"
    "path/filepath"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/creack/pty"
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
    MaximumAuditingEnabled   bool              `mapstructure:"maximum_auditing_enabled"`
    ShellPath                string            `mapstructure:"shell_path"` // NEW: Configurable shell path
}

var agentCfg AgentConfig
var cfgFile string

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
    interactiveSessionEndpoint = "/agent/interactive"
    auditEndpoint              = "/audit/agent"
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

func init() {
    cobra.OnInitialize(func() { initConfig("allsafe-agent") })
    rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/allsafe-agent/allsafe-agent.yaml or $HOME/.allsafe-agent/allsafe-agent.yaml)")
    rootCmd.Flags().String("id", "", "Agent ID (required)")
    viper.BindPFlag("id", rootCmd.Flags().Lookup("id"))
    rootCmd.Flags().String("proxy-url", "", "URL of the Allsafe Proxy (e.g., https://IpAddress:8080) (required)")
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
    rootCmd.Flags().Bool("maximum-auditing-enabled", false, "Enable maximum auditing to capture and log all shell commands")
    viper.BindPFlag("maximum_auditing_enabled", rootCmd.Flags().Lookup("maximum-auditing-enabled"))
    // NEW: Add a flag for the shell path
    rootCmd.Flags().String("shell-path", "", "Path to the shell executable (e.g., /bin/bash)")
    viper.BindPFlag("shell_path", rootCmd.Flags().Lookup("shell-path"))

    viper.SetDefault("listen_address", ":8081")
    viper.SetDefault("cert_file", "/etc/allsafe-agent/agent.crt")
    viper.SetDefault("key_file", "/etc/allsafe-agent/agent.key")
    viper.SetDefault("ca_cert_file", "/etc/allsafe-agent/ca.crt")
    viper.SetDefault("heartbeat_interval_seconds", 30)
    viper.SetDefault("labels", map[string]string{})
    viper.SetDefault("registration_token", "")
    viper.SetDefault("maximum_auditing_enabled", false)
    // NEW: Set a default shell path
    viper.SetDefault("shell_path", "/bin/bash")
}

var rootCmd = &cobra.Command{
    Use:   "allsafe-agent",
    Short: "Allsafe Agent",
    Long:  `Allsafe Agent registers with a proxy and executes commands.`,
    Args:  cobra.NoArgs,
    Run:   runAgent,
}

func main() {
    if err := rootCmd.Execute(); err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
}

func runAgent(cmd *cobra.Command, args []string) {
    if err := viper.Unmarshal(&agentCfg); err != nil {
        log.Fatalf("Unable to decode agent config into struct: %v", err)
    }

    if agentCfg.ID == "" {
        log.Fatal("Agent ID is required. Please provide it via 'id' in config file or --id flag.")
    }
    if agentCfg.ProxyURL == "" {
        log.Fatal("Proxy URL is required. Please provide it via 'proxy_url' in config file or --proxy-url flag.")
    }

    log.Printf("Loaded Agent Config: %+v\n", agentCfg)

    agent := &Agent{
        ID:         agentCfg.ID,
        ProxyURL:   agentCfg.ProxyURL,
        Labels:     agentCfg.Labels,
        CertFile:   agentCfg.CertFile,
        KeyFile:    agentCfg.KeyFile,
        CACertFile: agentCfg.CACertFile,
    }

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
    http.DefaultClient.Timeout = 30 * time.Second

    if err := agent.loadAndSetupAgentTLSServer(); err != nil {
        log.Fatalf("Failed to load agent server TLS configuration: %v", err)
    }

    if err := agent.register(agentCfg.RegistrationToken); err != nil {
        log.Printf("Agent initial registration failed: %v. Will retry registration via heartbeat.", err)
    }

    mux := http.NewServeMux()
    mux.HandleFunc(runCommandEndpoint, agent.handleRunCommand)
    mux.HandleFunc(interactiveSessionEndpoint, agent.handleInteractiveSession)

    server := &http.Server{
        Addr:      agentCfg.ListenAddress,
        Handler:   mux,
        TLSConfig: agent.TlsConfig,
    }

    go func() {
        log.Printf("Agent %s listening for proxy connections on %s...", agent.ID, server.Addr)
        if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
            log.Fatalf("Agent server failed: %v", err)
        }
    }()

    go agent.startHeartbeat()

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
        return fmt.Errorf("failed to read CA certificate for agent: %w", err)
    }
    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
        return fmt.Errorf("failed to append CA certificate for agent")
    }

    a.TlsConfig = &tls.Config{
        Certificates: []tls.Certificate{cert},
        ClientCAs:    caCertPool,
        ClientAuth:   tls.RequireAndVerifyClientCert, // Enforce mTLS for Proxy connections
    }
    return nil
}

// register sends agent's info to the proxy.
func (a *Agent) register(token string) error {
    reqBody, err := json.Marshal(map[string]interface{}{
        "id":     a.ID,
        "token":  token,
        "labels": a.Labels,
    })
    if err != nil {
        return fmt.Errorf("failed to marshal registration request: %w", err)
    }

    resp, err := http.DefaultClient.Post(a.ProxyURL+registerEndpoint, "application/json", bytes.NewBuffer(reqBody))
    if err != nil {
        return fmt.Errorf("failed to send registration request: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        bodyBytes, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(bodyBytes))
    }

    log.Printf("Agent %s registered successfully.", a.ID)
    a.LastHeartbeat = time.Now() // Record successful registration as first heartbeat
    return nil
}

// startHeartbeat periodically sends heartbeats to the proxy.
func (a *Agent) startHeartbeat() {
    ticker := time.NewTicker(time.Duration(agentCfg.HeartbeatIntervalSeconds) * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        reqBody, err := json.Marshal(map[string]string{"id": a.ID})
        if err != nil {
            log.Printf("Agent %s: Failed to marshal heartbeat request: %v", a.ID, err)
            continue
        }

        resp, err := http.DefaultClient.Post(a.ProxyURL+heartbeatEndpoint, "application/json", bytes.NewBuffer(reqBody))
        if err != nil {
            log.Printf("Agent %s: Failed to send heartbeat: %v", a.ID, err)
            if err := a.register(agentCfg.RegistrationToken); err != nil {
                log.Printf("Agent %s: Re-registration attempt failed after heartbeat error: %v", a.ID, err)
            }
            continue
        }
        resp.Body.Close() // Ensure body is closed

        if resp.StatusCode != http.StatusOK {
            bodyBytes, _ := io.ReadAll(resp.Body)
            log.Printf("Agent %s: Heartbeat failed with status %d: %s", a.ID, resp.StatusCode, string(bodyBytes))
            if err := a.register(agentCfg.RegistrationToken); err != nil {
                log.Printf("Agent %s: Re-registration attempt failed after non-OK heartbeat status: %v", a.ID, err)
            }
            continue
        }
        a.LastHeartbeat = time.Now()
        log.Printf("Agent %s: Heartbeat sent successfully.", a.ID)
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

    log.Printf("Agent %s: Executing command: %s %v", a.ID, req.Command, req.Args)

    cmd := exec.Command(req.Command, req.Args...)
    output, err := cmd.CombinedOutput()
    status := "success"
    if err != nil {
        status = fmt.Sprintf("failed: %v", err)
        log.Printf("Agent %s: Command execution failed: %v", a.ID, err)
    }

    resp := map[string]string{
        "output": string(output),
        "status": status,
    }

    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(resp); err != nil {
        log.Printf("Agent %s: Failed to encode run command response: %v", a.ID, err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
    }
}

// sendAuditToProxy sends a new audit event to the proxy for logging.
func (a *Agent) sendAuditToProxy(userID, eventType, action, details string) {
    event := map[string]string{
        "component_id": a.ID,
        "user_id":      userID,
        "event_type":   eventType,
        "action":       action,
        "details":      details,
    }

    reqBody, err := json.Marshal(event)
    if err != nil {
        log.Printf("Agent %s: Failed to marshal audit event: %v", a.ID, err)
        return
    }

    resp, err := http.DefaultClient.Post(a.ProxyURL+auditEndpoint, "application/json", bytes.NewBuffer(reqBody))
    if err != nil {
        log.Printf("Agent %s: Failed to send audit event to proxy: %v", a.ID, err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        bodyBytes, _ := io.ReadAll(resp.Body)
        log.Printf("Agent %s: Audit event failed with status %d: %s", a.ID, resp.StatusCode, string(bodyBytes))
    }
}

// handleInteractiveSession manages a WebSocket-based interactive shell session.
func (a *Agent) handleInteractiveSession(w http.ResponseWriter, r *http.Request) {
    upgrader := websocket.Upgrader{
        CheckOrigin:     func(r *http.Request) bool { return true }, // Allow all origins for demo
        ReadBufferSize:  1024,
        WriteBufferSize: 1024,
    }

    userID := r.URL.Query().Get("user_id")
    loginUser := r.URL.Query().Get("login_user")

    targetUser, err := user.Lookup(loginUser)
    if err != nil {
        log.Printf("Agent %s: Login user '%s' not found: %v", a.ID, loginUser, err)
        ws, _ := upgrader.Upgrade(w, r, nil)
        defer ws.Close()
        ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Error: Remote user '%s' does not exist.\n", loginUser)))
        return
    }

    log.Printf("Agent %s: Starting interactive session for CLI user '%s' (requesting remote login as '%s').", a.ID, userID, loginUser)

    ws, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("Agent %s: Failed to upgrade connection to WebSocket: %v", a.ID, err)
        return
    }
    defer ws.Close()

    // Determine the shell to use.
    // 1. Use the value from the config/flag first.
    // 2. Fallback to the SHELL environment variable.
    shellPath := agentCfg.ShellPath
    if shellPath == "" {
        shellPath = os.Getenv("SHELL")
        if shellPath == "" {
            shellPath = "/bin/sh" // Final fallback if all else fails
        }
    }
    // Now check if the resolved shell path exists
    if _, err := os.Stat(shellPath); os.IsNotExist(err) {
        log.Printf("Agent %s: Configured shell '%s' not found.", a.ID, shellPath)
        ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Error: Configured shell '%s' not found on agent.\n", shellPath)))
        return
    }

    log.Printf("Agent %s: Using shell: %s", a.ID, shellPath)

    cmd := exec.Command(shellPath, "-i", "-l") // -i for interactive, -l for login shell

    uid, _ := strconv.Atoi(targetUser.Uid)
    gid, _ := strconv.Atoi(targetUser.Gid)
    cmd.SysProcAttr = &syscall.SysProcAttr{}
    cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
    cmd.Dir = targetUser.HomeDir

    currentEnv := os.Environ()
    filteredEnv := []string{}
    for _, envVar := range currentEnv {
        if !strings.HasPrefix(envVar, "USER=") &&
            !strings.HasPrefix(envVar, "LOGNAME=") &&
            !strings.HasPrefix(envVar, "HOME=") &&
            !strings.HasPrefix(envVar, "PS1=") &&
            !strings.HasPrefix(envVar, "AGENT_ID=") &&
            !strings.HasPrefix(envVar, "ALLSAFE_CLI_USER_ID=") {
            filteredEnv = append(filteredEnv, envVar)
        }
    }
    cmd.Env = filteredEnv

    cmd.Env = append(cmd.Env, fmt.Sprintf("USER=%s", targetUser.Username))
    cmd.Env = append(cmd.Env, fmt.Sprintf("LOGNAME=%s", targetUser.Username))
    cmd.Env = append(cmd.Env, fmt.Sprintf("HOME=%s", targetUser.HomeDir))

    customPS1 := fmt.Sprintf("[%s@%s %s]$ ", userID, a.ID, filepath.Base(targetUser.HomeDir))
    cmd.Env = append(cmd.Env, fmt.Sprintf("PS1=%s", customPS1))

    cmd.Env = append(cmd.Env, fmt.Sprintf("AGENT_ID=%s", a.ID))
    cmd.Env = append(cmd.Env, fmt.Sprintf("ALLSAFE_CLI_USER_ID=%s", userID))

    ptmx, err := pty.Start(cmd)
    if err != nil {
        log.Printf("Agent %s: Failed to start PTY for interactive session: %v", a.ID, err)
        ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Error: Failed to start shell on agent: %v\n", err)))
        return
    }
    log.Printf("Agent %s: PTY started for shell: %s", a.ID, shellPath)

    defer func() {
        _ = ptmx.Close()
        if err := cmd.Wait(); err != nil {
            log.Printf("Agent %s: Shell command exited with error: %v", a.ID, err)
        } else {
            log.Printf("Agent %s: Shell command exited normally.", a.ID)
        }
    }()

    var wg sync.WaitGroup
    wg.Add(2)

    go func() {
        defer wg.Done()
        buf := make([]byte, 1024)
        for {
            n, err := ptmx.Read(buf)
            if err != nil {
                if err == io.EOF {
                    log.Printf("Agent %s: PTY EOF. Shell probably exited.", a.ID)
                } else {
                    log.Printf("Agent %s: Error reading from PTY: %v", a.ID, err)
                }
                ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "PTY closed"))
                return
            }
            if n > 0 {
                if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
                    log.Printf("Agent %s: Error writing to WebSocket (as BinaryMessage): %v", a.ID, err)
                    return
                }
            }
        }
    }()

    go func() {
        defer wg.Done()
        var commandBuffer bytes.Buffer
        for {
            messageType, p, err := ws.ReadMessage()
            if err != nil {
                if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
                    log.Printf("Agent %s: WebSocket closed by remote (CLI/Proxy): %v", a.ID, err)
                } else {
                    log.Printf("Agent %s: Error reading from WebSocket: %v", a.ID, err)
                }
                break
            }

            switch messageType {
            case websocket.TextMessage, websocket.BinaryMessage:
                if agentCfg.MaximumAuditingEnabled {
                    for _, b := range p {
                        if b == 127 {
                            if commandBuffer.Len() > 0 {
                                bufferBytes := commandBuffer.Bytes()
                                commandBuffer.Reset()
                                commandBuffer.Write(bufferBytes[:len(bufferBytes)-1])
                            }
                        } else if b == '\r' || b == '\n' {
                            command := strings.TrimSpace(commandBuffer.String())
                            if command != "" {
                                log.Printf("Agent %s: Captured command '%s' for CLI user '%s'", a.ID, command, userID)
                                a.sendAuditToProxy(userID, "MAXIMUM_AUDIT", "SHELL_COMMAND", command)
                            }
                            commandBuffer.Reset()
                        } else if b >= 32 {
                            commandBuffer.WriteByte(b)
                        }
                    }
                }

                _, err = ptmx.Write(p)
                if err != nil {
                    log.Printf("Agent %s: Error writing to PTY: %v", a.ID, err)
                    break
                }
            case websocket.CloseMessage:
                log.Printf("Agent %s: Received WebSocket close message from remote.", a.ID)
                return
            }
        }
        log.Printf("Agent %s: WebSocket to PTY copier stopped.", a.ID)
    }()

    wg.Wait()
    log.Printf("Agent %s: Interactive session handler completed for CLI user '%s' (remote login '%s').", a.ID, userID, loginUser)
}