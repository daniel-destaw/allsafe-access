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
    "os/signal"
    "path/filepath"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/fatih/color"
    "github.com/gorilla/websocket"
    "github.com/spf13/cobra"
    "github.com/spf13/viper"
    "golang.org/x/term"

    "allsafe-access/pkg/auth"
    "allsafe-access/pkg/session"
)

// CLIConfig defines the structure for cli.yaml configuration
type CLIConfig struct {
    ProxyURL       string `mapstructure:"proxy_url"`
    CACertFile     string `mapstructure:"ca_cert_file"`
    UsersConfigDir string `mapstructure:"users_config_dir"`
    RolesConfigDir string `mapstructure:"roles_config_dir"`
    SessionDir     string `mapstructure:"session_dir"`
}

var (
    cliCfg           CLIConfig
    cfgFile          string
    proxyURLOverride string

    authChecker    *auth.AuthChecker
    sessionManager session.Manager
    currentSession *session.SessionTokenContent
)

const (
    listNodesEndpoint  = "/list-nodes"
    cliShellEndpoint   = "/cli/shell"
    runCommandEndpoint = "/run-command"
)

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
        fmt.Fprintf(os.Stderr, "Loaded CLI Config: %s\n", viper.ConfigFileUsed())
    } else {
        if _, ok := err.(viper.ConfigFileNotFoundError); ok {
            log.Printf("No config file found for %s. Using defaults or flags. Error: %v\n", appName, err)
        } else {
            log.Fatalf("Error reading config file for %s: %v\n", appName, err)
        }
    }
}

func init() {
    cobra.OnInitialize(func() {
        initConfig("allsafe-cli")
        if err := viper.Unmarshal(&cliCfg); err != nil {
            log.Fatalf("Unable to decode CLI config into struct: %v", err)
        }
        log.Printf("Loaded CLI Config: {ProxyURL:%s CACertFile:%s UsersConfigDir:%s RolesConfigDir:%s SessionDir:%s}\n",
            cliCfg.ProxyURL, cliCfg.CACertFile, cliCfg.UsersConfigDir, cliCfg.RolesConfigDir, cliCfg.SessionDir)

        var err error
        if cliCfg.UsersConfigDir == "" {
            cliCfg.UsersConfigDir = viper.GetString("users_config_dir")
        }
        if cliCfg.RolesConfigDir == "" {
            cliCfg.RolesConfigDir = viper.GetString("roles_config_dir")
        }

        authChecker, err = auth.NewAuthChecker(cliCfg.UsersConfigDir, cliCfg.RolesConfigDir)
        if err != nil {
            log.Fatalf("Failed to initialize AuthChecker: %v", err)
        }

        if cliCfg.SessionDir == "" {
            cliCfg.SessionDir = viper.GetString("session_dir")
        }
        sessionManager, err = session.NewFileSessionManager(cliCfg.SessionDir)
        if err != nil {
            log.Fatalf("Failed to initialize session manager: %v", err)
        }

        currentSession, err = sessionManager.LoadSession()
        if err != nil {
            log.Printf("Warning: Could not load session: %v", err)
        }
        if currentSession != nil {
            log.Printf("Session loaded for user: %s", currentSession.User.Username)
        }
    })

    rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/allsafe-cli/allsafe-cli.yaml or $HOME/.allsafe-cli/allsafe-cli.yaml)")
    rootCmd.PersistentFlags().StringVarP(&proxyURLOverride, "proxy", "p", "", "Override Allsafe Proxy URL (e.g., https://10.195.130.14:8080)")

    rootCmd.AddCommand(loginCmd)
    rootCmd.AddCommand(logoutCmd)
    rootCmd.AddCommand(listNodesCmd)
    rootCmd.AddCommand(accessCmd)
    rootCmd.AddCommand(runCommandCmd)
    rootCmd.AddCommand(shellCmd)
    viper.SetDefault("proxy_url", "https://10.195.130.14:8080")
    viper.SetDefault("ca_cert_file", "./configs/certs/cli_ca.crt")
    viper.SetDefault("users_config_dir", "./configs/users")
    viper.SetDefault("roles_config_dir", "./configs/roles")
    home, _ := os.UserHomeDir()
    viper.SetDefault("session_dir", filepath.Join(home, ".allsafe-cli"))
}

var rootCmd = &cobra.Command{
    Use:   "allsafe-cli",
    Short: "Allsafe Command Line Interface",
    Long:  `The Allsafe CLI allows secure interaction with registered agents via the Allsafe Proxy.`,
}

func main() {
    if err := rootCmd.Execute(); err != nil {
        if !strings.Contains(err.Error(), "unknown command") && !strings.Contains(err.Error(), "help") {
            fmt.Fprintf(os.Stderr, "Error: %v\n", err)
            os.Exit(1)
        }
    }
}

var shellCmd = &cobra.Command{
    Use:    "shell",
    Short:  "Enter interactive Allsafe CLI shell (internal command)",
    Hidden: true,
    Run: func(cmd *cobra.Command, args []string) {
        runInteractiveShell(cmd.Root())
    },
}

var loginCmd = &cobra.Command{
    Use:   "login [username]",
    Short: "Login to the Allsafe CLI",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        username := args[0]
        effectiveProxyURL := cliCfg.ProxyURL
        if proxyURLOverride != "" {
            effectiveProxyURL = proxyURLOverride
        } else {
            if !viper.IsSet("proxy_url") {
                fmt.Println(color.YellowString("Warning: No proxy URL specified in config or via --proxy flag. Using default: %s", effectiveProxyURL))
            }
        }
        fmt.Printf("allsafe proxy=%s user=%s\n", effectiveProxyURL, username)
        fmt.Printf("Enter password for %s: ", username)
        bytePassword, err := term.ReadPassword(int(syscall.Stdin))
        if err != nil {
            fmt.Println("Error reading password:", err)
            return
        }
        password := string(bytePassword)
        fmt.Println()
        userObj, userPermissions, err := authChecker.VerifyUserAndGetPermissions(username, password)
        if err != nil {
            fmt.Printf("Login failed: %v\n", err)
            return
        }
        currentSession = &session.SessionTokenContent{
            User:        userObj,
            Permissions: userPermissions,
            ProxyURL:    effectiveProxyURL,
        }
        if err := sessionManager.CreateSession(currentSession); err != nil {
            fmt.Println("Failed to save session:", err)
        }
        fmt.Printf("Successfully logged in as %s.\n", currentSession.User.Username)
        runInteractiveShell(cmd.Root())
    },
}

var logoutCmd = &cobra.Command{
    Use:   "logout",
    Short: "Logout from the Allsafe CLI",
    Run: func(cmd *cobra.Command, args []string) {
        if currentSession == nil || currentSession.User == nil {
            fmt.Println("You are not currently logged in.")
            return
        }
        fmt.Println("Logging out...")
        currentSession = nil
        if err := sessionManager.ClearSession(); err != nil {
            fmt.Println("Failed to clear session file:", err)
        }
        fmt.Println("You have been successfully logged out.")
    },
}

func runInteractiveShell(root *cobra.Command) {
    reader := os.Stdin
    green := color.New(color.FgGreen).SprintFunc()
    scanner := NewLineScanner(reader)
    for {
        if currentSession == nil || currentSession.User == nil {
            fmt.Println("Session ended. Please login again.")
            break
        }
        promptUser := "allsafe"
        if currentSession.User != nil {
            promptUser = fmt.Sprintf("%s@%s", currentSession.User.Username, promptUser)
        }
        fmt.Printf("%s> ", green(promptUser))
        line, err := scanner.ScanLine()
        if err != nil {
            if err == io.EOF {
                fmt.Println("\nExiting Allsafe CLI.")
                break
            }
            log.Printf("Error reading input: %v", err)
            continue
        }
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        if line == "exit" || line == "quit" {
            logoutCmd.Run(root, []string{})
            break
        }
        args := strings.Fields(line)
        tempRoot := &cobra.Command{
            Use:           root.Use,
            Short:         root.Short,
            Long:          root.Long,
            SilenceUsage:  true,
            SilenceErrors: true,
        }
        for _, cmd := range root.Commands() {
            tempRoot.AddCommand(cmd)
        }
        oldStdout := os.Stdout
        oldStderr := os.Stderr
        rPipe, wPipe, _ := os.Pipe()
        os.Stdout = wPipe
        os.Stderr = wPipe
        tempRoot.SetArgs(args)
        executeErr := tempRoot.Execute()
        wPipe.Close()
        out, _ := io.ReadAll(rPipe)
        os.Stdout = oldStdout
        os.Stderr = oldStderr
        if executeErr != nil {
            if strings.Contains(executeErr.Error(), "unknown command") || strings.Contains(executeErr.Error(), "unknown flag") {
                fmt.Fprintf(os.Stderr, "Unknown Allsafe command: '%s'. Use 'help' to see available commands.\n", args[0])
            } else {
                fmt.Fprintf(os.Stderr, "Command error: %v\n", executeErr)
            }
        }
        fmt.Print(string(out))
    }
}

type LineScanner struct {
    reader *io.Reader
    buffer []byte
}

func NewLineScanner(r io.Reader) *LineScanner {
    return &LineScanner{reader: &r, buffer: make([]byte, 0)}
}

func (s *LineScanner) ScanLine() (string, error) {
    for {
        b := make([]byte, 1)
        n, err := (*s.reader).Read(b)
        if err != nil {
            if err == io.EOF && len(s.buffer) > 0 {
                line := string(s.buffer)
                s.buffer = make([]byte, 0)
                return line, nil
            }
            return "", err
        }
        if n == 0 {
            continue
        }
        char := b[0]
        if char == '\n' || char == '\r' {
            line := string(s.buffer)
            s.buffer = make([]byte, 0)
            if char == '\r' {
                peekBuf := make([]byte, 1)
                (*s.reader).Read(peekBuf)
            }
            return line, nil
        }
        s.buffer = append(s.buffer, char)
    }
}

func createHTTPClient() (*http.Client, error) {
    caCertFile := cliCfg.CACertFile
    if caCertFile == "" {
        return nil, fmt.Errorf("CA certificate file is not configured")
    }
    caCert, err := os.ReadFile(caCertFile)
    if err != nil {
        return nil, fmt.Errorf("failed to read CA certificate from %s: %w", caCertFile, err)
    }
    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
        return nil, fmt.Errorf("failed to append CA certificate to pool")
    }
    tlsConfig := &tls.Config{
        RootCAs: caCertPool,
    }
    tr := &http.Transport{TLSClientConfig: tlsConfig}
    client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
    return client, nil
}

var listNodesCmd = &cobra.Command{
    Use:   "list-nodes",
    Short: "List active agents",
    Run: func(cmd *cobra.Command, args []string) {
        if currentSession == nil || currentSession.User == nil {
            fmt.Println("Error: Not logged in. Please use 'login <username>'")
            return
        }
        client, err := createHTTPClient()
        if err != nil {
            fmt.Printf("Error creating HTTP client: %v\n", err)
            return
        }
        proxyURL := currentSession.ProxyURL
        resp, err := client.Get(proxyURL + listNodesEndpoint)
        if err != nil {
            fmt.Printf("Error listing nodes: %v\n", err)
            return
        }
        defer resp.Body.Close()
        if resp.StatusCode != http.StatusOK {
            bodyBytes, _ := io.ReadAll(resp.Body)
            fmt.Printf("Error from proxy (%d): %s\n", resp.StatusCode, string(bodyBytes))
            return
        }
        var agents []map[string]interface{}
        if err := json.NewDecoder(resp.Body).Decode(&agents); err != nil {
            fmt.Printf("Error decoding response: %v\n", err)
            return
        }
        fmt.Println("Active Agents:")
        for _, agent := range agents {
            fmt.Printf("  ID: %s, IP: %s, Last Heartbeat: %s, Labels: %v\n",
                agent["ID"], agent["IPAddress"], agent["LastHeartbeat"], agent["Labels"])
        }
    },
}

var accessCmd = &cobra.Command{
    Use:   "access [node-id]",
    Short: "Access an agent's interactive shell",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        if currentSession == nil || currentSession.User == nil {
            fmt.Println("Error: Not logged in. Please use 'login <username>'")
            return
        }
        nodeID := args[0]

        // --- Authorization Check (Access) ---
        authorized := false
        var allowedLoginUser string
        for _, rule := range currentSession.Permissions.AllowedRules {
            if contains(rule.Resources, "nodes") && contains(rule.Verbs, "access") {
                if len(rule.NodeLabels) > 0 {
                    log.Printf("Warning: NodeLabels in access rule not fully enforced by CLI for interactive access. Proxy should enforce this.")
                    authorized = true
                    break
                } else {
                    authorized = true
                    break
                }
            }
        }

        if !authorized {
            fmt.Println("Access denied: You are not authorized to access interactive sessions on nodes.")
            return
        }

        // --- Determine Allowed Login User for Agent ---
        effectiveLogins := currentSession.Permissions.AllowedLogins
        if len(effectiveLogins) == 0 {
            fmt.Println("Access denied: Your account has no allowed login usernames defined for remote sessions.")
            return
        }
        allowedLoginUser = effectiveLogins[0]
        log.Printf("Using remote login user: %s (from user's allowed logins: %v)", allowedLoginUser, effectiveLogins)

        // Use the effective proxy URL from the session for requests
        proxyURL := currentSession.ProxyURL
        log.Printf("CLI: Attempting WebSocket dial to %s%s?node_id=%s&user_id=%s&login_user=%s",
            proxyURL, cliShellEndpoint, nodeID, currentSession.User.Username, allowedLoginUser)

        // Setup WebSocket dialer without client certificates
        caCertFile := cliCfg.CACertFile
        if caCertFile == "" {
            fmt.Println("Error: CA certificate file is not configured for WebSocket.")
            return
        }
        caCert, err := os.ReadFile(caCertFile)
        if err != nil {
            log.Fatalf("Failed to read CA certificate for WebSocket: %v", err)
        }
        caCertPool := x509.NewCertPool()
        if !caCertPool.AppendCertsFromPEM(caCert) {
            log.Fatalf("Failed to append CA certificate for WebSocket")
        }
        dialer := &websocket.Dialer{
            TLSClientConfig: &tls.Config{
                RootCAs: caCertPool,
            },
            HandshakeTimeout: 45 * time.Second,
        }

        wsURL := fmt.Sprintf("%s%s?node_id=%s&user_id=%s&login_user=%s",
            strings.Replace(proxyURL, "https://", "wss://", 1),
            cliShellEndpoint,
            url.QueryEscape(nodeID),
            url.QueryEscape(currentSession.User.Username),
            url.QueryEscape(allowedLoginUser),
        )

        conn, resp, err := dialer.Dial(wsURL, nil)
        if err != nil {
            if resp != nil {
                bodyBytes, _ := io.ReadAll(resp.Body)
                log.Printf("CLI: WebSocket dial failed (Status: %d, Body: %s, Error: %v)", resp.StatusCode, string(bodyBytes), err)
                fmt.Printf("Error: Failed to connect to agent %s interactive session. Proxy/Agent response: %s\n", nodeID, string(bodyBytes))
            } else {
                log.Printf("CLI: WebSocket dial failed: %v", err)
                fmt.Printf("Error: Failed to connect to agent %s interactive session: %v\n", nodeID, err)
            }
            return
        }
        defer conn.Close()

        // --- OLD: These lines were causing the issue by printing a client-side prompt and then waiting for input.
        // fmt.Printf("Connected to remote shell. To exit, type 'exit'.\n")
        // fmt.Printf("%s@%s> ", color.GreenString(allowedLoginUser), color.GreenString(nodeID))
        
        // Log to console, not to user's screen
        log.Printf("CLI: WebSocket connection established. Proceeding to raw mode.")

        // Set terminal to raw mode
        oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
        if err != nil {
            log.Printf("CLI: Failed to set raw terminal mode: %v", err)
            fmt.Println("Warning: Could not set terminal to raw mode. Input may not function as expected.")
        } else {
            defer func() {
                log.Printf("CLI: Restoring terminal state.")
                _ = term.Restore(int(os.Stdin.Fd()), oldState)
            }()
            log.Printf("CLI: Raw mode enabled. Starting I/O loops.")
        }

        var wg sync.WaitGroup
        wg.Add(2)

        // Goroutine to read from WebSocket and write to stdout
        go func() {
            defer wg.Done()
            for {
                _, message, err := conn.ReadMessage()
                if err != nil {
                    if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
                        log.Printf("CLI: WebSocket closed by remote: %v", err)
                    } else {
                        log.Printf("CLI: Error reading from WebSocket: %v", err)
                    }
                    return
                }
                _, err = os.Stdout.Write(message)
                if err != nil {
                    log.Printf("CLI: Error writing to stdout: %v", err)
                    return
                }
            }
        }()

        // Goroutine to read from stdin and write to WebSocket
        go func() {
            defer wg.Done()
            stdinBuf := make([]byte, 1024)
            for {
                n, err := os.Stdin.Read(stdinBuf)
                if err != nil {
                    if err == io.EOF {
                        log.Printf("CLI: Stdin EOF, user likely closed input.")
                    } else {
                        log.Printf("CLI: Error reading from stdin: %v", err)
                    }
                    break
                }
                if n > 0 {
                    err = conn.WriteMessage(websocket.BinaryMessage, stdinBuf[:n])
                    if err != nil {
                        log.Printf("CLI: Error writing to WebSocket: %v", err)
                        break
                    }
                }
            }
            conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
            log.Printf("CLI: Stdin read loop ended.")
        }()

        sigChan := make(chan os.Signal, 1)
        signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
        select {
        case <-sigChan:
            log.Println("CLI: Caught interrupt signal (Ctrl+C). Disconnecting.")
            err = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Client interrupt"))
            if err != nil {
                log.Printf("CLI: Error sending close message: %v", err)
            }
        case <-cmd.Context().Done():
            log.Println("CLI: Command context cancelled. Disconnecting.")
        }
        wg.Wait()
        log.Println("CLI: Interactive session ended.")
    },
}

var runCommandCmd = &cobra.Command{
    Use:   "run-command [node-id] [command] [args...]",
    Short: "Execute a command on an agent",
    Args:  cobra.MinimumNArgs(2),
    Run: func(cmd *cobra.Command, args []string) {
        if currentSession == nil || currentSession.User == nil {
            fmt.Println("Error: Not logged in. Please use 'login <username>'")
            return
        }

        nodeID := args[0]
        command := args[1]
        cmdArgs := []string{}
        if len(args) > 2 {
            cmdArgs = args[2:]
        }

        // --- Authorization Check (Run Command) ---
        authorized := false
        for _, rule := range currentSession.Permissions.AllowedRules {
            if contains(rule.Resources, "nodes") && contains(rule.Verbs, "run") {
                log.Printf("Warning: NodeLabels in run-command rule not fully enforced by CLI. Proxy should enforce this.")
                authorized = true
                break
            }
        }

        if !authorized {
            fmt.Println("Access denied: You are not authorized to run commands on this node.")
            return
        }

        reqBody, err := json.Marshal(map[string]interface{}{
            "node_id": nodeID,
            "command": command,
            "args":    cmdArgs,
        })
        if err != nil {
            fmt.Printf("Error marshalling request: %v\n", err)
            return
        }

        client, err := createHTTPClient()
        if err != nil {
            fmt.Printf("Error creating HTTP client: %v\n", err)
            return
        }

        // Use the effective proxy URL from the session for requests
        proxyURL := currentSession.ProxyURL

        resp, err := client.Post(proxyURL+runCommandEndpoint, "application/json", bytes.NewBuffer(reqBody))
        if err != nil {
            fmt.Printf("Error sending command to proxy: %v\n", err)
            return
        }
        defer resp.Body.Close()

        bodyBytes, err := io.ReadAll(resp.Body)
        if err != nil {
            fmt.Printf("Error reading response from proxy: %v\n", err)
            return
        }

        if resp.StatusCode != http.StatusOK {
            fmt.Printf("Error from proxy (%d): %s\n", resp.StatusCode, string(bodyBytes))
            return
        }

        var result map[string]interface{}
        if err := json.Unmarshal(bodyBytes, &result); err != nil {
            fmt.Printf("Error decoding response: %v\n", err)
            fmt.Println("Raw Response:", string(bodyBytes))
            return
        }

        fmt.Printf("Command Output:\n%s\n", result["output"])
        fmt.Printf("Status: %s\n", result["status"])
    },
}

func contains(s []string, e string) bool {
    for _, a := range s {
        if a == e {
            return true
        }
    }
    return false
}
