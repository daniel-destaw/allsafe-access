package main

import (
    "bufio"
    "bytes"
    "context"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
    "time"

    "golang.org/x/term"

    "github.com/gorilla/websocket"
    "github.com/spf13/cobra"
    "github.com/spf13/viper"
)

var (
    proxyAddress string
    cliUser string
    currentUser *User
)

// User represents a user with a session token
type User struct {
    Username string
    Token    string
    AuthTime time.Time
}

// Node represents a registered agent
type Node struct {
    ID        string            `json:"ID"`
    IPAddress string            `json:"IPAddress"`
    Labels    map[string]string `json:"Labels"`
}

func main() {
    cobra.OnInitialize(initConfig)
    rootCmd.AddCommand(loginCmd)
    rootCmd.AddCommand(listNodesCmd)
    rootCmd.AddCommand(accessCmd)

    rootCmd.PersistentFlags().StringVarP(&proxyAddress, "proxy-address", "p", "https://10.195.130.14:8080", "Proxy server address")
    if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}

func initConfig() {
    viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
    viper.AutomaticEnv()
}

var rootCmd = &cobra.Command{
    Use:   "allsafe-cli",
    Short: "A CLI client for Allsafe Access",
    Long:  "A CLI client to authenticate with the Allsafe Access proxy and connect to agents.",
    Run: func(cmd *cobra.Command, args []string) {
        interactiveCLI()
    },
}

var loginCmd = &cobra.Command{
    Use:   "login [username] [password]",
    Short: "Login to the Allsafe Access proxy",
    Args:  cobra.MaximumNArgs(2),
    Run: func(cmd *cobra.Command, args []string) {
        interactiveLogin()
    },
}

var listNodesCmd = &cobra.Command{
    Use:   "list-nodes",
    Short: "List all accessible nodes",
    Run: func(cmd *cobra.Command, args []string) {
        if currentUser == nil {
            fmt.Println("Error: You must be logged in to list nodes.")
            return
        }
        listNodes()
    },
}

var accessCmd = &cobra.Command{
    Use:   "access [agent_id]",
    Short: "Connect to an agent's interactive shell",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        if currentUser == nil {
            fmt.Println("Error: You must be logged in to access a node.")
            return
        }
        runAccess(args[0])
    },
}

func interactiveCLI() {
    reader := bufio.NewReader(os.Stdin)
    for {
        if currentUser == nil {
            fmt.Print("allsafe-cli> ")
        } else {
            fmt.Printf("%s@allsafe-access$ ", currentUser.Username)
        }
        input, _ := reader.ReadString('\n')
        input = strings.TrimSpace(input)
        parts := strings.Fields(input)

        if len(parts) == 0 {
            continue
        }

        command := parts[0]
        args := []string{}
        if len(parts) > 1 {
            args = parts[1:]
        }

        switch command {
        case "login":
            if currentUser != nil {
                fmt.Println("You are already logged in.")
                continue
            }
            interactiveLogin()
        case "list-nodes":
            if currentUser == nil {
                fmt.Println("Error: You must be logged in to list nodes.")
            } else {
                listNodes()
            }
        case "access":
            if currentUser == nil {
                fmt.Println("Error: You must be logged in to access a node.")
            } else if len(args) < 1 {
                fmt.Println("Usage: access <agent_id>")
            } else {
                runAccess(args[0])
            }
        case "exit":
            fmt.Println("Goodbye!")
            return
        default:
            fmt.Println("Unknown command. Available commands: login, list-nodes, access <agent_id>, exit")
        }
    }
}

func interactiveLogin() {
    reader := bufio.NewReader(os.Stdin)
    fmt.Print("Username: ")
    username, _ := reader.ReadString('\n')
    username = strings.TrimSpace(username)

    fmt.Print("Password: ")
    bytePassword, _ := term.ReadPassword(int(os.Stdin.Fd()))
    password := string(bytePassword)
    fmt.Println()

    if username == "" || password == "" {
        fmt.Println("Username and password cannot be empty.")
        return
    }

    login(username, password)
}

func login(username, password string) {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

    loginURL := fmt.Sprintf("%s%s", proxyAddress, "/cli/auth")
    loginData := map[string]string{"username": username, "password": password}
    jsonData, _ := json.Marshal(loginData)

    resp, err := client.Post(loginURL, "application/json", bytes.NewBuffer(jsonData))
    if err != nil {
        fmt.Printf("Error: Failed to connect to proxy: %v\n", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        bodyBytes, _ := io.ReadAll(resp.Body)
        fmt.Printf("Login failed (Status: %d): %s\n", resp.StatusCode, string(bodyBytes))
        return
    }

    var result map[string]string
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        fmt.Printf("Login successful, but failed to parse response: %v\n", err)
        currentUser = &User{Username: username, AuthTime: time.Now()}
        fmt.Printf("Login successful. Welcome, %s!\n", currentUser.Username)
        return
    }

    currentUser = &User{Username: username, AuthTime: time.Now()}
    fmt.Printf("Login successful. Welcome, %s!\n", currentUser.Username)
}

func listNodes() {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

    listURL := fmt.Sprintf("%s%s", proxyAddress, "/cli/nodes")
    req, _ := http.NewRequest("GET", listURL, nil)
    req.Header.Set("X-Auth-Token", currentUser.Username)

    resp, err := client.Do(req)
    if err != nil {
        fmt.Printf("Error listing nodes: %v\n", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        bodyBytes, _ := io.ReadAll(resp.Body)
        fmt.Printf("Error listing nodes (Status: %d): %s\n", resp.StatusCode, string(bodyBytes))
        return
    }

    var nodes []Node
    if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
        fmt.Printf("Error parsing nodes list: %v\n", err)
        return
    }

    fmt.Println("---")
    fmt.Println("Allowed Agents:")
    fmt.Println("---")
    for _, node := range nodes {
        fmt.Printf("ID: %s\n", node.ID)
        if len(node.Labels) > 0 {
            fmt.Printf("Labels: %v\n", node.Labels)
        }
        fmt.Println("---")
    }
}

func runAccess(nodeID string) {
    fmt.Printf("Attempting to connect to agent %s...\n", nodeID)

    reader := bufio.NewReader(os.Stdin)
    fmt.Print("Remote login user: ")
    remoteUser, _ := reader.ReadString('\n')
    remoteUser = strings.TrimSpace(remoteUser)
    if remoteUser == "" {
        fmt.Println("Remote user cannot be empty.")
        return
    }

    // Save the old terminal state and set to raw mode
    oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
    if err != nil {
        log.Printf("Failed to set terminal to raw mode: %v", err)
        return
    }
    // Defer a function to restore the terminal state
    defer func() {
        _ = term.Restore(int(os.Stdin.Fd()), oldState)
        fmt.Print("\r\n") // Add a newline to move to a new line after the session
    }()
    
    // Construct the WebSocket URL with query parameters
    wsURL := strings.Replace(proxyAddress, "https", "wss", 1) + "/cli/shell"
    query := url.Values{}
    query.Add("node_id", nodeID)
    query.Add("user_id", currentUser.Username)
    query.Add("login_user", remoteUser)

    fullWsURL := fmt.Sprintf("%s?%s", wsURL, query.Encode())

    dialer := &websocket.Dialer{
        Proxy:            http.ProxyFromEnvironment,
        HandshakeTimeout: 45 * time.Second,
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
        },
    }
    
    // Add the authentication header
    header := http.Header{}
    header.Add("X-Auth-Token", currentUser.Username)

    conn, resp, err := dialer.Dial(fullWsURL, header)
    if err != nil {
        _ = term.Restore(int(os.Stdin.Fd()), oldState) // Restore terminal on error
        
        // --- NEW IMPROVED ERROR HANDLING LOGIC ---
        if resp != nil {
            bodyBytes, _ := io.ReadAll(resp.Body)
            body := strings.TrimSpace(string(bodyBytes))

            // Check for the specific unauthorized error from the proxy
            if resp.StatusCode == http.StatusForbidden {
                fmt.Printf("Error: Unauthorized. %s\n", body)
                return
            }

            // For other HTTP errors, show a more detailed message
            fmt.Printf("Error: Failed to connect to agent %s. Proxy/Agent response (Status: %d): %s\n", nodeID, resp.StatusCode, body)
        } else {
            // For general network or dialer errors
            fmt.Printf("Error: Failed to connect to agent %s. Error: %v\n", nodeID, err)
        }
        return
    }
    defer conn.Close()
    
    ctx, cancel := context.WithCancel(context.Background())
    var wg sync.WaitGroup
    wg.Add(2)

    // Read from stdin and send to WebSocket
    go func() {
        defer wg.Done()
        buf := make([]byte, 1024)
        for {
            select {
            case <-ctx.Done():
                return
            default:
                n, err := os.Stdin.Read(buf)
                if err != nil {
                    if err != io.EOF {
                        log.Printf("Error reading from stdin: %v", err)
                    }
                    return
                }
                if n > 0 {
                    err := conn.WriteMessage(websocket.BinaryMessage, buf[:n])
                    if err != nil {
                        // The connection is likely closed, so we'll just stop
                        return
                    }
                }
            }
        }
    }()

    // Read from WebSocket and write to stdout
    go func() {
        defer wg.Done()
        for {
            messageType, message, err := conn.ReadMessage()
            if err != nil {
                log.Println("read:", err)
                cancel()
                return
            }
            if messageType == websocket.BinaryMessage {
                os.Stdout.Write(message)
            } else {
                fmt.Println(string(message))
            }
        }
    }()

    wg.Wait()
}
