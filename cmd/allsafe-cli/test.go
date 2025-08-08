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

	"github.com/c-bata/go-prompt"
	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	proxyAddress string
	cliUser      string
	currentUser  *User
	// This variable will hold the initial state of the terminal.
	initialTermState *term.State
	// cachedNodes is a global variable to store the list of nodes,
	// so we don't have to make a network request every time the completer runs.
	cachedNodes []Node
	// isHintEnabled is a global variable to control the visibility of the auto-completion hints.
	isHintEnabled = true
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
	// Capture the initial terminal state as soon as the program starts.
	// This state will be restored when the program exits.
	fd := int(os.Stdin.Fd())
	var err error
	initialTermState, err = term.GetState(fd)
	if err != nil {
		log.Fatalf("Failed to get terminal state: %v", err)
	}

	cobra.OnInitialize(initConfig)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(listNodesCmd)
	rootCmd.AddCommand(accessCmd)
	rootCmd.PersistentFlags().StringVarP(&proxyAddress, "proxy", "p", "https://10.195.130.14:8080", "Proxy server address")
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
		interactiveLogin()
		if currentUser != nil {
			// After a successful login, fetch the nodes once and cache them.
			fetchAndCacheNodes()
			interactiveCLI()
		}
	},
}

var loginCmd = &cobra.Command{
	Use:   "login [username] [password]",
	Short: "Login to the Allsafe Access proxy",
	Args:  cobra.MaximumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		interactiveLogin()
		if currentUser != nil {
			fmt.Printf("Login successful. You can now use the interactive CLI.\n")
		}
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
		listNodesAndPrint()
	},
}

var accessCmd = &cobra.Command{
	Use:   "access [agent_id] [remote_user]",
	Short: "Connect to an agent's interactive shell",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		if currentUser == nil {
			fmt.Println("Error: You must be logged in to access a node.")
			return
		}
		runAccess(args[0], args[1])
	},
}

// All commands for the go-prompt completer
var commands = []prompt.Suggest{
	{Text: "list-nodes", Description: "List all accessible nodes"},
	{Text: "access", Description: "Connect to an agent's interactive shell"},
	{Text: "refresh", Description: "Refresh the list of available nodes"},
	{Text: "toggle-hint", Description: "Enable or disable command hints"},
	{Text: "exit", Description: "Exit the CLI"},
}

// completer is the function that provides auto-completion suggestions.
// It now uses the cachedNodes variable for performance and respects the isHintEnabled flag.
func completer(d prompt.Document) []prompt.Suggest {
	// If hints are disabled, return an empty slice immediately.
	if !isHintEnabled {
		return []prompt.Suggest{}
	}

	word := d.GetWordBeforeCursor()

	if word == "" || d.Text == "" {
		return prompt.FilterHasPrefix(commands, word, true)
	}

	parts := strings.Fields(d.Text)
	if len(parts) > 0 {
		switch parts[0] {
		case "access":
			// We now use the cachedNodes list instead of making a new network request
			// every time a character is typed.
			var suggests []prompt.Suggest
			for _, node := range cachedNodes {
				suggests = append(suggests, prompt.Suggest{Text: node.ID, Description: fmt.Sprintf("OS: %s, Region: %s", node.Labels["os"], node.Labels["region"])})
			}
			return prompt.FilterHasPrefix(suggests, word, true)
		}
	}
	return prompt.FilterHasPrefix(commands, word, true)
}

// executor is the function that handles the command after the user presses Enter
func executor(in string) {
	in = strings.TrimSpace(in)
	if in == "" {
		return
	}
	parts := strings.Fields(in)
	command := parts[0]
	args := []string{}
	if len(parts) > 1 {
		args = parts[1:]
	}

	switch command {
	case "list-nodes":
		if currentUser == nil {
			fmt.Println("Error: You must be logged in to list nodes.")
		} else {
			listNodesAndPrint()
		}
	case "access":
		if currentUser == nil {
			fmt.Println("Error: You must be logged in to access a node.")
		} else if len(args) < 2 {
			fmt.Println("Usage: access <agent_id> <remote_user>")
		} else {
			runAccess(args[0], args[1])
		}
	case "refresh":
		fetchAndCacheNodes()
		fmt.Println("Node list refreshed.")
	case "toggle-hint":
		isHintEnabled = !isHintEnabled
		state := "enabled"
		if !isHintEnabled {
			state = "disabled"
		}
		fmt.Printf("Auto-completion hints are now %s.\n", state)
	case "exit":
		fmt.Printf("Goodbye!\n")
		// Explicitly restore the terminal state before exiting the program.
		term.Restore(int(os.Stdin.Fd()), initialTermState)
		os.Exit(0)
	default:
		fmt.Println("Unknown command. Available commands: list-nodes, access <agent_id> <remote_user>, refresh, toggle-hint, exit")
	}
}

func interactiveCLI() {
	p := prompt.New(
		executor,
		completer,
		prompt.OptionPrefix(getPromptPrefix()),
		prompt.OptionTitle("Allsafe CLI"),
		prompt.OptionLivePrefix(func() (string, bool) {
			return getPromptPrefix(), true
		}),
	)
	p.Run()
}

func getPromptPrefix() string {
	if currentUser == nil {
		return fmt.Sprintf("allsafe-cli> ")
	}
	return fmt.Sprintf("%s@allsafe-access$ ", currentUser.Username)
}

func interactiveLogin() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Welcome to Allsafe CLI. Please log in.\n")
	fmt.Printf("Username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Printf("Password: ")
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
		fmt.Printf("[allsafe-cli] Login successful. *Welcome, %s!*\n", username)
		currentUser = &User{Username: username, AuthTime: time.Now()}
		return
	}

	currentUser = &User{Username: username, AuthTime: time.Now()}
	fmt.Printf("[allsafe-cli] Login successful. *Welcome, %s!*\n", currentUser.Username)
}

// fetchAndCacheNodes fetches the nodes from the proxy and stores them in the global cache.
func fetchAndCacheNodes() {
	nodes, err := listNodes()
	if err != nil {
		fmt.Println("Failed to fetch nodes:", err)
		return
	}
	cachedNodes = nodes
}

// listNodes now returns the cached nodes if they exist, or fetches them if not.
func listNodes() ([]Node, error) {
	if currentUser == nil {
		return nil, fmt.Errorf("not logged in")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	listURL := fmt.Sprintf("%s%s", proxyAddress, "/cli/nodes")
	req, _ := http.NewRequest("GET", listURL, nil)
	req.Header.Set("X-Auth-Token", currentUser.Username)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error listing nodes: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("error listing nodes (Status: %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var nodes []Node
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		return nil, fmt.Errorf("error parsing nodes list: %v", err)
	}
	return nodes, nil
}

func listNodesAndPrint() {
	nodes, err := listNodes()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("---\n")
	fmt.Printf("Allowed Agents:\n")
	fmt.Printf("---\n")
	for _, node := range nodes {
		fmt.Printf("ID: %s\n", node.ID)
		if len(node.Labels) > 0 {
			fmt.Printf("Labels: %v\n", node.Labels)
		}
		fmt.Printf("---\n")
	}
}

func runAccess(nodeID, remoteUser string) {
	fmt.Printf("Attempting to connect to agent %s as user %s...\n", nodeID, remoteUser)

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		log.Printf("Failed to set terminal to raw mode: %v", err)
		return
	}

	// This defer block ensures the terminal is restored and a new line is printed
	// to reset the cursor position before the next go-prompt is drawn.
	defer func() {
		_ = term.Restore(int(os.Stdin.Fd()), oldState)
		fmt.Print("\n")
	}()

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

	header := http.Header{}
	header.Add("X-Auth-Token", currentUser.Username)

	conn, resp, err := dialer.Dial(fullWsURL, header)
	if err != nil {
		if resp != nil {
			bodyBytes, _ := io.ReadAll(resp.Body)
			body := strings.TrimSpace(string(bodyBytes))
			if resp.StatusCode == http.StatusForbidden {
				fmt.Printf("Error: Unauthorized. %s\n", body)
				return
			}
			fmt.Printf("Error: Failed to connect to agent %s. Proxy/Agent response (Status: %d): %s\n", nodeID, resp.StatusCode, body)
		} else {
			fmt.Printf("Error: Failed to connect to agent %s. Error: %v\n", nodeID, err)
		}
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)

	done := make(chan struct{})

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
						return
					}
				}
			}
		}
	}()

	go func() {
		defer wg.Done()
		for {
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					fmt.Printf("\r\n[allsafe-cli] Logout successful.\n")
				} else {
					log.Println("read:", err)
				}
				close(done)
				return
			}
			if messageType == websocket.BinaryMessage {
				os.Stdout.Write(message)
			} else {
				fmt.Println(string(message))
			}
		}
	}()
	
	<-done
	cancel()
	wg.Wait()
}
