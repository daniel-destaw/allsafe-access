package main

import (
    "context"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "github.com/google/uuid"
    "github.com/redis/go-redis/v9"
    "io/ioutil"
    "os"
    "strings"
    "time"
)

const usersFile = "users.json"

type User struct {
    Username string   `json:"username"`
    Roles    []string `json:"roles"`
    Logins   []string `json:"logins"`
    Password string   `json:"password,omitempty"`
}

func loadUsers() ([]User, error) {
    if _, err := os.Stat(usersFile); os.IsNotExist(err) {
        return []User{}, nil
    }
    data, err := ioutil.ReadFile(usersFile)
    if err != nil {
        return nil, err
    }
    var users []User
    if err := json.Unmarshal(data, &users); err != nil {
        return nil, err
    }
    return users, nil
}

func saveUsers(users []User) error {
    data, err := json.MarshalIndent(users, "", "  ")
    if err != nil {
        return err
    }
    return ioutil.WriteFile(usersFile, data, 0644)
}

func findUser(users []User, username string) (int, *User) {
    for i, u := range users {
        if u.Username == username {
            return i, &u
        }
    }
    return -1, nil
}

// Add user (no password set)
func addUser(username string, roles, logins []string) error {
    users, err := loadUsers()
    if err != nil {
        return err
    }
    if _, u := findUser(users, username); u != nil {
        return errors.New("user already exists")
    }
    newUser := User{
        Username: username,
        Roles:    roles,
        Logins:   logins,
        Password: "",
    }
    users = append(users, newUser)
    return saveUsers(users)
}

// Delete user
func deleteUser(username string) error {
    users, err := loadUsers()
    if err != nil {
        return err
    }
    idx, _ := findUser(users, username)
    if idx == -1 {
        return errors.New("user not found")
    }
    users = append(users[:idx], users[idx+1:]...)
    return saveUsers(users)
}

// List users
func listUsers() error {
    users, err := loadUsers()
    if err != nil {
        return err
    }
    fmt.Println("Users:")
    for _, u := range users {
        fmt.Printf("- %s (roles: %v, logins: %v)\n", u.Username, u.Roles, u.Logins)
    }
    return nil
}

// Redis-backed session manager for setup tokens
type SessionManager struct {
    rdb      *redis.Client
    ctx      context.Context
    tokenTTL time.Duration
}

func NewSessionManager(redisAddr string, tokenTTL time.Duration) *SessionManager {
    rdb := redis.NewClient(&redis.Options{
        Addr: redisAddr,
    })
    return &SessionManager{
        rdb:      rdb,
        ctx:      context.Background(),
        tokenTTL: tokenTTL,
    }
}

// CreateToken creates a setup session token in Redis with username and expiry
func (sm *SessionManager) CreateToken(username string) (string, error) {
    token := uuid.NewString()
    key := "setup_session:" + token
    data := map[string]interface{}{
        "username":  username,
        "issued_at": time.Now().Unix(),
    }
    if err := sm.rdb.HSet(sm.ctx, key, data).Err(); err != nil {
        return "", err
    }
    if err := sm.rdb.Expire(sm.ctx, key, sm.tokenTTL).Err(); err != nil {
        return "", err
    }
    return token, nil
}

// ValidateToken checks token validity and returns username
func (sm *SessionManager) ValidateToken(token string) (string, error) {
    key := "setup_session:" + token
    exists, err := sm.rdb.Exists(sm.ctx, key).Result()
    if err != nil {
        return "", err
    }
    if exists == 0 {
        return "", errors.New("token not found or expired")
    }
    username, err := sm.rdb.HGet(sm.ctx, key, "username").Result()
    if err != nil {
        return "", err
    }
    return username, nil
}

// RevokeToken deletes token (called after password setup completed)
func (sm *SessionManager) RevokeToken(token string) error {
    key := "setup_session:" + token
    return sm.rdb.Del(sm.ctx, key).Err()
}

func printUsage() {
    fmt.Println(`Usage:
  users add <username> --roles=role1,role2 --logins=login1,login2
  users delete <username>
  users list
`)
}

func main() {
    redisAddr := flag.String("redis", "localhost:6379", "Redis server address")
    serverAddr := flag.String("server", "localhost:8443", "Server address for setup URL")
    tokenTTL := flag.Duration("token-ttl", 24*time.Hour, "Setup token TTL")
    flag.Parse()

    args := flag.Args()
    if len(args) < 1 {
        printUsage()
        return
    }

    sm := NewSessionManager(*redisAddr, *tokenTTL)

    cmd := args[0]

    switch cmd {
    case "users":
        if len(args) < 2 {
            printUsage()
            return
        }
        subcmd := args[1]
        switch subcmd {
        case "add":
            if len(args) < 3 {
                fmt.Println("Username required")
                return
            }
            username := args[2]

            // Parse flags manually for roles and logins from args
            var roles, logins []string
            for _, arg := range args[3:] {
                if strings.HasPrefix(arg, "--roles=") {
                    roles = strings.Split(strings.TrimPrefix(arg, "--roles="), ",")
                }
                if strings.HasPrefix(arg, "--logins=") {
                    logins = strings.Split(strings.TrimPrefix(arg, "--logins="), ",")
                }
            }

            if err := addUser(username, roles, logins); err != nil {
                fmt.Println("Error adding user:", err)
                return
            }

            token, err := sm.CreateToken(username)
            if err != nil {
                fmt.Println("Failed to create setup token:", err)
                return
            }
            fmt.Printf("User %q added successfully.\n", username)
            fmt.Printf("Setup URL (share with user to complete password setup): https://%s/complete?token=%s\n", *serverAddr, token)

        case "delete":
            if len(args) < 3 {
                fmt.Println("Username required")
                return
            }
            username := args[2]
            if err := deleteUser(username); err != nil {
                fmt.Println("Error deleting user:", err)
                return
            }
            fmt.Printf("User %q deleted.\n", username)

        case "list":
            if err := listUsers(); err != nil {
                fmt.Println("Error listing users:", err)
            }

        default:
            printUsage()
        }
    default:
        printUsage()
    }
}
