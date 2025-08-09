package main

import (
    "bufio"
    "fmt"
    "log"
    "os"
    "strings"

    "allsafe-access/pkg/auth"
)

func main() {
    log.SetFlags(log.LstdFlags | log.Lshortfile)

    // Define the paths to your configuration files.
    // The userDBPath is now the path to your SQLite database file.
    // The roleConfigDir is the directory containing YAML files.
    usersDBPath := "./allsafe_admin.db"
    rolesConfigDir := "configs/roles"

    // Initialize the AuthChecker.
    authChecker, err := auth.NewAuthChecker(usersDBPath, rolesConfigDir)
    if err != nil {
        log.Fatalf("Failed to initialize AuthChecker: %v", err)
    }
    log.Println("AuthChecker fully initialized and ready.")

    reader := bufio.NewReader(os.Stdin)

    fmt.Println("\n--- Allsafe Auth Interactive Test ---")
    fmt.Println("Enter 'exit' for username to quit.")

    for {
        fmt.Print("\nEnter Username: ")
        usernameInput, _ := reader.ReadString('\n')
        username := strings.TrimSpace(usernameInput)

        if strings.ToLower(username) == "exit" {
            break
        }

        fmt.Print("Enter Password: ")
        passwordInput, _ := reader.ReadString('\n')
        password := strings.TrimSpace(passwordInput)

        // Call the AuthChecker to verify the user and get permissions.
        userObj, permissions, err := authChecker.VerifyUserAndGetPermissions(username, password)
        if err != nil {
            fmt.Printf("Authentication failed for '%s': %v\n", username, err)
            continue
        }

        // Display the results.
        fmt.Printf("\nAuthentication successful for user: %s\n", userObj.Username)
        fmt.Printf("User Details:\n")
        fmt.Printf("  Assigned Roles: %v\n", userObj.Roles)

        fmt.Printf("\nCombined Effective Permissions:\n")
        fmt.Printf("  Max Session TTL: %s\n", permissions.MaxSessionTTL)
        fmt.Printf("  SSH File Copy Allowed: %t\n", permissions.SSHFileCopy)
        fmt.Printf("  Permission Rules (%d):\n", len(permissions.Permissions))
        for i, p := range permissions.Permissions {
            fmt.Printf("    Rule %d:\n", i+1)
            fmt.Printf("      - Node: %s\n", p.Node)
            fmt.Printf("      - Logins: %v\n", p.Logins)
        }
    }

    fmt.Println("\nExiting Allsafe Auth Interactive Test. Goodbye!")
}