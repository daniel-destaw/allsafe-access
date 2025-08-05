// cmd/allsafe-auth/main.go
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"allsafe-access/pkg/auth" // <--- IMPORTANT: Update this import path to your Go module name
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	usersConfigDir := "configs/users"
	rolesConfigDir := "configs/roles"

	// --- REMOVED: No longer creating dummy config files ---
	// Your program will now expect these files to exist at the specified paths.
	// Ensure configs/users/users.json and configs/roles/allow_10.195.yaml are present.
	// If they are not, the AuthChecker initialization will fail.
	// --- End REMOVED ---

	// Initialize the AuthChecker, which in turn initializes UserManager and loads roles
	authChecker, err := auth.NewAuthChecker(usersConfigDir, rolesConfigDir)
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

		// Call the AuthChecker to verify the user and get permissions
		userObj, permissions, err := authChecker.VerifyUserAndGetPermissions(username, password)
		if err != nil {
			fmt.Printf("Authentication failed for '%s': %v\n", username, err)
			continue
		}

		// Display the results
		fmt.Printf("\nAuthentication successful for user: %s\n", userObj.Username)
		fmt.Printf("User Details from %s/users.json:\n", usersConfigDir)
		fmt.Printf("  Direct Logins: %v\n", userObj.Logins)
		fmt.Printf("  Assigned Roles: %v\n", userObj.Roles)

		fmt.Printf("\nCombined Effective Permissions:\n")
		fmt.Printf("  Max Session TTL: %s\n", permissions.MaxSessionTTL)
		fmt.Printf("  SSH File Copy Allowed: %t\n", permissions.SSHFileCopy)
		fmt.Printf("  Allowed Logins: %v\n", permissions.AllowedLogins)
		fmt.Printf("  Allowed Node Labels: %v\n", permissions.AllowedNodeLabels)
		fmt.Printf("  Allowed Rules (%d):\n", len(permissions.AllowedRules))
		for i, rule := range permissions.AllowedRules {
			fmt.Printf("    Rule %d: Resources=%v, Verbs=%v, NodeLabels=%v\n", i+1, rule.Resources, rule.Verbs, rule.NodeLabels)
		}
		fmt.Printf("  Denied Logins: %v\n", permissions.DeniedLogins)
		fmt.Printf("  Denied Rules (%d):\n", len(permissions.DeniedRules))
		for i, rule := range permissions.DeniedRules {
			fmt.Printf("    Rule %d: Resources=%v, Verbs=%v, NodeLabels=%v\n", i+1, rule.Resources, rule.Verbs, rule.NodeLabels)
		}
	}

	fmt.Println("\nExiting Allsafe Auth Interactive Test. Goodbye!")
}

// --- REMOVED: The setupDummyConfigs function is no longer here ---