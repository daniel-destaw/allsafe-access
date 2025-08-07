package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"allsafe-access/pkg/auth"
	"golang.org/x/term"
)

func main() {
	// --- Setup: Hardcoded paths for this example ---
	// In a real application, these paths would be configurable.
	userFilePath := "./configs/users/users.json"
	roleConfigDir := "./configs/roles"

	// Create a new AuthChecker instance
	ac, err := auth.NewAuthChecker(userFilePath, roleConfigDir)
	if err != nil {
		log.Fatalf("Failed to initialize AuthChecker: %v", err)
	}

	// --- Interactive Login ---
	var username string
	fmt.Print("Enter username: ")
	fmt.Scanln(&username)

	fmt.Print("Enter password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("Error reading password:", err)
		return
	}
	password := string(bytePassword)
	fmt.Println() // Print a newline after reading the password

	// Verify the user and get their permissions
	userObj, permissions, err := ac.VerifyUserAndGetPermissions(username, password)
	if err != nil {
		fmt.Printf("Login failed: %v\n", err)
		os.Exit(1)
	}

	// --- Displaying Results ---
	fmt.Printf("Login successful for user: %s\n", userObj.Username)
	fmt.Println("--- User Roles and Permissions ---")
	fmt.Printf("Roles: %v\n", userObj.Roles)
	fmt.Printf("Effective Max Session TTL: %v\n", permissions.MaxSessionTTL)
	fmt.Printf("SSH File Copy Allowed: %t\n", permissions.SSHFileCopy)
	fmt.Println("Permission Rules:")
	for _, p := range permissions.Permissions {
		fmt.Printf("  - Node: %s, Logins: %v\n", p.Node, p.Logins)
	}
}
