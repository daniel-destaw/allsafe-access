package admin

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// User struct
type User struct {
	Username string `json:"username"`
	Password string `json:"password"` // stored as bcrypt hash
	Role     string `json:"role"`
}

// CreateDefaultAdminUser prompts for username and password (hidden), validates and stores user
func CreateDefaultAdminUser() error {
	if _, err := os.Stat("users.json"); err == nil {
		// users.json exists, skip creation
		return nil
	}

	reader := bufio.NewReader(os.Stdin)

	// Prompt username
	fmt.Print("Enter username for admin user: ")
	usernameRaw, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	username := strings.TrimSpace(usernameRaw)
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	// Prompt password twice
	var password, passwordConfirm string
	for {
		fmt.Print("Enter password (min 8 chars): ")
		bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return err
		}
		password = string(bytePassword)
		password = strings.TrimSpace(password)

		if len(password) < 8 {
			fmt.Println("Password too short, must be at least 8 characters.")
			continue
		}

		fmt.Print("Re-enter password: ")
		bytePasswordConfirm, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return err
		}
		passwordConfirm = string(bytePasswordConfirm)
		passwordConfirm = strings.TrimSpace(passwordConfirm)

		if password != passwordConfirm {
			fmt.Println("Passwords do not match, please try again.")
			continue
		}
		break
	}

	// Hash password
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	adminUser := User{
		Username: username,
		Password: string(hashed),
		Role:     "admin",
	}

	data, err := json.MarshalIndent([]User{adminUser}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("users.json", data, 0600)
}
