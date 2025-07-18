package admin

import (
	"fmt"
	"os"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

var users = map[string]User{}

func AddUser(username, password, role string) {
	users[username] = User{username, password, role}
	fmt.Println("✅ User added:", username)
}

func DeleteUser(username string) {
	delete(users, username)
	fmt.Println("🗑️ User deleted:", username)
}

func UpdateUser(username, password, role string) {
	if user, exists := users[username]; exists {
		if password != "" {
			user.Password = password
		}
		if role != "" {
			user.Role = role
		}
		users[username] = user
		fmt.Println("🔁 User updated:", username)
	} else {
		fmt.Println("❌ User not found:", username)
	}
}

func ListUsers() {
	fmt.Println("👥 All Users:")
	for _, user := range users {
		fmt.Printf("- %s (%s)\n", user.Username, user.Role)
	}
}