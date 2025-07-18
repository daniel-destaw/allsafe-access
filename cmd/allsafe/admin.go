package allsafe

import (
	"fmt"
	"allsafe-access/core/admin"
	"github.com/spf13/cobra"
)

var addUserCmd = &cobra.Command{
	Use:   "add-user",
	Short: "Add a new user",
	Run: func(cmd *cobra.Command, args []string) {
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		role, _ := cmd.Flags().GetString("role")
		admin.AddUser(username, password, role)
	},
}

var deleteUserCmd = &cobra.Command{
	Use:   "delete-user",
	Short: "Delete a user",
	Run: func(cmd *cobra.Command, args []string) {
		username, _ := cmd.Flags().GetString("username")
		admin.DeleteUser(username)
	},
}

var updateUserCmd = &cobra.Command{
	Use:   "update-user",
	Short: "Update user password or role",
	Run: func(cmd *cobra.Command, args []string) {
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		role, _ := cmd.Flags().GetString("role")
		admin.UpdateUser(username, password, role)
	},
}

var listUsersCmd = &cobra.Command{
	Use:   "list-users",
	Short: "List all users",
	Run: func(cmd *cobra.Command, args []string) {
		admin.ListUsers()
	},
}

func init() {
	addUserCmd.Flags().StringP("username", "u", "", "Username")
	addUserCmd.Flags().StringP("password", "p", "", "Password")
	addUserCmd.Flags().StringP("role", "r", "", "Role")

	deleteUserCmd.Flags().StringP("username", "u", "", "Username")

	updateUserCmd.Flags().StringP("username", "u", "", "Username")
	updateUserCmd.Flags().StringP("password", "p", "", "Password")
	updateUserCmd.Flags().StringP("role", "r", "", "Role")
}