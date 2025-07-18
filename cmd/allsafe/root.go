package allsafe

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "allsafe",
	Short: "Allsafe CLI for access control",
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.AddCommand(addUserCmd)
	rootCmd.AddCommand(deleteUserCmd)
	rootCmd.AddCommand(updateUserCmd)
	rootCmd.AddCommand(listUsersCmd)
}