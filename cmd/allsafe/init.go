package main

import (
    "fmt"
    "github.com/spf13/cobra"

    "allsafeaccess/core/config"  // adjust if your module name differs
    "allsafeaccess/core/admin"
)

var secureFlag bool

var initCmd = &cobra.Command{
    Use:   "init",
    Short: "Initialize allsafe environment",
    RunE: func(cmd *cobra.Command, args []string) error {
        fmt.Println("Initializing Allsafe Access with secure =", secureFlag)
        
        err := config.SetupEnvironment(secureFlag)
        if err != nil {
            return fmt.Errorf("failed to setup environment: %w", err)
        }

        err = admin.CreateDefaultAdminUser()
        if err != nil {
            return fmt.Errorf("failed to create admin user: %w", err)
        }

        fmt.Println("Allsafe Access initialized successfully")
        return nil
    },
}

func init() {
    initCmd.Flags().BoolVar(&secureFlag, "secure", false, "Generate TLS certificates for secure HTTPS")
}
