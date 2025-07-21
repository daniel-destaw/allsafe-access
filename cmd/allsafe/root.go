package main

import (
    "fmt"
    "github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
    Use:   "allsafe",
    Short: "Allsafe Access CLI",
    Long:  "Command line interface for Allsafe Access",
}

func init() {
    rootCmd.AddCommand(initCmd) // make sure initCmd is declared
}

func Execute() {
    if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
    }
}
