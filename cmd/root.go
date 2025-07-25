package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "synaudit",
	Short: "Security audit tool for Synology NAS",
	Long:  `Synaudit is a comprehensive security audit tool for Synology NAS systems that analyzes configurations and identifies potential security vulnerabilities.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
}
