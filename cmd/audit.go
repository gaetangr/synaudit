package cmd

import (
	"fmt"

	"github.com/gaetangr/synaudit/internal/api"
	"github.com/gaetangr/synaudit/internal/audit"
	"github.com/gaetangr/synaudit/internal/auth"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run security audit on Synology NAS",
	Long:  `Performs a comprehensive security audit of your Synology NAS and generates a detailed report.`,
	Run: func(cmd *cobra.Command, args []string) {
		session, err := auth.LoadSessionFromFile()
		if err != nil {
			fmt.Printf("Authentication required: %v\n", err)
			fmt.Println("Please run 'synaudit login' first")
			return
		}

		fmt.Printf("Running security audit on %s...\n", session.Host)

		apiSession := &api.SessionConfig{
			SID:  session.SID,
			DID:  session.DID,
			Host: session.Host,
			User: session.User,
		}

		response, err := api.FetchSynologyDataWithSession(apiSession)
		if err != nil {
			fmt.Printf("Failed to fetch data: %v\n", err)
			return
		}

		report, err := audit.GenerateReport(*response)
		if err != nil {
			fmt.Printf("Failed to generate report: %v\n", err)
			return
		}

		audit.DisplayReport(report)
	},
}

func init() {
	rootCmd.AddCommand(auditCmd)
}
