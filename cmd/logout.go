package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout and clear saved session",
	Long:  `Logout from Synology NAS and clear the saved session data.`,
	Run: func(cmd *cobra.Command, args []string) {
		session, err := loadSessionFromFile()
		if err != nil {
			fmt.Printf("No active session found: %v\n", err)
			return
		}

		fmt.Printf("Logging out from %s...\n", session.Host)

		if err := logoutAPI(session.Host, session.SID); err != nil {
			fmt.Printf("Warning: Could not logout from server: %v\n", err)
		} else {
			fmt.Println("Logged out from server")
		}

		if err := clearSessionFile(); err != nil {
			fmt.Printf("Warning: Could not clear session file: %v\n", err)
		} else {
			fmt.Println("Session data cleared")
		}

		fmt.Println("Goodbye!")
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
