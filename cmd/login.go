// cmd/login.go - Version avec support 2FA

package cmd

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/gaetangr/synaudit/internal/auth"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Synology NAS",
	Long:  `Authenticate with your Synology NAS and save the session for future commands.`,
	Run: func(cmd *cobra.Command, args []string) {
		user, _ := cmd.Flags().GetString("user")
		host, _ := cmd.Flags().GetString("host")

		if user == "" {
			fmt.Println("Error: username is required")
			return
		}

		if host == "" {
			fmt.Println("Error: host is required")
			return
		}

		fmt.Print("Enter password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Printf("\nError reading password: %v\n", err)
			return
		}
		fmt.Println()

		password := string(passwordBytes)
		if password == "" {
			fmt.Println("Error: password cannot be empty")
			return
		}

		fmt.Printf("Logging in with user: %s to host: %s\n", user, host)

		loginData, err := auth.AuthenticateUser(host, user, password)

		var twoFactorErr *auth.TwoFactorRequiredError
		if errors.As(err, &twoFactorErr) {
			fmt.Printf("\n🔐 Two-factor authentication required\n")
			fmt.Print("Enter your 2FA code (6 digits): ")

			otpBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				fmt.Printf("\nError reading 2FA code: %v\n", err)
				return
			}
			fmt.Println()

			otpCode := string(otpBytes)
			if otpCode == "" {
				fmt.Println("Error: 2FA code cannot be empty")
				return
			}

			fmt.Println("Authenticating with 2FA code...")

			loginData, err = auth.AuthenticateWith2FA(host, user, password, otpCode)
			if err != nil {
				fmt.Printf("2FA Login failed: %v\n", err)
				return
			}
		} else if err != nil {
			fmt.Printf("Login failed: %v\n", err)
			return
		}

		fmt.Printf("✅ Login successful!\n")

		if err := auth.SaveSessionToFile(loginData, host, user); err != nil {
			fmt.Printf("Warning: Could not save session: %v\n", err)
			fmt.Println("You'll need to login again for each command.")
		} else {
			fmt.Printf("📁 Session saved successfully\n")
			fmt.Println("You can now use other commands without logging in again.")
		}
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)

	loginCmd.Flags().StringP("user", "u", "", "Username for authentication")
	loginCmd.Flags().StringP("host", "H", "192.168.1.198:8443", "IP for your Synology NAS (eg: 192.168.1.198:8443)")
}
