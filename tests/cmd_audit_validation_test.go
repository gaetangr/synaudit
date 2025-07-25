package tests

import (
	"testing"

	"github.com/gaetangr/synaudit/cmd"
)

func TestAdminStatusAuditExpectedValues(t *testing.T) {
	t.Run("Admin disabled should return no findings", func(t *testing.T) {
		userData := cmd.UserListData{
			Total: 1,
			Users: []struct {
				Expired cmd.UserStatus `json:"expired"`
				Name    string         `json:"name"`
			}{
				{
					Name:    "admin",
					Expired: cmd.UserStatusExpired,
				},
			},
		}

		findings := cmd.CheckAdminStatus(userData)

		if len(findings) != 0 {
			t.Errorf("Expected 0 findings when admin is disabled, got %d", len(findings))
		}
	})

	t.Run("Admin active should return ADMIN_ACCOUNT_ACTIVE finding", func(t *testing.T) {
		userData := cmd.UserListData{
			Total: 1,
			Users: []struct {
				Expired cmd.UserStatus `json:"expired"`
				Name    string         `json:"name"`
			}{
				{
					Name:    "admin",
					Expired: cmd.UserStatusActive,
				},
			},
		}

		findings := cmd.CheckAdminStatus(userData)

		if len(findings) != 1 {
			t.Fatalf("Expected 1 finding when admin is active, got %d", len(findings))
		}

		expectedFinding := cmd.SecurityFindings["ADMIN_ACCOUNT_ACTIVE"]
		actualFinding := findings[0]

		if actualFinding.Title != expectedFinding.Title {
			t.Errorf("Expected title '%s', got '%s'", expectedFinding.Title, actualFinding.Title)
		}

		if actualFinding.Description != expectedFinding.Description {
			t.Errorf("Expected description '%s', got '%s'", expectedFinding.Description, actualFinding.Description)
		}

		if actualFinding.Remediation != expectedFinding.Remediation {
			t.Errorf("Expected remediation '%s', got '%s'", expectedFinding.Remediation, actualFinding.Remediation)
		}
	})
}

func TestFirewallAuditExpectedValues(t *testing.T) {
	t.Run("Firewall enabled should return no findings", func(t *testing.T) {
		firewallData := cmd.FirewallData{
			Enable_firewall: true,
		}

		findings := cmd.CheckFirewallStatus(firewallData)

		if len(findings) != 0 {
			t.Errorf("Expected 0 findings when firewall is enabled, got %d", len(findings))
		}
	})

	t.Run("Firewall disabled should return FIREWALL_DISABLED finding", func(t *testing.T) {
		firewallData := cmd.FirewallData{
			Enable_firewall: false,
		}

		findings := cmd.CheckFirewallStatus(firewallData)

		if len(findings) != 1 {
			t.Fatalf("Expected 1 finding when firewall is disabled, got %d", len(findings))
		}

		expectedFinding := cmd.SecurityFindings["FIREWALL_DISABLED"]
		actualFinding := findings[0]

		if actualFinding.Title != expectedFinding.Title {
			t.Errorf("Expected title '%s', got '%s'", expectedFinding.Title, actualFinding.Title)
		}

		if actualFinding.Description != expectedFinding.Description {
			t.Errorf("Expected description '%s', got '%s'", expectedFinding.Description, actualFinding.Description)
		}

		if actualFinding.Remediation != expectedFinding.Remediation {
			t.Errorf("Expected remediation '%s', got '%s'", expectedFinding.Remediation, actualFinding.Remediation)
		}
	})
}

func Test2FAAuditExpectedValues(t *testing.T) {
	t.Run("2FA enforced for admin should return no findings", func(t *testing.T) {
		optData := cmd.EnforcePolicyOptData{
			OtpEnforceOption: cmd.EnforcePolicyAdmin,
		}

		findings := cmd.CheckOptStatus(optData)

		if len(findings) != 0 {
			t.Errorf("Expected 0 findings when 2FA is enforced for admin, got %d", len(findings))
		}
	})

	t.Run("2FA not enforced should return NO_2FA_ENFORCED_ADMIN finding", func(t *testing.T) {
		optData := cmd.EnforcePolicyOptData{
			OtpEnforceOption: "none",
		}

		findings := cmd.CheckOptStatus(optData)

		if len(findings) != 1 {
			t.Fatalf("Expected 1 finding when 2FA is not enforced, got %d", len(findings))
		}

		expectedFinding := cmd.SecurityFindings["NO_2FA_ENFORCED_ADMIN"]
		actualFinding := findings[0]

		if actualFinding.Title != expectedFinding.Title {
			t.Errorf("Expected title '%s', got '%s'", expectedFinding.Title, actualFinding.Title)
		}

		if actualFinding.Description != expectedFinding.Description {
			t.Errorf("Expected description '%s', got '%s'", expectedFinding.Description, actualFinding.Description)
		}

		if actualFinding.Remediation != expectedFinding.Remediation {
			t.Errorf("Expected remediation '%s', got '%s'", expectedFinding.Remediation, actualFinding.Remediation)
		}
	})
}

func TestTelnetAuditExpectedValues(t *testing.T) {
	t.Run("Telnet disabled should return no telnet findings", func(t *testing.T) {
		terminalData := cmd.TerminalData{
			EnableTelnet: false,
			EnableSSH:    true,
			SSHPort:      2222,
		}

		findings := cmd.CheckTerminalSecurity(terminalData)

		for _, finding := range findings {
			if finding.Title == "Telnet service is enabled" {
				t.Error("Expected no Telnet finding when Telnet is disabled")
			}
		}
	})

	t.Run("Telnet enabled should return TELNET_ENABLED finding", func(t *testing.T) {
		terminalData := cmd.TerminalData{
			EnableTelnet: true,
			EnableSSH:    false,
			SSHPort:      22,
		}

		findings := cmd.CheckTerminalSecurity(terminalData)

		expectedFinding := cmd.SecurityFindings["TELNET_ENABLED"]
		found := false

		for _, finding := range findings {
			if finding.Title == expectedFinding.Title {
				found = true

				if finding.Description != expectedFinding.Description {
					t.Errorf("Expected description '%s', got '%s'", expectedFinding.Description, finding.Description)
				}

				if finding.Remediation != expectedFinding.Remediation {
					t.Errorf("Expected remediation '%s', got '%s'", expectedFinding.Remediation, finding.Remediation)
				}
				break
			}
		}

		if !found {
			t.Error("Expected TELNET_ENABLED finding when Telnet is enabled")
		}
	})
}

func TestSSHDefaultPortAuditExpectedValues(t *testing.T) {
	t.Run("SSH on custom port should return no SSH findings", func(t *testing.T) {
		terminalData := cmd.TerminalData{
			EnableTelnet: false,
			EnableSSH:    true,
			SSHPort:      2222,
		}

		findings := cmd.CheckTerminalSecurity(terminalData)

		for _, finding := range findings {
			if finding.Title == "SSH using default port" {
				t.Error("Expected no SSH default port finding when SSH is on custom port")
			}
		}
	})

	t.Run("SSH on default port should return SSH_DEFAULT_PORT finding", func(t *testing.T) {
		terminalData := cmd.TerminalData{
			EnableTelnet: false,
			EnableSSH:    true,
			SSHPort:      22,
		}

		findings := cmd.CheckTerminalSecurity(terminalData)

		expectedFinding := cmd.SecurityFindings["SSH_DEFAULT_PORT"]
		found := false

		for _, finding := range findings {
			if finding.Title == expectedFinding.Title {
				found = true

				if finding.Description != expectedFinding.Description {
					t.Errorf("Expected description '%s', got '%s'", expectedFinding.Description, finding.Description)
				}

				if finding.Remediation != expectedFinding.Remediation {
					t.Errorf("Expected remediation '%s', got '%s'", expectedFinding.Remediation, finding.Remediation)
				}
				break
			}
		}

		if !found {
			t.Error("Expected SSH_DEFAULT_PORT finding when SSH is on port 22")
		}
	})
}

func TestFTPAuditExpectedValues(t *testing.T) {
	t.Run("FTP with TLS should return no findings", func(t *testing.T) {
		ftpData := cmd.FTPData{
			Enable:    true,
			EnableTLS: true,
		}

		findings := cmd.CheckFtpSecurity(ftpData)

		if len(findings) != 0 {
			t.Errorf("Expected 0 findings when FTP has TLS enabled, got %d", len(findings))
		}
	})

	t.Run("FTP without TLS should return FTP_ENABLED finding", func(t *testing.T) {
		ftpData := cmd.FTPData{
			Enable:    true,
			EnableTLS: false,
		}

		findings := cmd.CheckFtpSecurity(ftpData)

		if len(findings) != 1 {
			t.Fatalf("Expected 1 finding when FTP is insecure, got %d", len(findings))
		}

		expectedFinding := cmd.SecurityFindings["FTP_ENABLED"]
		actualFinding := findings[0]

		if actualFinding.Title != expectedFinding.Title {
			t.Errorf("Expected title '%s', got '%s'", expectedFinding.Title, actualFinding.Title)
		}

		if actualFinding.Description != expectedFinding.Description {
			t.Errorf("Expected description '%s', got '%s'", expectedFinding.Description, actualFinding.Description)
		}

		if actualFinding.Remediation != expectedFinding.Remediation {
			t.Errorf("Expected remediation '%s', got '%s'", expectedFinding.Remediation, actualFinding.Remediation)
		}
	})
}

func TestQuickConnectAuditExpectedValues(t *testing.T) {
	t.Run("QuickConnect disabled should return no findings", func(t *testing.T) {
		quickConnectData := cmd.QuickConnectData{
			Enabled: false,
		}

		findings := cmd.CheckQuickConnectSecurity(quickConnectData)

		if len(findings) != 0 {
			t.Errorf("Expected 0 findings when QuickConnect is disabled, got %d", len(findings))
		}
	})

	t.Run("QuickConnect enabled should return QUICKCONNECT_ENABLED finding", func(t *testing.T) {
		quickConnectData := cmd.QuickConnectData{
			Enabled: true,
		}

		findings := cmd.CheckQuickConnectSecurity(quickConnectData)

		if len(findings) != 1 {
			t.Fatalf("Expected 1 finding when QuickConnect is enabled, got %d", len(findings))
		}

		expectedFinding := cmd.SecurityFindings["QUICKCONNECT_ENABLED"]
		actualFinding := findings[0]

		if actualFinding.Title != expectedFinding.Title {
			t.Errorf("Expected title '%s', got '%s'", expectedFinding.Title, actualFinding.Title)
		}

		if actualFinding.Description != expectedFinding.Description {
			t.Errorf("Expected description '%s', got '%s'", expectedFinding.Description, actualFinding.Description)
		}

		if actualFinding.Remediation != expectedFinding.Remediation {
			t.Errorf("Expected remediation '%s', got '%s'", expectedFinding.Remediation, actualFinding.Remediation)
		}
	})
}

func TestAutoBlockAuditExpectedValues(t *testing.T) {
	t.Run("Auto block enabled should return no findings", func(t *testing.T) {
		autoBlockData := cmd.AutoBlockData{
			Enable: true,
		}

		findings := cmd.CheckAutoBlockPolicy(autoBlockData)

		if len(findings) != 0 {
			t.Errorf("Expected 0 findings when auto block is enabled, got %d", len(findings))
		}
	})

	t.Run("Auto block disabled should return AUTO_BLOCK_DISABLED finding", func(t *testing.T) {
		autoBlockData := cmd.AutoBlockData{
			Enable: false,
		}

		findings := cmd.CheckAutoBlockPolicy(autoBlockData)

		if len(findings) != 1 {
			t.Fatalf("Expected 1 finding when auto block is disabled, got %d", len(findings))
		}

		expectedFinding := cmd.SecurityFindings["AUTO_BLOCK_DISABLED"]
		actualFinding := findings[0]

		if actualFinding.Title != expectedFinding.Title {
			t.Errorf("Expected title '%s', got '%s'", expectedFinding.Title, actualFinding.Title)
		}

		if actualFinding.Description != expectedFinding.Description {
			t.Errorf("Expected description '%s', got '%s'", expectedFinding.Description, actualFinding.Description)
		}

		if actualFinding.Remediation != expectedFinding.Remediation {
			t.Errorf("Expected remediation '%s', got '%s'", expectedFinding.Remediation, actualFinding.Remediation)
		}
	})
}
