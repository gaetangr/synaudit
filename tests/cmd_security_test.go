package tests

import (
	"strings"
	"testing"

	"github.com/gaetangr/synaudit/cmd"
)

func TestIsAdminDisabled(t *testing.T) {
	tests := []struct {
		name           string
		userData       cmd.UserListData
		expectDisabled bool
		expectError    bool
	}{
		{
			name: "Admin is disabled",
			userData: cmd.UserListData{
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
			},
			expectDisabled: true,
			expectError:    false,
		},
		{
			name: "Admin is active",
			userData: cmd.UserListData{
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
			},
			expectDisabled: false,
			expectError:    false,
		},
		{
			name: "Admin user not found",
			userData: cmd.UserListData{
				Total: 1,
				Users: []struct {
					Expired cmd.UserStatus `json:"expired"`
					Name    string         `json:"name"`
				}{
					{
						Name:    "user1",
						Expired: cmd.UserStatusActive,
					},
				},
			},
			expectDisabled: false,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			disabled, err := cmd.IsAdminDisabled(tt.userData)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if disabled != tt.expectDisabled {
				t.Errorf("Expected disabled=%v, got %v", tt.expectDisabled, disabled)
			}
		})
	}
}

func TestCheckAdminStatus(t *testing.T) {
	tests := []struct {
		name           string
		userData       cmd.UserListData
		expectFindings int
		expectFinding  string
	}{
		{
			name: "Admin disabled - no findings",
			userData: cmd.UserListData{
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
			},
			expectFindings: 0,
			expectFinding:  "",
		},
		{
			name: "Admin active - finding expected",
			userData: cmd.UserListData{
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
			},
			expectFindings: 1,
			expectFinding:  "Admin account is active",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := cmd.CheckAdminStatus(tt.userData)

			if len(findings) != tt.expectFindings {
				t.Errorf("Expected %d findings, got %d", tt.expectFindings, len(findings))
			}

			if tt.expectFindings > 0 && findings[0].Title != tt.expectFinding {
				t.Errorf("Expected finding title '%s', got '%s'", tt.expectFinding, findings[0].Title)
			}
		})
	}
}

func TestCheckFirewallStatus(t *testing.T) {
	tests := []struct {
		name           string
		firewallData   cmd.FirewallData
		expectFindings int
		expectFinding  string
	}{
		{
			name: "Firewall enabled - no findings",
			firewallData: cmd.FirewallData{
				Enable_firewall: true,
			},
			expectFindings: 0,
		},
		{
			name: "Firewall disabled - finding expected",
			firewallData: cmd.FirewallData{
				Enable_firewall: false,
			},
			expectFindings: 1,
			expectFinding:  "Firewall is disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := cmd.CheckFirewallStatus(tt.firewallData)

			if len(findings) != tt.expectFindings {
				t.Errorf("Expected %d findings, got %d", tt.expectFindings, len(findings))
			}

			if tt.expectFindings > 0 && findings[0].Title != tt.expectFinding {
				t.Errorf("Expected finding title '%s', got '%s'", tt.expectFinding, findings[0].Title)
			}
		})
	}
}

func TestCheckOptStatus(t *testing.T) {
	tests := []struct {
		name           string
		optData        cmd.EnforcePolicyOptData
		expectFindings int
		expectFinding  string
	}{
		{
			name: "2FA enforced for admin - no findings",
			optData: cmd.EnforcePolicyOptData{
				OtpEnforceOption: cmd.EnforcePolicyAdmin,
			},
			expectFindings: 0,
		},
		{
			name: "2FA enforced for users - no findings",
			optData: cmd.EnforcePolicyOptData{
				OtpEnforceOption: cmd.EnforcePolicyUser,
			},
			expectFindings: 0,
		},
		{
			name: "2FA not enforced - finding expected",
			optData: cmd.EnforcePolicyOptData{
				OtpEnforceOption: "none",
			},
			expectFindings: 1,
			expectFinding:  "2FA not enforced for administrators",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := cmd.CheckOptStatus(tt.optData)

			if len(findings) != tt.expectFindings {
				t.Errorf("Expected %d findings, got %d", tt.expectFindings, len(findings))
			}

			if tt.expectFindings > 0 && findings[0].Title != tt.expectFinding {
				t.Errorf("Expected finding title '%s', got '%s'", tt.expectFinding, findings[0].Title)
			}
		})
	}
}

func TestCheckTerminalSecurity(t *testing.T) {
	tests := []struct {
		name           string
		terminalData   cmd.TerminalData
		expectFindings int
		expectTelnet   bool
		expectSSH      bool
	}{
		{
			name: "Both services secure",
			terminalData: cmd.TerminalData{
				EnableTelnet: false,
				EnableSSH:    true,
				SSHPort:      2222,
			},
			expectFindings: 0,
		},
		{
			name: "Telnet enabled",
			terminalData: cmd.TerminalData{
				EnableTelnet: true,
				EnableSSH:    false,
				SSHPort:      22,
			},
			expectFindings: 1,
			expectTelnet:   true,
		},
		{
			name: "SSH on default port",
			terminalData: cmd.TerminalData{
				EnableTelnet: false,
				EnableSSH:    true,
				SSHPort:      22,
			},
			expectFindings: 1,
			expectSSH:      true,
		},
		{
			name: "Both Telnet and SSH default port",
			terminalData: cmd.TerminalData{
				EnableTelnet: true,
				EnableSSH:    true,
				SSHPort:      22,
			},
			expectFindings: 2,
			expectTelnet:   true,
			expectSSH:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := cmd.CheckTerminalSecurity(tt.terminalData)

			if len(findings) != tt.expectFindings {
				t.Errorf("Expected %d findings, got %d", tt.expectFindings, len(findings))
			}

			foundTelnet := false
			foundSSH := false

			for _, finding := range findings {
				if strings.Contains(finding.Title, "Telnet") {
					foundTelnet = true
				}
				if strings.Contains(finding.Title, "SSH") && strings.Contains(finding.Title, "default port") {
					foundSSH = true
				}
			}

			if tt.expectTelnet && !foundTelnet {
				t.Error("Expected Telnet finding but didn't find it")
			}

			if tt.expectSSH && !foundSSH {
				t.Error("Expected SSH default port finding but didn't find it")
			}
		})
	}
}

func TestCheckFTPSecurity(t *testing.T) {
	tests := []struct {
		name           string
		ftpData        cmd.FTPData
		expectFindings int
	}{
		{
			name: "FTP disabled",
			ftpData: cmd.FTPData{
				Enable:    false,
				EnableTLS: false,
			},
			expectFindings: 0,
		},
		{
			name: "FTP with TLS",
			ftpData: cmd.FTPData{
				Enable:    true,
				EnableTLS: true,
			},
			expectFindings: 0,
		},
		{
			name: "FTP without TLS - insecure",
			ftpData: cmd.FTPData{
				Enable:    true,
				EnableTLS: false,
			},
			expectFindings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := cmd.CheckFtpSecurity(tt.ftpData)

			if len(findings) != tt.expectFindings {
				t.Errorf("Expected %d findings, got %d", tt.expectFindings, len(findings))
			}

			if tt.expectFindings > 0 {
				if !strings.Contains(findings[0].Title, "FTP") {
					t.Errorf("Expected FTP-related finding, got: %s", findings[0].Title)
				}
			}
		})
	}
}

func TestCheckQuickConnectSecurity(t *testing.T) {
	tests := []struct {
		name             string
		quickConnectData cmd.QuickConnectData
		expectFindings   int
	}{
		{
			name: "QuickConnect disabled",
			quickConnectData: cmd.QuickConnectData{
				Enabled: false,
			},
			expectFindings: 0,
		},
		{
			name: "QuickConnect enabled",
			quickConnectData: cmd.QuickConnectData{
				Enabled: true,
			},
			expectFindings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := cmd.CheckQuickConnectSecurity(tt.quickConnectData)

			if len(findings) != tt.expectFindings {
				t.Errorf("Expected %d findings, got %d", tt.expectFindings, len(findings))
			}

			if tt.expectFindings > 0 {
				if !strings.Contains(findings[0].Title, "QuickConnect") {
					t.Errorf("Expected QuickConnect-related finding, got: %s", findings[0].Title)
				}
			}
		})
	}
}

func TestCheckAutoBlockPolicy(t *testing.T) {
	tests := []struct {
		name           string
		autoBlockData  cmd.AutoBlockData
		expectFindings int
	}{
		{
			name: "Auto block enabled",
			autoBlockData: cmd.AutoBlockData{
				Enable: true,
			},
			expectFindings: 0,
		},
		{
			name: "Auto block disabled",
			autoBlockData: cmd.AutoBlockData{
				Enable: false,
			},
			expectFindings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := cmd.CheckAutoBlockPolicy(tt.autoBlockData)

			if len(findings) != tt.expectFindings {
				t.Errorf("Expected %d findings, got %d", tt.expectFindings, len(findings))
			}

			if tt.expectFindings > 0 {
				if !strings.Contains(findings[0].Title, "Auto block") {
					t.Errorf("Expected Auto block-related finding, got: %s", findings[0].Title)
				}
			}
		})
	}
}
