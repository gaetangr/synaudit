package tests

import (
	"testing"

	"github.com/gaetangr/synaudit/cmd"
)

func TestSecurityFindingsIntegrity(t *testing.T) {
	expectedSecurityFindings := map[string]cmd.Finding{
		"ADMIN_ACCOUNT_ACTIVE": {
			Title:       "Admin account is active",
			Description: "The default admin account is still active and not disabled",
			Remediation: "Disable the admin account and use a custom administrator account instead",
		},
		"FIREWALL_DISABLED": {
			Title:       "Firewall is disabled",
			Description: "The built-in firewall is not enabled",
			Remediation: "Enable the firewall in Control Panel > Security > Firewall",
		},
		"NO_2FA_ENFORCED_ADMIN": {
			Title:       "2FA not enforced for administrators",
			Description: "Two-factor authentication is not required for administrator accounts",
			Remediation: "Enable 2FA enforcement for administrators in Control Panel > User & Group > Advanced",
		},
		"TELNET_ENABLED": {
			Title:       "Telnet service is enabled",
			Description: "Telnet provides unencrypted remote access and should be disabled",
			Remediation: "Disable Telnet in Control Panel > Terminal & SNMP and use SSH instead",
		},
		"SSH_DEFAULT_PORT": {
			Title:       "SSH using default port",
			Description: "SSH is running on the default port 22",
			Remediation: "Change SSH port to a non-standard port in Control Panel > Terminal & SNMP",
		},
		"FTP_ENABLED": {
			Title:       "Unencrypted FTP is enabled",
			Description: "FTP service is enabled without TLS encryption",
			Remediation: "Enable FTPS or disable FTP service in Control Panel > File Services > FTP",
		},
		"QUICKCONNECT_ENABLED": {
			Title:       "QuickConnect is enabled",
			Description: "QuickConnect may expose your NAS to external networks",
			Remediation: "Consider disabling QuickConnect if not needed in Control Panel > QuickConnect",
		},
		"AUTO_BLOCK_DISABLED": {
			Title:       "Auto block is disabled",
			Description: "Automatic IP blocking for failed login attempts is disabled",
			Remediation: "Enable auto block in Control Panel > Security > Account",
		},
	}

	for key, expectedFinding := range expectedSecurityFindings {
		actualFinding, exists := cmd.SecurityFindings[key]
		if !exists {
			t.Errorf("Security finding '%s' is missing from SecurityFindings map", key)
			continue
		}

		if actualFinding.Title != expectedFinding.Title {
			t.Errorf("Finding '%s': Title mismatch. Expected '%s', got '%s'",
				key, expectedFinding.Title, actualFinding.Title)
		}

		if actualFinding.Description != expectedFinding.Description {
			t.Errorf("Finding '%s': Description mismatch. Expected '%s', got '%s'",
				key, expectedFinding.Description, actualFinding.Description)
		}

		if actualFinding.Remediation != expectedFinding.Remediation {
			t.Errorf("Finding '%s': Remediation mismatch. Expected '%s', got '%s'",
				key, expectedFinding.Remediation, actualFinding.Remediation)
		}
	}

	if len(cmd.SecurityFindings) != len(expectedSecurityFindings) {
		t.Errorf("SecurityFindings count mismatch. Expected %d, got %d",
			len(expectedSecurityFindings), len(cmd.SecurityFindings))
	}
}

func TestSecurityFindingsNotModified(t *testing.T) {
	originalCount := len(cmd.SecurityFindings)

	originalAdminFinding := cmd.SecurityFindings["ADMIN_ACCOUNT_ACTIVE"]

	if originalAdminFinding.Title != "Admin account is active" {
		t.Errorf("ADMIN_ACCOUNT_ACTIVE finding has been modified. Expected 'Admin account is active', got '%s'",
			originalAdminFinding.Title)
	}

	if originalCount != 8 {
		t.Errorf("Expected exactly 8 security findings, got %d. This suggests findings have been added or removed.",
			originalCount)
	}
}

func TestCriticalSecurityFindingsPresent(t *testing.T) {
	criticalFindings := []string{
		"ADMIN_ACCOUNT_ACTIVE",
		"FIREWALL_DISABLED",
		"NO_2FA_ENFORCED_ADMIN",
		"TELNET_ENABLED",
	}

	for _, key := range criticalFindings {
		finding, exists := cmd.SecurityFindings[key]
		if !exists {
			t.Errorf("Critical security finding '%s' is missing", key)
			continue
		}

		if finding.Title == "" {
			t.Errorf("Critical finding '%s' has empty title", key)
		}

		if finding.Description == "" {
			t.Errorf("Critical finding '%s' has empty description", key)
		}

		if finding.Remediation == "" {
			t.Errorf("Critical finding '%s' has empty remediation", key)
		}
	}
}

func TestNetworkSecurityFindings(t *testing.T) {
	networkRelatedFindings := []string{
		"SSH_DEFAULT_PORT",
		"TELNET_ENABLED",
		"FTP_ENABLED",
		"QUICKCONNECT_ENABLED",
	}

	for _, key := range networkRelatedFindings {
		finding, exists := cmd.SecurityFindings[key]
		if !exists {
			t.Errorf("Network security finding '%s' is missing", key)
			continue
		}

		if len(finding.Title) < 10 {
			t.Errorf("Network finding '%s' title too short: '%s'", key, finding.Title)
		}

		if len(finding.Description) < 25 {
			t.Errorf("Network finding '%s' description too short: '%s'", key, finding.Description)
		}
	}
}

func TestFindingDataIntegrity(t *testing.T) {
	for key, finding := range cmd.SecurityFindings {
		if finding.Title == finding.Description {
			t.Errorf("Finding '%s': Title and Description should not be identical", key)
		}

		if finding.Title == finding.Remediation {
			t.Errorf("Finding '%s': Title and Remediation should not be identical", key)
		}

		if finding.Description == finding.Remediation {
			t.Errorf("Finding '%s': Description and Remediation should not be identical", key)
		}
	}
}
