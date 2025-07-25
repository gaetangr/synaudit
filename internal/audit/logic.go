package audit

import (
	"fmt"
	"strings"
	"time"

	"github.com/gaetangr/synaudit/internal/api"
)

func IsAdminDisabled(userListData api.UserListData) (bool, error) {
	for _, user := range userListData.Users {
		if user.Name == api.AdminUsername {
			if user.Expired == api.UserStatusExpired {
				return true, nil
			}
			return false, nil
		}
	}
	return false, fmt.Errorf("admin user not found")
}

func CheckAdminStatus(userData api.UserListData) []api.Finding {
	var findings []api.Finding

	disabled, _ := IsAdminDisabled(userData)

	if !disabled {
		findings = append(findings, SecurityFindings["ADMIN_ACCOUNT_ACTIVE"])
	}

	return findings
}

func CheckFirewallStatus(firewallData api.FirewallData) []api.Finding {
	var findings []api.Finding

	if !firewallData.Enable_firewall {
		return append(findings, SecurityFindings["FIREWALL_DISABLED"])
	}
	return []api.Finding{}
}

func CheckOptStatus(optData api.EnforcePolicyOptData) []api.Finding {
	var findings []api.Finding

	if optData.OtpEnforceOption != api.EnforcePolicyAdmin && optData.OtpEnforceOption != api.EnforcePolicyUser {
		return append(findings, SecurityFindings["NO_2FA_ENFORCED_ADMIN"])
	}
	return []api.Finding{}
}

func CheckTerminalSecurity(terminalData api.TerminalData) []api.Finding {
	var findings []api.Finding

	if terminalData.EnableTelnet {
		findings = append(findings, SecurityFindings["TELNET_ENABLED"])
	}

	if terminalData.EnableSSH && terminalData.SSHPort == 22 {
		findings = append(findings, SecurityFindings["SSH_DEFAULT_PORT"])
	}

	return findings
}

func CheckFtpSecurity(ftpData api.FTPData) []api.Finding {
	var findings []api.Finding

	if ftpData.Enable && !ftpData.EnableTLS {
		findings = append(findings, SecurityFindings["FTP_ENABLED"])
	}

	return findings
}

func CheckPasswordPolicy(passwordData api.PasswordPolicyData) []api.Finding {
	var findings []api.Finding

	if !passwordData.StrongPassword.MinLengthEnable {
		findings = append(findings, api.Finding{
			Title:       "Password length requirement disabled",
			Description: "Minimum password length requirement is not enforced",
			Remediation: "Enable minimum password length requirement in Control Panel > User & Group > Advanced > Password Policy",
		})
	} else if passwordData.StrongPassword.MinLength < 10 {
		findings = append(findings, api.Finding{
			Title:       "Password minimum length too short",
			Description: fmt.Sprintf("Current minimum password length is %d characters, should be at least 10", passwordData.StrongPassword.MinLength),
			Remediation: "Increase minimum password length to 10+ characters",
		})
	}

	if !passwordData.StrongPassword.IncludedNumericChar {
		findings = append(findings, api.Finding{
			Title:       "Numeric characters not required in passwords",
			Description: "Password policy does not require numeric characters",
			Remediation: "Enable numeric character requirement in password policy",
		})
	}

	if !passwordData.StrongPassword.MixedCase {
		findings = append(findings, api.Finding{
			Title:       "Mixed case not required in passwords",
			Description: "Password policy does not require both uppercase and lowercase letters",
			Remediation: "Enable mixed case requirement in password policy",
		})
	}

	if !passwordData.StrongPassword.IncludedSpecialChar {
		findings = append(findings, api.Finding{
			Title:       "Special characters not required in passwords",
			Description: "Password policy does not require special characters",
			Remediation: "Enable special character requirement in password policy for stronger security",
		})
	}

	if !passwordData.StrongPassword.ExcludeUsername {
		findings = append(findings, api.Finding{
			Title:       "Username inclusion allowed in passwords",
			Description: "Users can include their username in their password",
			Remediation: "Enable username exclusion in password policy",
		})
	}

	if !passwordData.StrongPassword.ExcludeCommonPassword {
		findings = append(findings, api.Finding{
			Title:       "Common passwords not blocked",
			Description: "Common weak passwords are not being blocked",
			Remediation: "Enable common password exclusion to prevent use of dictionary words and common passwords",
		})
	}

	if !passwordData.StrongPassword.ExcludeHistory {
		findings = append(findings, api.Finding{
			Title:       "Password history not enforced",
			Description: "Users can reuse their previous passwords",
			Remediation: "Enable password history to prevent password reuse",
		})
	} else if passwordData.StrongPassword.HistoryNum < 5 {
		findings = append(findings, api.Finding{
			Title:       "Password history count too low",
			Description: fmt.Sprintf("Only %d previous passwords are remembered, should be at least 5", passwordData.StrongPassword.HistoryNum),
			Remediation: "Increase password history count to 5 or more",
		})
	}

	if !passwordData.PasswordMustChange {
		findings = append(findings, api.Finding{
			Title:       "Password expiration not enforced",
			Description: "Users are not required to change their passwords periodically",
			Remediation: "Consider enabling periodic password changes for enhanced security",
		})
	}

	return findings
}

func CheckPackageSecurity(packageData api.PackageData) []api.Finding {
	var findings []api.Finding

	riskyPackages := map[string]string{
		"Node.js":          "Runtime environments can expose additional attack vectors",
		"PHP":              "Web scripting languages increase attack surface",
		"Perl":             "Scripting languages can be exploited if not properly secured",
		"Python2":          "Python 2 is deprecated and no longer receives security updates",
		"ContainerManager": "Docker containers can compromise system security if misconfigured",
		"DownloadStation":  "Download services can be exploited to access unauthorized content",
		"WebDAV":           "WebDAV service can expose file system to web attacks",
		"VPN Server":       "VPN services need careful configuration to remain secure",
		"RADIUS Server":    "Authentication servers are high-value targets",
	}

	obsoletePackages := []string{
		"Python2", "PHP7.4",
	}

	developmentPackages := []string{
		"Node.js", "PHP", "Perl",
	}

	for _, pkg := range packageData.Packages {
		if pkg.Additional.InstallType == "system" {
			continue
		}

		// Check for risky packages
		for riskyID, description := range riskyPackages {
			if strings.Contains(pkg.ID, riskyID) || strings.Contains(pkg.Name, riskyID) {
				findings = append(findings, api.Finding{
					Title:       fmt.Sprintf("Potentially risky package installed: %s", pkg.Name),
					Description: fmt.Sprintf("%s. %s", pkg.Name, description),
					Remediation: fmt.Sprintf("Review if %s is necessary and ensure it's properly configured", pkg.Name),
				})
				break // Only report one risky finding per package
			}
		}

		// Check for obsolete packages
		for _, obsolete := range obsoletePackages {
			if strings.Contains(pkg.ID, obsolete) || strings.Contains(pkg.Name, obsolete) {
				findings = append(findings, api.Finding{
					Title:       fmt.Sprintf("Obsolete package installed: %s", pkg.Name),
					Description: fmt.Sprintf("%s is outdated and may have security vulnerabilities", pkg.Name),
					Remediation: fmt.Sprintf("Remove %s and upgrade to a supported version if needed", pkg.Name),
				})
				break // Only report one obsolete finding per package
			}
		}

		// Check for development packages (separate check, can coexist with risky)
		for _, dev := range developmentPackages {
			if strings.Contains(pkg.ID, dev) || strings.Contains(pkg.Name, dev) {
				findings = append(findings, api.Finding{
					Title:       fmt.Sprintf("Development package in production: %s", pkg.Name),
					Description: fmt.Sprintf("%s should typically not be installed on production systems", pkg.Name),
					Remediation: fmt.Sprintf("Remove %s if not required for production use", pkg.Name),
				})
				break // Only report one development finding per package
			}
		}
	}

	return findings
}

func CheckQuickConnectSecurity(quickConnectData api.QuickConnectData) []api.Finding {
	var findings []api.Finding

	if quickConnectData.Enabled {
		findings = append(findings, SecurityFindings["QUICKCONNECT_ENABLED"])
	}

	return findings
}

func CheckAutoBlockPolicy(autoBlockData api.AutoBlockData) []api.Finding {
	var findings []api.Finding
	if !autoBlockData.Enable {
		findings = append(findings, SecurityFindings["AUTO_BLOCK_DISABLED"])
	}
	return findings
}

func GenerateReport(response api.SynologyResponse) (*api.SecurityReport, error) {
	report := &api.SecurityReport{
		CheckedAt: time.Now(),
		Findings:  []api.Finding{},
	}

	checks := map[string]func() ([]api.Finding, error){
		"users": func() ([]api.Finding, error) {
			data, err := api.GetUserData(response)
			if err != nil {
				return nil, err
			}
			return CheckAdminStatus(data), nil
		},
		"firewall": func() ([]api.Finding, error) {
			data, err := api.GetFirewallData(response)
			if err != nil {
				return nil, err
			}
			return CheckFirewallStatus(data), nil
		},
		"opt": func() ([]api.Finding, error) {
			data, err := api.GetOptData(response)
			if err != nil {
				return nil, err
			}
			return CheckOptStatus(data), nil
		},
		"password_policy": func() ([]api.Finding, error) {
			data, err := api.GetPasswordPolicyData(response)
			if err != nil {
				return nil, err
			}
			return CheckPasswordPolicy(data), nil
		},
		"packages": func() ([]api.Finding, error) {
			data, err := api.GetPackageData(response)
			if err != nil {
				return nil, err
			}
			return CheckPackageSecurity(data), nil
		},
		"terminal": func() ([]api.Finding, error) {
			data, err := api.GetTerminalData(response)
			if err != nil {
				return nil, err
			}
			return CheckTerminalSecurity(data), nil
		},
		"ftp": func() ([]api.Finding, error) {
			data, err := api.GetFTPData(response)
			if err != nil {
				return nil, err
			}
			return CheckFtpSecurity(data), nil
		},
		"quickconnect": func() ([]api.Finding, error) {
			data, err := api.GetQuickConnectData(response)
			if err != nil {
				return nil, err
			}
			return CheckQuickConnectSecurity(data), nil
		},
		"autoblock": func() ([]api.Finding, error) {
			data, err := api.GetAutoBlockData(response)
			if err != nil {
				return nil, err
			}
			return CheckAutoBlockPolicy(data), nil
		},
	}

	for name, check := range checks {
		findings, err := check()
		if err != nil {
			fmt.Printf("Warning: %s check failed: %v\n", name, err)
			continue
		}
		report.Findings = append(report.Findings, findings...)
	}

	return report, nil
}

func DisplayReport(report *api.SecurityReport) {
	fmt.Println("\nSECURITY AUDIT REPORT")
	fmt.Printf("Checked at: %s\n", report.CheckedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Total issues: %d\n", len(report.Findings))

	if len(report.Findings) == 0 {
		fmt.Println("\nNo security issues found!")
		return
	}

	fmt.Println("\n" + strings.Repeat("-", 80))

	for i, finding := range report.Findings {
		fmt.Printf("\n[%d] %s\n", i+1, finding.Title)
		fmt.Printf("    %s\n", finding.Description)
		fmt.Printf("    %s\n", finding.Remediation)
	}

	fmt.Println("\n" + strings.Repeat("-", 80))
}
