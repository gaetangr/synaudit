package cmd

import (
	"fmt"
	"strings"
	"time"
)

func IsAdminDisabled(userListData UserListData) (bool, error) {
	for _, user := range userListData.Users {
		if user.Name == AdminUsername {
			if user.Expired == UserStatusExpired {
				return true, nil
			}
			return false, nil
		}
	}
	return false, fmt.Errorf("admin user not found")
}

func CheckAdminStatus(userData UserListData) []Finding {
	var findings []Finding

	disabled, _ := IsAdminDisabled(userData)

	if !disabled {
		findings = append(findings, SecurityFindings["ADMIN_ACCOUNT_ACTIVE"])
	}

	return findings
}

func CheckFirewallStatus(firewallData FirewallData) []Finding {
	var findings []Finding

	if !firewallData.Enable_firewall {
		return append(findings, SecurityFindings["FIREWALL_DISABLED"])
	}
	return []Finding{}
}

func CheckOptStatus(optData EnforcePolicyOptData) []Finding {
	var findings []Finding

	if optData.OtpEnforceOption != EnforcePolicyAdmin && optData.OtpEnforceOption != EnforcePolicyUser {
		return append(findings, SecurityFindings["NO_2FA_ENFORCED_ADMIN"])
	}
	return []Finding{}
}

func CheckTerminalSecurity(terminalData TerminalData) []Finding {
	var findings []Finding

	if terminalData.EnableTelnet {
		findings = append(findings, SecurityFindings["TELNET_ENABLED"])
	}

	if terminalData.EnableSSH && terminalData.SSHPort == 22 {
		findings = append(findings, SecurityFindings["SSH_DEFAULT_PORT"])
	}

	return findings
}

func CheckFtpSecurity(ftpData FTPData) []Finding {
	var findings []Finding

	if ftpData.Enable && !ftpData.EnableTLS {
		findings = append(findings, SecurityFindings["FTP_ENABLED"])
	}

	return findings
}

func CheckPasswordPolicy(passwordData PasswordPolicyData) []Finding {
	var findings []Finding

	if !passwordData.StrongPassword.MinLengthEnable {
		findings = append(findings, Finding{
			Title:       "Password length requirement disabled",
			Description: "Minimum password length requirement is not enforced",
			Remediation: "Enable minimum password length requirement in Control Panel > User & Group > Advanced > Password Policy",
		})
	} else if passwordData.StrongPassword.MinLength < 10 {
		findings = append(findings, Finding{
			Title:       "Password minimum length too short",
			Description: fmt.Sprintf("Current minimum password length is %d characters, should be at least 10", passwordData.StrongPassword.MinLength),
			Remediation: "Increase minimum password length to 10+ characters",
		})
	}

	if !passwordData.StrongPassword.IncludedNumericChar {
		findings = append(findings, Finding{
			Title:       "Numeric characters not required in passwords",
			Description: "Password policy does not require numeric characters",
			Remediation: "Enable numeric character requirement in password policy",
		})
	}

	if !passwordData.StrongPassword.MixedCase {
		findings = append(findings, Finding{
			Title:       "Mixed case not required in passwords",
			Description: "Password policy does not require both uppercase and lowercase letters",
			Remediation: "Enable mixed case requirement in password policy",
		})
	}

	if !passwordData.StrongPassword.IncludedSpecialChar {
		findings = append(findings, Finding{
			Title:       "Special characters not required in passwords",
			Description: "Password policy does not require special characters",
			Remediation: "Enable special character requirement in password policy for stronger security",
		})
	}

	if !passwordData.StrongPassword.ExcludeUsername {
		findings = append(findings, Finding{
			Title:       "Username inclusion allowed in passwords",
			Description: "Users can include their username in their password",
			Remediation: "Enable username exclusion in password policy",
		})
	}

	if !passwordData.StrongPassword.ExcludeCommonPassword {
		findings = append(findings, Finding{
			Title:       "Common passwords not blocked",
			Description: "Common weak passwords are not being blocked",
			Remediation: "Enable common password exclusion to prevent use of dictionary words and common passwords",
		})
	}

	if !passwordData.StrongPassword.ExcludeHistory {
		findings = append(findings, Finding{
			Title:       "Password history not enforced",
			Description: "Users can reuse their previous passwords",
			Remediation: "Enable password history to prevent password reuse",
		})
	} else if passwordData.StrongPassword.HistoryNum < 5 {
		findings = append(findings, Finding{
			Title:       "Password history count too low",
			Description: fmt.Sprintf("Only %d previous passwords are remembered, should be at least 5", passwordData.StrongPassword.HistoryNum),
			Remediation: "Increase password history count to 5 or more",
		})
	}

	if !passwordData.PasswordMustChange {
		findings = append(findings, Finding{
			Title:       "Password expiration not enforced",
			Description: "Users are not required to change their passwords periodically",
			Remediation: "Consider enabling periodic password changes for enhanced security",
		})
	}

	return findings
}

func CheckPackageSecurity(packageData PackageData) []Finding {
	var findings []Finding

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

		for riskyID, description := range riskyPackages {
			if strings.Contains(pkg.ID, riskyID) || strings.Contains(pkg.Name, riskyID) {
				findings = append(findings, Finding{
					Title:       fmt.Sprintf("Potentially risky package installed: %s", pkg.Name),
					Description: fmt.Sprintf("%s. %s", pkg.Name, description),
					Remediation: fmt.Sprintf("Review if %s is necessary and ensure it's properly configured", pkg.Name),
				})
			}
		}

		for _, obsolete := range obsoletePackages {
			if strings.Contains(pkg.ID, obsolete) {
				findings = append(findings, Finding{
					Title:       fmt.Sprintf("Obsolete package installed: %s", pkg.Name),
					Description: fmt.Sprintf("%s is outdated and may have security vulnerabilities", pkg.Name),
					Remediation: fmt.Sprintf("Remove %s and upgrade to a supported version if needed", pkg.Name),
				})
			}
		}

		for _, dev := range developmentPackages {
			if strings.Contains(pkg.ID, dev) {
				findings = append(findings, Finding{
					Title:       fmt.Sprintf("Development package in production: %s", pkg.Name),
					Description: fmt.Sprintf("%s should typically not be installed on production systems", pkg.Name),
					Remediation: fmt.Sprintf("Remove %s if not required for production use", pkg.Name),
				})
			}
		}
	}

	return findings
}

func CheckQuickConnectSecurity(quickConnectData QuickConnectData) []Finding {
	var findings []Finding

	if quickConnectData.Enabled {
		findings = append(findings, SecurityFindings["QUICKCONNECT_ENABLED"])
	}

	return findings
}

func CheckAutoBlockPolicy(autoBlockData AutoBlockData) []Finding {
	var findings []Finding
	if !autoBlockData.Enable {
		findings = append(findings, SecurityFindings["AUTO_BLOCK_DISABLED"])
	}
	return findings
}

func generateReport(response SynologyResponse) (*SecurityReport, error) {
	report := &SecurityReport{
		CheckedAt: time.Now(),
		Findings:  []Finding{},
	}

	checks := map[string]func() ([]Finding, error){
		"users": func() ([]Finding, error) {
			data, err := GetUserData(response)
			if err != nil {
				return nil, err
			}
			return CheckAdminStatus(data), nil
		},
		"firewall": func() ([]Finding, error) {
			data, err := GetFirewallData(response)
			if err != nil {
				return nil, err
			}
			return CheckFirewallStatus(data), nil
		},
		"opt": func() ([]Finding, error) {
			data, err := getOptData(response)
			if err != nil {
				return nil, err
			}
			return CheckOptStatus(data), nil
		},
		"password_policy": func() ([]Finding, error) {
			data, err := getPasswordPolicyData(response)
			if err != nil {
				return nil, err
			}
			return CheckPasswordPolicy(data), nil
		},
		"packages": func() ([]Finding, error) {
			data, err := getPackageData(response)
			if err != nil {
				return nil, err
			}
			return CheckPackageSecurity(data), nil
		},
		"terminal": func() ([]Finding, error) {
			data, err := getTerminalData(response)
			if err != nil {
				return nil, err
			}
			return CheckTerminalSecurity(data), nil
		},
		"ftp": func() ([]Finding, error) {
			data, err := getFTPData(response)
			if err != nil {
				return nil, err
			}
			return CheckFtpSecurity(data), nil
		},
		"quickconnect": func() ([]Finding, error) {
			data, err := getQuickConnectData(response)
			if err != nil {
				return nil, err
			}
			return CheckQuickConnectSecurity(data), nil
		},
		"autoblock": func() ([]Finding, error) {
			data, err := getAutoBlockData(response)
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

func displayReport(report *SecurityReport) {
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
