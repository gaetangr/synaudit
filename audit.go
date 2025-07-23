package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func IsAdminDisabled(userListData UserListData) (bool, error) {
	for _, user := range userListData.Users {
		if user.Name == AdminUsername {
			fmt.Printf("DEBUG: Admin user found - expired: %s\n", user.Expired)

			if user.Expired == UserStatusExpired {
				return true, nil
			}
			return false, nil
		}
	}
	return false, fmt.Errorf("admin user not found")
}

func checkAdminStatus(userData UserListData) []Finding {
	var findings []Finding

	disabled, _ := IsAdminDisabled(userData)

	if !disabled {
		findings = append(findings, SecurityFindings["ADMIN_ACCOUNT_ACTIVE"])
	}

	return findings
}

func checkFirewallStatus(firewallData FirewallData) []Finding {
	var findings []Finding

	if !firewallData.Enable_firewall {
		return append(findings, SecurityFindings["FIREWALL_DISABLED"])
	}
	return []Finding{}
}

func checkOptStatus(optData EnforcePolicyOptData) []Finding {
	var findings []Finding

	if optData.OtpEnforceOption != EnforcePolicyAdmin && optData.OtpEnforceOption != EnforcePolicyUser {
		return append(findings, SecurityFindings["NO_2FA_ENFORCED_ADMIN"])
	}
	return []Finding{}
}

func generateReport(response SynologyResponse) (*SecurityReport, error) {
	report := &SecurityReport{
		CheckedAt: time.Now(),
		Findings:  []Finding{},
	}

	checks := map[string]func() ([]Finding, error){
		"users": func() ([]Finding, error) {
			data, err := getUserData(response)
			if err != nil {
				return nil, err
			}
			return checkAdminStatus(data), nil
		},
		"firewall": func() ([]Finding, error) {
			data, err := getFirewallData(response)
			if err != nil {
				return nil, err
			}
			return checkFirewallStatus(data), nil
		},
		"opt": func() ([]Finding, error) {
			data, err := getOptData(response)
			if err != nil {
				return nil, err
			}
			return checkOptStatus(data), nil
		},
		"network": func() ([]Finding, error) {
			url := os.Getenv("SYNOLOGY_HOST")
			host, err := extractHost(url)
			if err != nil {
				return nil, err
			}
			_, networkFindings := scanPorts(host)
			return networkFindings, nil
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
	fmt.Println("\n🔍 SECURITY AUDIT REPORT")
	fmt.Printf("📅 Checked at: %s\n", report.CheckedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("📊 Total issues: %d\n", len(report.Findings))

	if len(report.Findings) == 0 {
		fmt.Println("\n✅ No security issues found!")
		return
	}

	fmt.Println("\n" + strings.Repeat("─", 80))

	for i, finding := range report.Findings {
		fmt.Printf("\n[%d] %s\n", i+1, finding.Title)
		fmt.Printf("    ⚠️  %s\n", finding.Description)
		fmt.Printf("    💡 %s\n", finding.Remediation)
	}

	fmt.Println("\n" + strings.Repeat("─", 80))
}
