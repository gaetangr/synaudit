package main

import (
	"fmt"
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

func checkAdminStatus(userData UserListData) []Finding {
	var findings []Finding

	disabled, err := IsAdminDisabled(userData)
	if err != nil {
		findings = append(findings, Finding{
			Title:       "Admin User Not Found",
			Description: "The admin account does not exist in the system",
			Remediation: "Investigate why the admin account is missing",
		})
		return findings
	}

	if disabled {
		findings = append(findings, Finding{
			Title:       "Admin Account Disabled",
			Description: "The admin account is currently disabled (expired status: 'now')",
			Remediation: "Re-enable the admin account if this was not intentional",
		})
	}

	return findings
}
func generateReport(response SynologyResponse) (*SecurityReport, error) {
	report := &SecurityReport{
		CheckedAt: time.Now(),
		Findings:  []Finding{},
	}

	userData, err := getUserData(response)

	if err != nil {
		return report, err
	}

	report.Findings = append(report.Findings, checkAdminStatus(userData)...)

	return report, nil
}
func displayReport(report *SecurityReport) {
	fmt.Println("\n🔍 SECURITY AUDIT REPORT")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════════")
	fmt.Printf("📅 Checked at: %s\n", report.CheckedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("📊 Total issues: %d\n\n", len(report.Findings))

	if len(report.Findings) == 0 {
		fmt.Println("✅ No security issues found! Your Synology appears to be well configured.")
		return
	}

	fmt.Println("┌────┬─────────────────────────────────────────┬──────────────────────────────────────────────┐")
	fmt.Println("│ #  │ Issue                                   │ Description                                  │")
	fmt.Println("├────┼─────────────────────────────────────────┼──────────────────────────────────────────────┤")

	for i, finding := range report.Findings {
		fmt.Printf("│ %-2d │ %-39s │ %-44s │\n",
			i+1,
			truncateString(finding.Title, 39),
			truncateString(finding.Description, 44))
	}

	fmt.Println("└────┴─────────────────────────────────────────┴──────────────────────────────────────────────┘")

	fmt.Println("\n🔧 RECOMMENDED ACTIONS:")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════════")

	for i, finding := range report.Findings {
		fmt.Printf("\n%d. %s\n", i+1, finding.Title)
		fmt.Printf("   💡 Solution: %s\n", finding.Remediation)
	}

	fmt.Println("\n═══════════════════════════════════════════════════════════════════════════════")
}
