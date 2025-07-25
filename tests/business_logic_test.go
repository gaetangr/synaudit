package tests

import (
	"testing"

	"github.com/gaetangr/synaudit/internal/api"
	"github.com/gaetangr/synaudit/internal/audit"
)

func TestPasswordPolicyAudit(t *testing.T) {
	tests := []struct {
		name           string
		passwordData   api.PasswordPolicyData
		expectFindings int
		expectTitles   []string
	}{
		{
			name: "Secure password policy",
			passwordData: api.PasswordPolicyData{
				StrongPassword: struct {
					ExcludeCommonPassword bool `json:"exclude_common_password"`
					ExcludeHistory        bool `json:"exclude_history"`
					ExcludeUsername       bool `json:"exclude_username"`
					HistoryNum            int  `json:"history_num"`
					IncludedNumericChar   bool `json:"included_numeric_char"`
					IncludedSpecialChar   bool `json:"included_special_char"`
					MinLength             int  `json:"min_length"`
					MinLengthEnable       bool `json:"min_length_enable"`
					MixedCase             bool `json:"mixed_case"`
				}{
					MinLengthEnable:       true,
					MinLength:             12,
					IncludedNumericChar:   true,
					MixedCase:             true,
					IncludedSpecialChar:   true,
					ExcludeUsername:       true,
					ExcludeCommonPassword: true,
					ExcludeHistory:        true,
					HistoryNum:            5,
				},
				PasswordMustChange: true,
			},
			expectFindings: 0,
		},
		{
			name: "Insecure password policy - no length requirement",
			passwordData: api.PasswordPolicyData{
				StrongPassword: struct {
					ExcludeCommonPassword bool `json:"exclude_common_password"`
					ExcludeHistory        bool `json:"exclude_history"`
					ExcludeUsername       bool `json:"exclude_username"`
					HistoryNum            int  `json:"history_num"`
					IncludedNumericChar   bool `json:"included_numeric_char"`
					IncludedSpecialChar   bool `json:"included_special_char"`
					MinLength             int  `json:"min_length"`
					MinLengthEnable       bool `json:"min_length_enable"`
					MixedCase             bool `json:"mixed_case"`
				}{
					MinLengthEnable:       false,
					MinLength:             6,
					IncludedNumericChar:   false,
					MixedCase:             false,
					IncludedSpecialChar:   false,
					ExcludeUsername:       false,
					ExcludeCommonPassword: false,
					ExcludeHistory:        false,
					HistoryNum:            0,
				},
				PasswordMustChange: false,
			},
			expectFindings: 8,
			expectTitles: []string{
				"Password length requirement disabled",
				"Numeric characters not required in passwords",
				"Mixed case not required in passwords",
				"Special characters not required in passwords",
				"Username inclusion allowed in passwords",
				"Common passwords not blocked",
				"Password history not enforced",
				"Password expiration not enforced",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := audit.CheckPasswordPolicy(tt.passwordData)

			if len(findings) != tt.expectFindings {
				t.Errorf("Expected %d findings, got %d", tt.expectFindings, len(findings))
			}

			if len(tt.expectTitles) > 0 {
				titles := make([]string, len(findings))
				for i, finding := range findings {
					titles[i] = finding.Title
				}

				for _, expectedTitle := range tt.expectTitles {
					found := false
					for _, title := range titles {
						if title == expectedTitle {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected finding with title '%s' not found. Got titles: %v", expectedTitle, titles)
					}
				}
			}
		})
	}
}

func TestPackageSecurityAudit(t *testing.T) {
	tests := []struct {
		name           string
		packageData    api.PackageData
		expectFindings int
		expectTitles   []string
	}{
		{
			name: "Secure package configuration",
			packageData: api.PackageData{
				Packages: []struct {
					ID         string `json:"id"`
					Name       string `json:"name"`
					Version    string `json:"version"`
					Timestamp  int64  `json:"timestamp"`
					Additional struct {
						InstallType string `json:"install_type"`
					} `json:"additional"`
				}{
					{
						ID:      "safe_package",
						Name:    "Safe Package",
						Version: "1.0.0",
						Additional: struct {
							InstallType string `json:"install_type"`
						}{
							InstallType: "system",
						},
					},
				},
			},
			expectFindings: 0,
		},
		{
			name: "Risky packages installed",
			packageData: api.PackageData{
				Packages: []struct {
					ID         string `json:"id"`
					Name       string `json:"name"`
					Version    string `json:"version"`
					Timestamp  int64  `json:"timestamp"`
					Additional struct {
						InstallType string `json:"install_type"`
					} `json:"additional"`
				}{
					{
						ID:      "node_js_package",
						Name:    "Node.js",
						Version: "18.0.0",
						Additional: struct {
							InstallType string `json:"install_type"`
						}{
							InstallType: "user",
						},
					},
				},
			},
			expectFindings: 2,
			expectTitles: []string{
				"Potentially risky package installed: Node.js",
				"Development package in production: Node.js",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := audit.CheckPackageSecurity(tt.packageData)

			if len(findings) != tt.expectFindings {
				t.Errorf("Expected %d findings, got %d", tt.expectFindings, len(findings))
			}

			if len(tt.expectTitles) > 0 {
				titles := make([]string, len(findings))
				for i, finding := range findings {
					titles[i] = finding.Title
				}

				for _, expectedTitle := range tt.expectTitles {
					found := false
					for _, title := range titles {
						if title == expectedTitle {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected finding with title '%s' not found. Got titles: %v", expectedTitle, titles)
					}
				}
			}
		})
	}
}
