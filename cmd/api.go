package cmd

import (
	"encoding/json"
	"fmt"
	"time"
)

type EnforcePolicy string

const (
	EnforcePolicyAdmin EnforcePolicy = "admin"
	EnforcePolicyUser  EnforcePolicy = "user"
	NoEnforcePolicy    EnforcePolicy = "none"
	AdminUsername                    = "admin"
)

type UserStatus string

const (
	UserStatusExpired UserStatus = "now"
	UserStatusActive  UserStatus = "normal"
)

type Finding struct {
	Title       string
	Description string
	Remediation string
}

type SecurityReport struct {
	Findings  []Finding
	CheckedAt time.Time
}

type UserListData struct {
	Total int `json:"total"`
	Users []struct {
		Expired UserStatus `json:"expired"`
		Name    string     `json:"name"`
	} `json:"users"`
}

type FirewallData struct {
	Enable_firewall bool `json:"enable_firewall"`
}

type TerminalData struct {
	EnableSSH    bool `json:"enable_ssh"`
	EnableTelnet bool `json:"enable_telnet"`
	SSHPort      int  `json:"ssh_port"`
	TelnetPort   int  `json:"telnet_port"`
}

type AutoBlockData struct {
	Attemps     int  `json:"attempts"`
	Enable      bool `json:"enable"`
	Expire_day  int  `json:"expire_day"`
	Within_mins int  `json:"within_mins"`
}

type EnforcePolicyOptData struct {
	OtpEnforceOption EnforcePolicy `json:"otp_enforce_option"`
}

type PasswordPolicyData struct {
	EnableResetPasswdByEmail bool `json:"enable_reset_passwd_by_email"`
	PasswordMustChange       bool `json:"password_must_change"`
	StrongPassword           struct {
		ExcludeCommonPassword bool `json:"exclude_common_password"`
		ExcludeHistory        bool `json:"exclude_history"`
		ExcludeUsername       bool `json:"exclude_username"`
		HistoryNum            int  `json:"history_num"`
		IncludedNumericChar   bool `json:"included_numeric_char"`
		IncludedSpecialChar   bool `json:"included_special_char"`
		MinLength             int  `json:"min_length"`
		MinLengthEnable       bool `json:"min_length_enable"`
		MixedCase             bool `json:"mixed_case"`
	} `json:"strong_password"`
}

type PackageData struct {
	Packages []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Version    string `json:"version"`
		Timestamp  int64  `json:"timestamp"`
		Additional struct {
			InstallType string `json:"install_type"`
		} `json:"additional"`
	} `json:"packages"`
}

type QuickConnectData struct {
	Enabled bool `json:"enabled"`
}

type FTPData struct {
	Enable      bool `json:"enable"`
	EnableTLS   bool `json:"enable_tls"`
	Port        int  `json:"port"`
	PassiveMode bool `json:"passive_mode"`
}

type SynologyResponseData struct {
	HasFail bool        `json:"has_fail"`
	Result  []APIResult `json:"result"`
}

type SynologyResponse struct {
	Success bool                 `json:"success"`
	Data    SynologyResponseData `json:"data"`
}

type APIResult struct {
	API  string      `json:"api"`
	Data interface{} `json:"data"`
}

type APIEndpoint struct {
	API        string   `json:"api"`
	Method     string   `json:"method"`
	Version    int      `json:"version"`
	Type       string   `json:"type,omitempty"`
	Additional []string `json:"additional,omitempty"`
}

var SecurityFindings = map[string]Finding{
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

func getData[T any](endpoint string, response SynologyResponse) (T, error) {
	var result T

	for _, apiResult := range response.Data.Result {
		if apiResult.API == endpoint {
			if apiResult.Data == nil {
				return result, fmt.Errorf("no data for endpoint %s", endpoint)
			}

			jsonData, err := json.Marshal(apiResult.Data)
			if err != nil {
				return result, fmt.Errorf("marshaling data: %w", err)
			}

			err = json.Unmarshal(jsonData, &result)
			if err != nil {
				return result, fmt.Errorf("unmarshaling to type: %w", err)
			}

			return result, nil
		}
	}

	return result, fmt.Errorf("endpoint %s not found in response", endpoint)
}

func GetUserData(response SynologyResponse) (UserListData, error) {
	return getData[UserListData]("SYNO.Core.User", response)
}

func GetFirewallData(response SynologyResponse) (FirewallData, error) {
	return getData[FirewallData]("SYNO.Core.Security.Firewall.Profile", response)
}
