package api

import "time"

type LoginData struct {
	DID          string `json:"did"`
	IsPortalPort bool   `json:"is_portal_port"`
	SID          string `json:"sid"`
}

type LoginResponse struct {
	Data    LoginData `json:"data"`
	Success bool      `json:"success"`
	Error   *struct {
		Code int `json:"code"`
	} `json:"error,omitempty"`
}

type EnforcePolicy string

const (
	EnforcePolicyAdmin EnforcePolicy = "admin"
	EnforcePolicyUser  EnforcePolicy = "user"
	NoEnforcePolicy    EnforcePolicy = "none"
)

type EnforcePolicyOptData struct {
	OtpEnforceOption EnforcePolicy `json:"otp_enforce_option"`
}

type UserStatus string

const (
	UserStatusExpired UserStatus = "now"
	UserStatusActive  UserStatus = "normal"
	AdminUsername                = "admin"
)

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

type Finding struct {
	Title       string
	Description string
	Remediation string
}

type FTPData struct {
	Enable      bool `json:"enable"`
	EnableTLS   bool `json:"enable_tls"`
	Port        int  `json:"port"`
	PassiveMode bool `json:"passive_mode"`
}

type SecurityReport struct {
	Findings  []Finding
	CheckedAt time.Time
}

type APIResult struct {
	API  string      `json:"api"`
	Data interface{} `json:"data"`
}

type SynologyResponseData struct {
	HasFail bool        `json:"has_fail"`
	Result  []APIResult `json:"result"`
}

type SynologyResponse struct {
	Success bool                 `json:"success"`
	Data    SynologyResponseData `json:"data"`
}
