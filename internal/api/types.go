package api

import (
	"fmt"
	"time"
)

type SynologyErrorCode struct {
	Code        int
	Description string
}

var SynologyErrorCodes = []SynologyErrorCode{
	{400, "No such account or incorrect password."},
	{401, "Disabled account."},
	{402, "Denied permission."},
	{403, "2-factor authentication code required."},
	{404, "Failed to authenticate 2-factor authentication code."},
	{406, "Enforce to authenticate with 2-factor authentication code."},
	{407, "Blocked IP source."},
	{408, "Expired password cannot change."},
	{409, "Expired password."},
	{410, "Password must be changed."},
	{100, "Unknown error."},
	{101, "No parameter of API, method or version."},
	{102, "The requested API does not exist."},
	{103, "The requested method does not exist."},
	{104, "The requested version does not support the functionality."},
	{105, "The logged in session does not have permission."},
	{106, "Session timeout."},
	{107, "Session interrupted by duplicated login."},
	{108, "Failed to upload the file."},
	{109, "The network connection is unstable or the system is busy."},
	{110, "The network connection is unstable or the system is busy."},
	{111, "The network connection is unstable or the system is busy."},
	{112, "Preserve for other purpose."},
	{113, "Preserve for other purpose."},
	{114, "Lost parameters for this API."},
	{115, "Not allowed to upload a file."},
	{116, "Not allowed to perform for a demo site."},
	{117, "The network connection is unstable or the system is busy."},
	{118, "The network connection is unstable or the system is busy."},
	{119, "Invalid session."},
	{150, "Request source IP does not match the login IP."},
}

func GetSynologyErrorDescription(code int) string {
	for _, errorCode := range SynologyErrorCodes {
		if errorCode.Code == code {
			return errorCode.Description
		}
	}
	return fmt.Sprintf("Unknown error code: %d", code)
}

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
type LogData struct {
	Descr           string `json:"descr"`
	Level           string `json:"level"`
	LogType         string `json:"logtype"`
	OriginalLogType string `json:"orginalLogType"`
	Time            string `json:"time"`
	Who             string `json:"who"`
}

type LogList struct {
	ErrorCount int       `json:"errorCount"`
	InfoCount  int       `json:"infoCount"`
	Items      []LogData `json:"items"`
}

type APIResult struct {
	API     string      `json:"api"`
	Data    interface{} `json:"data"`
	Success bool        `json:"success"`
	Error   *struct {
		Code int `json:"code"`
	} `json:"error,omitempty"`
	Method  string `json:"method"`
	Version int    `json:"version"`
}

type SynologyResponseData struct {
	HasFail bool        `json:"has_fail"`
	Result  []APIResult `json:"result"`
}

type SynologyResponse struct {
	Success bool                 `json:"success"`
	Data    SynologyResponseData `json:"data"`
}
