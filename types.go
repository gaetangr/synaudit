package main

import "time"

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

type Finding struct {
	Title       string
	Description string
	Remediation string
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

type PortInfo struct {
	Port        int
	Service     string
	Protocol    string
	Severity    string
	Description string
}
type PortStatus struct {
	Port        int
	Service     string
	IsOpen      bool
	Description string
}

type NetworkFinding struct {
	Finding
	Ports []PortStatus
}

var CriticalPorts = []PortInfo{
	{23, "Telnet", "tcp", "critical", "Unencrypted remote access - MUST be disabled"},
	{111, "RPC", "tcp", "critical", "Remote Procedure Call - Often exploited"},
	{137, "NetBIOS", "tcp", "high", "Legacy Windows networking - Security risk"},
	{138, "NetBIOS", "udp", "high", "Legacy Windows networking - Security risk"},
	{139, "NetBIOS", "tcp", "high", "Legacy Windows networking - Security risk"},
	{445, "SMB", "tcp", "high", "File sharing - Ensure proper authentication"},
}

var CommonPorts = []PortInfo{
	// Management
	{5000, "DSM HTTP", "tcp", "medium", "Unencrypted DSM access"},
	{5001, "DSM HTTPS", "tcp", "low", "Encrypted DSM access - Preferred"},

	// Remote Access
	{22, "SSH", "tcp", "medium", "Secure Shell - OK if properly configured"},
	{3389, "RDP", "tcp", "high", "Remote Desktop - Avoid exposing to internet"},

	// File Services
	{21, "FTP", "tcp", "high", "Unencrypted file transfer"},
	{990, "FTPS", "tcp", "medium", "Encrypted FTP - Better than FTP"},
	{873, "rsync", "tcp", "medium", "File synchronization"},

	// Web Services
	{80, "HTTP", "tcp", "medium", "Unencrypted web traffic"},
	{443, "HTTPS", "tcp", "low", "Encrypted web traffic - Preferred"},
	{8080, "HTTP Alt", "tcp", "medium", "Alternative HTTP port"},

	// Database
	{3306, "MySQL/MariaDB", "tcp", "high", "Database - Should not be exposed"},
	{5432, "PostgreSQL", "tcp", "high", "Database - Should not be exposed"},
}

var OptionalPorts = []PortInfo{
	// Multimedia
	{1900, "UPnP", "udp", "medium", "Universal Plug and Play"},
	{5353, "Bonjour", "udp", "low", "Service discovery"},
	{9999, "Surveillance Station", "tcp", "low", "Camera management"},

	// VPN
	{1723, "PPTP", "tcp", "high", "Outdated VPN protocol"},
	{1701, "L2TP", "udp", "medium", "VPN protocol"},
	{500, "IPSec/IKEv2", "udp", "low", "Secure VPN protocol"},
	{4500, "IPSec NAT", "udp", "low", "VPN NAT traversal"},
	{1194, "OpenVPN", "udp", "low", "Secure VPN protocol"},

	// Other Services
	{25, "SMTP", "tcp", "medium", "Email sending"},
	{110, "POP3", "tcp", "high", "Unencrypted email"},
	{143, "IMAP", "tcp", "high", "Unencrypted email"},
	{993, "IMAPS", "tcp", "medium", "Encrypted email"},
	{995, "POP3S", "tcp", "medium", "Encrypted email"},
}
