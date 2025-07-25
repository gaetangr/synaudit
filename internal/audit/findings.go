package audit

import "github.com/gaetangr/synaudit/internal/api"

var SecurityFindings = map[string]api.Finding{
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
