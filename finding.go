package main

// Not all implemented as of yet
// This single truth for Synaudit will be updated
var SecurityFindings = map[string]Finding{
	// Account & Authentication
	"ADMIN_ACCOUNT_ACTIVE": {
		Title:       "Default admin account is active",
		Description: "The default 'admin' account is enabled and can be targeted by attackers",
		Remediation: "Create a new admin user and disable the default 'admin' account",
	},
	"WEAK_PASSWORD_POLICY": {
		Title:       "Weak password policy",
		Description: "Password requirements are not strong enough to prevent brute force attacks",
		Remediation: "Enable password strength rules and set minimum length to 10+ characters",
	},
	"NO_2FA_ENFORCED_ADMIN": {
		Title:       "Two-factor authentication not enforced",
		Description: "2FA is not mandatory for admin accounts, reducing security",
		Remediation: "Enable and enforce 2FA for all users with admin privileges",
	},
	"AUTO_BLOCK_DISABLED": {
		Title:       "Auto-block is disabled",
		Description: "Failed login attempts are not being blocked automatically",
		Remediation: "Enable auto-block after 10 attempts within 5 minutes",
	},
	"GUEST_ACCOUNT_ENABLED": {
		Title:       "Guest account is enabled",
		Description: "Guest account provides unnecessary attack surface",
		Remediation: "Disable guest account if not specifically needed",
	},

	// Network & Firewall
	"FIREWALL_DISABLED": {
		Title:       "Firewall is disabled",
		Description: "The system firewall is currently turned off, leaving your NAS exposed",
		Remediation: "Enable firewall in Control Panel > Security > Firewall",
	},
	"DEFAULT_PORTS_EXPOSED": {
		Title:       "Using default service ports",
		Description: "Services running on default ports are easier targets for automated attacks",
		Remediation: "Change default ports for DSM (5000/5001), SSH (22), FTP (21)",
	},
	"QUICKCONNECT_ENABLED": {
		Title:       "QuickConnect is enabled",
		Description: "QuickConnect exposes your NAS to the internet through Synology's relay servers",
		Remediation: "Disable QuickConnect and use VPN for remote access instead",
	},
	"UPNP_ENABLED": {
		Title:       "UPnP is enabled",
		Description: "UPnP can automatically open ports without your knowledge",
		Remediation: "Disable UPnP in Control Panel > External Access > Router Configuration",
	},

	// Critical Ports
	"TELNET_ENABLED": {
		Title:       "Telnet service is running",
		Description: "Telnet transmits data unencrypted and should never be used",
		Remediation: "Disable Telnet immediately and use SSH instead",
	},
	"FTP_ENABLED": {
		Title:       "FTP service is running",
		Description: "FTP transmits credentials in plain text",
		Remediation: "Disable FTP and use SFTP or FTPS instead",
	},
	"SSH_DEFAULT_PORT": {
		Title:       "SSH running on default port",
		Description: "SSH on port 22 is heavily targeted by automated attacks",
		Remediation: "Change SSH port to a high random port (e.g., 22000-65000)",
	},
	"SMB1_ENABLED": {
		Title:       "SMB1 protocol is enabled",
		Description: "SMB1 is outdated and vulnerable to exploits like WannaCry",
		Remediation: "Disable SMB1 in Control Panel > File Services > SMB > Advanced",
	},
	"SMB_EXPOSED": {
		Title:       "SMB service exposed",
		Description: "SMB file sharing is accessible and may lack proper authentication",
		Remediation: "Ensure SMB has strong authentication and restrict access to trusted networks",
	},
	"RDP_EXPOSED": {
		Title:       "RDP service exposed",
		Description: "Remote Desktop Protocol is accessible and frequently targeted by attackers",
		Remediation: "Avoid exposing RDP to the internet, use VPN for remote access",
	},
	"DSM_HTTP_EXPOSED": {
		Title:       "DSM HTTP service exposed",
		Description: "Unencrypted DSM access allows credentials to be intercepted",
		Remediation: "Disable HTTP access and use HTTPS (port 5001) only",
	},
	"NETBIOS_EXPOSED": {
		Title:       "NetBIOS service exposed",
		Description: "Legacy Windows networking protocol with known security risks",
		Remediation: "Disable NetBIOS services if not required for legacy Windows compatibility",
	},
	"RPC_EXPOSED": {
		Title:       "RPC service exposed",
		Description: "Remote Procedure Call service is often exploited by attackers",
		Remediation: "Disable RPC service if not required or restrict to trusted networks",
	},
	"NFS_EXPOSED": {
		Title:       "NFS service is exposed",
		Description: "NFS shares might be accessible without proper authentication",
		Remediation: "Restrict NFS to specific IPs or disable if not needed",
	},

	// HTTPS & Certificates
	"HTTP_ENABLED": {
		Title:       "HTTP access is enabled",
		Description: "Unencrypted HTTP access allows credentials to be intercepted",
		Remediation: "Disable HTTP and force HTTPS only",
	},
	"SELF_SIGNED_CERT": {
		Title:       "Using self-signed certificate",
		Description: "Self-signed certificates are vulnerable to MITM attacks",
		Remediation: "Install a valid certificate from Let's Encrypt or trusted CA",
	},
	"OLD_TLS_VERSION": {
		Title:       "Outdated TLS version supported",
		Description: "TLS 1.0/1.1 have known vulnerabilities",
		Remediation: "Set minimum TLS version to 1.2 in Control Panel > Security",
	},

	// Updates & Patches
	"DSM_UPDATE_AVAILABLE": {
		Title:       "DSM update available",
		Description: "Running outdated DSM version with potential security vulnerabilities",
		Remediation: "Update DSM to the latest version in Control Panel > Update & Restore",
	},
	"AUTO_UPDATE_DISABLED": {
		Title:       "Automatic updates disabled",
		Description: "Security updates are not being installed automatically",
		Remediation: "Enable automatic installation of important updates",
	},

	// Backup & Protection
	"NO_BACKUP_CONFIGURED": {
		Title:       "No backup task configured",
		Description: "No automated backup protects against ransomware and data loss",
		Remediation: "Configure regular backups using Hyper Backup",
	},
	"SNAPSHOT_DISABLED": {
		Title:       "Btrfs snapshots not configured",
		Description: "Snapshots provide protection against ransomware and accidental deletion",
		Remediation: "Enable and schedule regular snapshots if using Btrfs",
	},
	"RECYCLE_BIN_DISABLED": {
		Title:       "Recycle bin is disabled",
		Description: "Deleted files cannot be recovered without recycle bin",
		Remediation: "Enable recycle bin for all shared folders",
	},

	// Advanced Threats
	"DOS_PROTECTION_DISABLED": {
		Title:       "DoS protection is disabled",
		Description: "System is vulnerable to denial of service attacks",
		Remediation: "Enable DoS protection in Control Panel > Security > Protection",
	},
	"NO_LOGIN_PORTAL": {
		Title:       "Custom login portal not configured",
		Description: "Default DSM login page reveals it's a Synology NAS",
		Remediation: "Setup custom login portal to hide NAS identity",
	},
	"DEFAULT_SHARED_FOLDERS": {
		Title:       "Default shared folders are accessible",
		Description: "Default folders like 'public' provide unnecessary exposure",
		Remediation: "Remove or restrict access to default shared folders",
	},

	// VPN & Remote Access
	"PPTP_VPN_ENABLED": {
		Title:       "PPTP VPN is enabled",
		Description: "PPTP is outdated and cryptographically broken",
		Remediation: "Disable PPTP and use OpenVPN or L2TP/IPSec instead",
	},
	"NO_VPN_FOR_ADMIN": {
		Title:       "Admin access allowed without VPN",
		Description: "Administrative access should require VPN connection",
		Remediation: "Restrict admin access to VPN connections only",
	},

	// Logging & Monitoring
	"LOG_CENTER_DISABLED": {
		Title:       "Log Center is not configured",
		Description: "Security events are not being logged for analysis",
		Remediation: "Enable Log Center and configure log retention",
	},
	"NO_EMAIL_ALERTS": {
		Title:       "Email notifications not configured",
		Description: "You won't be notified of critical security events",
		Remediation: "Configure email alerts for login attempts and system events",
	},

	// Application Security
	"UNNECESSARY_PACKAGES": {
		Title:       "Unnecessary packages installed",
		Description: "Each installed package increases attack surface",
		Remediation: "Remove unused packages from Package Center",
	},
	"DOCKER_PRIVILEGED": {
		Title:       "Docker containers running as privileged",
		Description: "Privileged containers can compromise the entire system",
		Remediation: "Review and restrict Docker container privileges",
	},
}
