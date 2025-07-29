# Synaudit - Security Auditing Tool for Synology NAS

[![Synaudit Go CI/CD](https://github.com/gaetangr/synaudit/actions/workflows/go.yml/badge.svg)](https://github.com/gaetangr/synaudit/actions/workflows/go.yml)

A security auditing tool for Synology NAS systems written in Go.

![Synaudit Example](assets/media/synaudit_cli_example.gif)

## Why Synaudit?

While I love my Synology NAS, the DSM interface can be slow and cumbersome for quick security audits. I found myself constantly jumping between multiple services and applications just to get a comprehensive understanding of my system's health and security status.

## Disclaimer 

To perform security audits, you need admin credentials for your Synology NAS. We are using the official Synology authentication API to securely log in and perform checks, you can check the [API documentation](https://kb.synology.com/fr-fr/DG/DSM_Login_Web_API_Guide/2) for more details.

All API calls are made locally to your NAS, you can check the [source code](https://github.com/gaetangr/synaudit/blob/main/cmd/auth.go) for more details. No external servers are contacted, and no telemetry or analytics are collected.

Password is not stored in the tool nor your terminal history.

## Features

### Security Checks

**User & Authentication**
- Admin account status
- 2FA enforcement for admin accounts
- Password policy analysis (length, complexity, history, expiration)
- Detection of suspect login attempts (multiple failed logins, brute force)

**Network & Firewall**
- Firewall status
- Open port scanning
- Service exposure (SSH, Telnet, FTP, SMB, RDP, HTTP/HTTPS)

**Services**
- QuickConnect status
- Terminal service configuration (SSH/Telnet)
- FTP encryption settings
- Auto-block (brute force protection)

**Packages**
- Identifies potentially risky installed packages
- Flags development tools in production
- Detects obsolete software versions

See [Planned Features](#planned-features) for future improvements and features.

## Installation

### Prerequisites
- Synology NAS with DSM 6.0+
- Admin account credentials
- Go 1.19+ (if building from source)

### Build from source
```bash
git clone https://github.com/gaetangr/synaudit.git
cd synaudit
go build -o synaudit .
```

## Usage

### Quick Start

1. **Login to your NAS:**
```bash
./synaudit login -u admin -H https://your-synology-ip:5001
```

2. **Run security audit:**
```bash
./synaudit audit
```

3. **Logout when done:**
```bash
./synaudit logout
```

### Authentication with Two-Factor Authentication (2FA)

If your Synology NAS has 2FA enabled, Synaudit will automatically detect this and prompt you for your authentication code:

```bash
./synaudit login -u admin -H https://your-synology-ip:5001
Enter password: [hidden]
Logging in with user: admin to host: your-synology-ip:5001

🔐 Two-factor authentication required
Enter your 2FA code (6 digits): [hidden]
Authenticating with 2FA code...
✅ Login successful!
📁 Session saved successfully
You can now use other commands without logging in again.
```

**Supported 2FA Methods:**
- Google Authenticator
- Authy
- Any TOTP-compatible authenticator app
- SMS (if configured in DSM)

**2FA Error Handling:**
- **Code 403**: 2FA code required - You'll be prompted to enter your 2FA code
- **Code 404**: Invalid 2FA code - Check your authenticator app and try again
- **Code 406**: 2FA enforced - 2FA is mandatory for your account

### Commands

- `login` - Authenticate with your Synology NAS (supports 2FA)
- `audit` - Run local security audit 
- `logout` - End session and clear credentials

### Flags

- `-u, --user` - Username (required for login)
- `-H, --host` - NAS host URL (required for login)
- `-h, --help` - Show help

### Example output
```
SECURITY AUDIT REPORT
Checked at: 2025-07-24 15:30:45
Total issues: 3

[1] SSH running on default port
    WARNING: SSH on port 22 is heavily targeted by automated attacks
    RECOMMENDATION: Change SSH port to a high random port (e.g., 22000-65000)

[2] Password minimum length too short
    WARNING: Current minimum password length is 8 characters
    RECOMMENDATION: Increase minimum password length to 10+ characters

[3] QuickConnect is enabled
    WARNING: QuickConnect exposes your NAS to the internet
    RECOMMENDATION: Disable QuickConnect and use VPN for remote access
```

## Technical Details

Synaudit uses the Synology Web API to gather system information. Since official documentation is limited, many endpoints were discovered through reverse engineering the DSM interface. The tool uses compound requests with session cookies for efficient data collection.

### Security Considerations

- **2FA Support**: Full support for TOTP-based 2FA authentication
- **Session Management**: Secure session storage with automatic expiration
- **Local-Only**: All communications happen directly between your computer and your NAS
- **No Data Collection**: No telemetry, analytics, or external data transmission

## Troubleshooting

### Common Authentication Issues

1. **"2-factor authentication code required"**
   - Your NAS has 2FA enabled. Enter your 6-digit code from your authenticator app when prompted.

2. **"Failed to authenticate 2-factor authentication code"**
   - Double-check your authenticator app
   - Ensure your system time is synchronized
   - Try generating a new code

3. **"Session expired"**
   - Run `./synaudit login` again to create a new session

4. **Connection Issues**
   - Verify your NAS IP address and port
   - Check if HTTPS is enabled (use port 5001)
   - Ensure your NAS is accessible from your network

## Planned Features

- Certificate validation
- Share permission auditing
- Report export (JSON/HTML/PDF)
- Scheduled audits
- Known vulnerabilities (CVE) including recent Synology vulnerabilities such as CVE-2024-10443, CVE-2024-29241, CVE‑2025‑4679
- Enhanced 2FA support (hardware keys, backup codes)
- And much more...

## AI Assistance Disclaimer

This project was developed with AI assistance for code generation, unit testing, and refactoring. However, **every line of code has been reviewed, validated, and approved by human developers**. The AI was used as a productivity tool to:

- Create unit tests
- Assist with code refactoring and organization
- Provide documentation improvements

All security-critical logic, API implementations, and business decisions were made by human developers. The final codebase reflects human judgment, testing, and validation.