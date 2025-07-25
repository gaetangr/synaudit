# Synaudit

[![Synaudit Go CI/CD](https://github.com/gaetangr/synaudit/actions/workflows/go.yml/badge.svg)](https://github.com/gaetangr/synaudit/actions/workflows/go.yml)


A security auditing tool for Synology NAS systems written in Go.

![Synaudit Example](assets/media/synaudit_cli_example.gif)

## Why Synaudit?

While I love my Synology NAS, the DSM interface can be slow and cumbersome for quick security audits. I found myself constantly jumping between multiple services and applications just to get a comprehensive understanding of my system's health and security status.

## Features

### Security Checks

**User & Authentication**
- Admin account status
- 2FA enforcement for admin accounts
- Password policy analysis (length, complexity, history, expiration)

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

### Commands

- `login` - Authenticate with your Synology NAS
- `audit` - Run comprehensive security audit  
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


## Security Notes

- All API calls are made locally to your NAS
- No external servers are contacted
- Admin credentials are required to perform security checks
- No telemetry or analytics

## Contributing

Contributions are welcome. When submitting PRs:

1. Check existing issues first
2. Follow Go conventions
3. Include tests for new checks
4. Update documentation as needed
5. Test on different DSM versions if possible

### Development

This project uses modern development practices including AI-assisted development for productivity:

```bash
# Install dependencies
go mod download

# Run tests
go test ./tests/...

# Build
go build -o synaudit .
```

## Planned Features

- Certificate validation
- Update status checking
- Backup configuration analysis
- Share permission auditing
- Report export (JSON/HTML/PDF)
- Scheduled audits

## Disclaimer

This tool is for auditing your own Synology NAS systems only. Ensure you have proper authorization before running security audits. The authors are not responsible for misuse or damage.

## AI Assistance Disclaimer

This project was developed with AI assistance for code generation, unit testing, and refactoring. However, **every line of code has been reviewed, validated, and approved by human developers**. The AI was used as a productivity tool to:

- Create unit tests
- Assist with code refactoring and organization
- Provide documentation improvements

All security-critical logic, API implementations, and business decisions were made by human developers. The final codebase reflects human judgment, testing, and validation.
