# Synaudit

[![Synaudit Go CI/CD](https://github.com/gaetangr/synaudit/actions/workflows/go.yml/badge.svg)](https://github.com/gaetangr/synaudit/actions/workflows/go.yml)

A fast and user-friendly security auditing tool for Synology NAS systems built in Go.

## Why Synaudit?

While I love my Synology NAS, the DSM interface can be slow and cumbersome for quick security audits. I found myself constantly jumping between multiple services and applications just to get a comprehensive understanding of my system's health and security status.

Although Synology provides some built-in tools, none offer the speed or comprehensive bundling of all the security checks I needed. That's why I created Synaudit.

## Performance Comparison

**Synaudit vs DSM Interface:**
- **Speed**: Complete audit in **under 5 seconds** vs 5-10+ minutes manually checking DSM
- **Comprehensiveness**: 40+ automated checks vs scattered manual verification
- **Usability**: Single command vs navigating multiple DSM menus and services
- **Reliability**: Consistent results vs potential human oversight
- **Actionable**: Clear recommendations vs generic status information

The DSM graphical interface, while functional, becomes inefficient when you need regular security assessments. Synaudit consolidates all critical security checks into one fast, automated tool.

## Community-Driven Development

Synaudit is built **by the community, for the community**. As a Synology user myself, I understand the real-world security challenges we face. This project thrives on contributions from:

- **Synology Experts**: System administrators and security professionals
- **Home Users**: Enthusiasts who want to secure their personal NAS
- **Developers**: Contributors improving code quality and adding features
- **Security Researchers**: Experts identifying new vulnerabilities and checks

**How You Can Contribute:**
- **Suggest New Security Checks**: Share security best practices from your experience
- **Report Issues**: Help identify bugs or compatibility problems
- **Improve Recommendations**: Enhance our security advice and solutions
- **Documentation**: Help make Synaudit more accessible to all users
- **Code Contributions**: Add features, optimize performance, or fix bugs


### Key Benefits:
- **Lightning Fast**: Complete security audit in under 7 seconds vs minutes with DSM interface
- **User-friendly**: Designed for both technical and non-technical users
- **Comprehensive**: All security checks in one place with actionable recommendations
- **Community-driven**: Built by and for the Synology community
- **No dependencies**: Single binary, no installation required
- **Scalable**: The code architecture is easy to expand for future checks

## Features

### Current Security Checks

#### User & Authentication
- **Admin Account Status**: Verifies if the default admin account is properly disabled
- **2FA Enforcement**: Checks if two-factor authentication is enforced for admin accounts
- **Password Policy**: Comprehensive analysis of password strength requirements
  - Minimum length enforcement
  - Mixed case requirements
  - Numeric character requirements
  - Special character requirements
  - Username exclusion in passwords
  - Common password blocking
  - Password history enforcement
  - Password expiration policies

#### Network & Firewall
- **Firewall Status**: Verifies if the system firewall is enabled
- **Port Security**: Scans for open ports and identifies security risks
  - SSH on default port (22)
  - Telnet service detection (critical risk)
  - FTP service detection (unencrypted)
  - SMB/NetBIOS exposure
  - RDP exposure
  - DSM HTTP vs HTTPS usage
  - RPC service exposure

#### Remote Access & Services
- **QuickConnect**: Detects if QuickConnect service is enabled (security risk)
- **Terminal Services**: Checks SSH and Telnet configuration
  - SSH default port usage
  - Telnet enablement (critical security issue)
- **FTP Security**: Analyzes FTP service configuration
  - Unencrypted FTP detection
  - TLS/SSL encryption status
- **Auto-Block Policy**: Verifies brute force protection settings

#### Package Security
- **Installed Packages Analysis**: Reviews installed packages for security risks
  - Development tools in production (Node.js, PHP, Perl)
  - Obsolete packages (Python2, old PHP versions)
  - High-risk packages (ContainerManager, DownloadStation)
  - Unnecessary services identification

### Configuration
- **Environment Variables**: Uses `.env` file for easy configuration
- **Comprehensive API Coverage**: Utilizes 40+ Synology API endpoints

## Quick Start

### 1. Setup Configuration
Create a `.env` file in the project directory:
```bash
cp .env.example .env
```

Edit the `.env` file with your Synology NAS details:
```env
SYNOLOGY_HOST=https://your-synology-ip:port/webapi/entry.cgi
```

### 2. Run the Audit
```bash
go run .
```

Or build and run:
```bash
go build .
./synaudit
```

### Current Features
- **Admin Account Security**: Default admin account status verification
- **2FA Enforcement**: Two-factor authentication policy checks
- **Password Policy**: Comprehensive password strength analysis
- **Firewall Status**: System firewall configuration verification
- **Network Security**: Port scanning and service exposure detection
- **Terminal Services**: SSH/Telnet security configuration
- **FTP Security**: File transfer protocol security analysis
- **QuickConnect**: Remote access service security assessment
- **Package Security**: Installed package risk analysis
- **Auto-Block**: Brute force protection verification
- **Comprehensive API**: 40+ Synology API endpoints coverage

### Planned Features
- **Certificate Management**: SSL/TLS certificate validation
- **Update Management**: DSM and package update status
- **Backup Verification**: Backup task configuration analysis
- **Share Security**: Shared folder permission auditing
- **Log Analysis**: Security event log monitoring
- **VPN Configuration**: VPN service security assessment
- **Export Reports**: JSON, HTML, and PDF report generation
- **Scheduled Audits**: Automated recurring security checks

## Requirements

- Synology NAS with DSM 6.0 or higher
- Admin privileges on your Synology NAS
- Go 1.19+ (for building from source)

## Installation

### Option 1: Download Pre-built Binary
```bash
# Coming soon
wget https://github.com/gaetangr/synaudit/releases/latest/synaudit
chmod +x synaudit
```

### Option 2: Build from Source
```bash
git clone https://github.com/gaetangr/synaudit.git
cd synaudit
go build -o synaudit .
```

## Usage

### Basic Usage
```bash
# Run security audit
./synaudit

# Example output:
SECURITY AUDIT REPORT
Checked at: 2025-07-24 15:30:45
Total issues: 3

[1] SSH running on default port
    WARNING: SSH on port 22 is heavily targeted by automated attacks
    RECOMMENDATION: Change SSH port to a high random port (e.g., 22000-65000)

[2] Password minimum length too short
    WARNING: Current minimum password length is 8 characters, should be at least 10
    RECOMMENDATION: Increase minimum password length to 10+ characters

[3] QuickConnect is enabled
    WARNING: QuickConnect exposes your NAS to the internet through Synology's relay servers
    RECOMMENDATION: Disable QuickConnect and use VPN for remote access instead
```

## Security & Privacy

**Your data is safe:**
- All network calls are made locally to your NAS IP
- No data is transmitted to external servers
- No analytics or telemetry
- 100% open source and auditable

**Note**: To perform security checks, Synaudit requires a user with admin privileges on your Synology NAS.

## Technical Details

### The Synology API

Synology provides an API for various system operations, but official documentation is limited. The available guide ([Synology Web API Guide](https://kb.synology.com/en-us/DSM/DG/DSM_Login_Web_API_Guide/2)) provides basic insights.

Through reverse engineering the DSM interface, I discovered that using the compound request method with proper session cookies allows for much faster and more efficient API consumption.



### Project Structure
```
synaudit/
├── main.go              # Entry point and main execution flow
├── audit.go             # Security audit logic and finding generation
├── api.go               # Synology API communication and data fetching
├── api_endpoints.go     # API endpoint definitions and payload building
├── network.go           # Network scanning and port analysis
├── types.go             # Data structures and type definitions
├── finding.go           # Security findings database and descriptions
├── utils.go             # Utility functions and helpers
├── .env.example         # Environment configuration template
└── README.md            # This file
```

## Contributing

Synaudit is a **community-driven project** that welcomes contributions from Synology users, security experts, and developers of all skill levels.

### Ways to Contribute

**Security Expertise**
- Suggest new security checks based on real-world threats
- Improve existing check logic and detection accuracy
- Share Synology-specific security best practices
- Help identify false positives and edge cases

**Development**
- Add new features and security checks
- Optimize performance and code quality
- Improve error handling and user experience
- Enhance API coverage and data parsing

**Documentation & Community**
- Improve documentation and user guides
- Create tutorials and best practice guides
- Help with translations and accessibility
- Assist other users in discussions and issues

### Development Setup
```bash
# Clone the repo
git clone https://github.com/gaetangr/synaudit.git
cd synaudit

# Install dependencies
go mod download

# Run tests
go test ./...

# Build
go build -o synaudit .
```

### Contribution Guidelines
1. **Check existing issues** before creating new ones
2. **Follow Go conventions** and maintain code quality
3. **Include tests** for new security checks
4. **Update documentation** for new features
5. **Test thoroughly** on different DSM versions when possible

**Together, we're making Synology NAS security accessible to everyone!**
## Disclaimer

This tool is provided as-is for security auditing of your own Synology NAS systems. Always ensure you have proper authorization before running security audits. The authors are not responsible for any misuse or damage caused by this tool.

