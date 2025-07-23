# Synaudit

[![Synaudit Go CI/CD](https://github.com/gaetangr/synaudit/actions/workflows/go.yml/badge.svg)](https://github.com/gaetangr/synaudit/actions/workflows/go.yml)

🔐 A fast and user-friendly security auditing tool for Synology NAS systems built in Go.

## 🎯 Why Synaudit?

While I love my Synology NAS, the DSM interface can be slow and cumbersome for quick security audits. I found myself constantly jumping between multiple services and applications just to get a comprehensive understanding of my system's health and security status.

Although Synology provides some built-in tools, none offer the speed or comprehensive bundling of all the security checks I needed. That's why I created Synaudit.

### Key Benefits:
- **Fast**: Built with Go for lightning-fast performance
- **User-friendly**: Designed for both technical and non-technical users
- **Comprehensive**: All security checks in one place
- **Community-driven**: Implements best practices discussed in the Synology community
- **No dependencies**: Single binary, no installation required
- **Scalable**: The code architecture is easy to expand for futur checks

## 🚀 Features

### Current Security Checks
- **Admin Account Status**: Verifies if the admin account is properly disabled
- **User Management**: Lists and analyzes local user accounts

### Configuration
- **Environment Variables**: Uses `.env` file for easy configuration
- **Secure Connection**: Supports HTTPS with custom certificates

## ⚡ Quick Start

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
- ✅ ....

### Planned Features
- 🔜 Monitor open ports (SSH, Telnet, Mail, etc.)
- 🔜 Check firewall rules and configuration
- 🔜 Monitor CPU and system resource usage
- 🔜 Verify SSL/TLS configurations
- 🔜 Check for available DSM updates
- 🔜 Detect brute force vulnerabilities
- 🔜 Export reports (JSON, HTML)

## 📋 Requirements

- Synology NAS with DSM 6.0 or higher
- Admin privileges on your Synology NAS
- Go 1.19+ (for building from source)

## 🛠️ Installation

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

## 🔧 Usage

### Basic Usage
```bash
# Run with default settings
./synaudit # WORK IN PROGRESS, NOT YET IMPLEMENTED
```

## 🔒 Security & Privacy

**Your data is safe:**
- All network calls are made locally to your NAS IP
- No data is transmitted to external servers
- No analytics or telemetry
- 100% open source and auditable

**Note**: To perform security checks, Synaudit requires a user with admin privileges on your Synology NAS.

## 🏗️ Technical Details

### The Synology API

Synology provides an API for various system operations, but official documentation is limited. The available guide ([Synology Web API Guide](https://kb.synology.com/en-us/DSM/DG/DSM_Login_Web_API_Guide/2)) provides basic insights.

Through reverse engineering the DSM interface, I discovered that using the compound request method with proper session cookies allows for much faster and more efficient API consumption.



### Project Structure
```
synaudit/
├── main.go          # Entry point
├── audit.go         # Security audit logic
├── synology.go      # API communication
├── types.go         # Data structures
└── README.md        # This file
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

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
## ⚠️ Disclaimer

This tool is provided as-is for security auditing of your own Synology NAS systems. Always ensure you have proper authorization before running security audits. The authors are not responsible for any misuse or damage caused by this tool.

