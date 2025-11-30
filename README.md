# HTB Automated Flag Reveal System

A comprehensive automated penetration testing tool for Hack The Box (HTB) machines. This system performs network scanning, vulnerability detection, and automated exploitation attempts using various Kali Linux tools.

## 🎯 Features

- **Automated Network Scanning**: Uses nmap for port discovery and service enumeration
- **Vulnerability Detection**: Identifies common security weaknesses across multiple protocols
- **Automated Exploitation**: Attempts exploitation based on detected vulnerabilities
- **Flag Extraction**: Automatically extracts and reports flags from various sources
- **Comprehensive Logging**: Detailed logging of all activities
- **JSON Output**: Structured results for further analysis

## 🔧 Supported Services & Attacks

### Network Scanning
- Quick port scan (top 100 ports)
- Detailed version detection and OS fingerprinting
- NSE script scanning for vulnerabilities

### Vulnerability Detection & Exploitation

#### FTP (Port 21)
- Anonymous login detection
- File enumeration and download
- Flag extraction from accessible files

#### SSH (Port 22)
- Version detection
- Common credential testing
- Flag retrieval attempts

#### Web Services (HTTP/HTTPS)
- Nikto vulnerability scanning
- Directory bruteforcing with gobuster
- Common file location testing
- Git repository exposure checks
- Environment file discovery

#### SMB (Ports 139, 445)
- SMB vulnerability scanning (EternalBlue, etc.)
- Share enumeration
- Anonymous access testing
- File extraction

#### Database Services
- MySQL (Port 3306)
- PostgreSQL (Port 5432)

## 📋 Prerequisites

### Required Tools

The following tools must be installed on your Kali Linux system:

```bash
sudo apt-get update
sudo apt-get install -y \
    nmap \
    nikto \
    gobuster \
    smbclient \
    curl \
    sshpass \
    lftp \
    python3 \
    python3-pip
```

**Note:** The script will automatically detect missing tools and prompt you to install them when you run it for the first time.

### Python Requirements

Python 3.7 or higher is required. The script uses only standard library modules.

## 🚀 Installation

1. Clone or download the script:
```bash
cd /Users/ahmednaseem/Documents/Codex_Dev/KaliHTB
chmod +x htb_auto_pwn.py
```

2. On first run, the script will check for required tools and offer to install any missing ones automatically.

## 💻 Usage

### Basic Usage

```bash
# Scan a target IP (will prompt to install missing tools if needed)
python3 htb_auto_pwn.py -t 10.10.10.100

# Scan with custom output file
python3 htb_auto_pwn.py -t 10.10.10.100 -o my_results.json

# Verbose mode for detailed logging
python3 htb_auto_pwn.py -t 10.10.10.100 -v
```

### Automatic Tool Installation

When you run the script, it will:
1. Check for all required tools (nmap, nikto, gobuster, etc.)
2. If any tools are missing, prompt you to install them
3. Automatically install missing tools with your confirmation
4. Verify successful installation

Example interaction:
```bash
$ python3 htb_auto_pwn.py -t 10.10.10.100
[WARNING] Missing tools detected: nikto, gobuster
[WARNING] Some functionality may be limited without these tools.

Would you like to install missing tools now? (y/n): y
[INFO] Installing missing tools...
[INFO] Updating package list...
[INFO] Installing: nikto, gobuster
[INFO] ✓ Successfully installed missing tools!
```

### Command Line Options

```
-t, --target    Target IP address or hostname (required)
-o, --output    Output file for results in JSON format
-v, --verbose   Enable verbose output for debugging
```

## 📊 Output

### Console Output

The tool provides real-time colored output showing:
- Scanning progress
- Discovered ports and services
- Detected vulnerabilities
- Exploitation attempts
- Found flags

### JSON Output

Results are saved in JSON format containing:
```json
{
  "target": "10.10.10.100",
  "timestamp": "2025-11-30T...",
  "scan_results": {
    "ports": [...],
    "os": "...",
    "vulnerabilities": [...]
  },
  "vulnerabilities": [...],
  "flags": [
    {
      "flag": "HTB{...}",
      "source": "...",
      "timestamp": "..."
    }
  ]
}
```

### Log Files

Detailed logs are saved to `htb_auto_YYYYMMDD_HHMMSS.log` including:
- All executed commands
- Full tool outputs
- Error messages
- Debugging information

## 🔍 How It Works

### Phase 1: Network Scanning
1. **Quick Scan**: Fast scan of top 100 ports to identify open services
2. **Detailed Scan**: Deep scan with version detection, OS fingerprinting, and vulnerability scripts

### Phase 2: Vulnerability Detection
1. Parse nmap results for known vulnerabilities
2. Check each service for common weaknesses:
   - Default credentials
   - Anonymous access
   - Version-specific vulnerabilities
   - Misconfigurations

### Phase 3: Exploitation
1. For each detected vulnerability, attempt appropriate exploitation
2. Extract flags using multiple patterns:
   - MD5-like hashes (32 hex chars)
   - SHA256-like hashes (64 hex chars)
   - HTB{...} format
   - flag{...} format

## 🛡️ Security Considerations

**⚠️ WARNING**: This tool is designed for authorized penetration testing only.

- Only use on systems you have explicit permission to test
- HTB provides authorized targets for practice
- Unauthorized use may violate computer fraud laws
- Always follow responsible disclosure practices

## 🎯 Flag Detection Patterns

The tool searches for flags matching these patterns:
- `[a-f0-9]{32}` - MD5-style hashes
- `[a-f0-9]{64}` - SHA256-style hashes
- `HTB{...}` - HTB flag format
- `flag{...}` - Generic flag format

## 🔧 Customization

### Adding New Vulnerability Checks

Edit the `VulnerabilityDetector` class to add custom checks:

```python
def _check_custom_service(self, port: int):
    """Check for custom service vulnerabilities"""
    logger.info(f"Checking custom service on port {port}")
    # Your custom logic here
    self.vulnerabilities.append({
        'type': 'custom',
        'port': port,
        'severity': 'medium',
        'description': 'Custom vulnerability'
    })
```

### Adding New Exploitation Methods

Edit the `Exploiter` class to add custom exploitation:

```python
def _exploit_custom(self, port: int):
    """Exploit custom vulnerability"""
    logger.info(f"Attempting custom exploitation on port {port}")
    # Your exploitation logic here
    self._extract_flags_from_output(output, 'CUSTOM')
```

## 📝 Example Session

```bash
$ python3 htb_auto_pwn.py -t 10.10.10.100

╔══════════════════════════════════════════════╗
║   HTB Automated Flag Reveal System          ║
║   Target: 10.10.10.100                      ║
╚══════════════════════════════════════════════╝

[PHASE 1] Network Scanning
[INFO] Starting quick port scan on 10.10.10.100
[INFO] Open ports found: [21, 22, 80]
[INFO] Running detailed scan on ports: 21,22,80

[PHASE 2] Vulnerability Detection
[INFO] Analyzing for vulnerabilities...
[INFO] Found 3 potential vulnerabilities
  - ftp_anonymous on port 21 (Severity: high)
  - ssh on port 22 (Severity: medium)
  - web on port 80 (Severity: medium)

[PHASE 3] Exploitation
[INFO] Starting exploitation phase...
[INFO] [FLAG FOUND] FTP: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6

╔══════════════════════════════════════════════╗
║             EXECUTION SUMMARY                ║
╚══════════════════════════════════════════════╝

Target: 10.10.10.100
Open Ports: 3
Vulnerabilities: 3
Flags Found: 1

FLAGS DISCOVERED:
  ✓ a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6 (from FTP)

Results saved to: htb_results_20251130_123456.json
```

## 🐛 Troubleshooting

### Common Issues

**No ports found:**
- Check target is reachable: `ping <target>`
- Verify firewall rules
- Try with sudo: `sudo python3 htb_auto_pwn.py -t <target>`

**Missing tools:**
- The script will automatically detect and offer to install missing tools
- If automatic installation fails, install manually: `sudo apt-get install <tool-name>`
- Update package list: `sudo apt-get update`
- You can continue with limited functionality if some tools are missing

**Timeouts:**
- Increase timeout values in the script
- Check network connectivity
- Target may be rate-limiting

**No flags found:**
- Some machines require manual exploitation
- Check log files for clues
- Review JSON output for detailed scan results

## 📚 Resources

- [Hack The Box](https://www.hackthebox.com/)
- [Nmap Documentation](https://nmap.org/docs.html)
- [Kali Linux Tools](https://www.kali.org/tools/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## 📄 License

This tool is provided for educational purposes only. Use responsibly and only on authorized systems.

## 🤝 Contributing

Feel free to submit issues, suggestions, or improvements!

## ⚠️ Disclaimer

This tool is for authorized security testing only. The author is not responsible for misuse or damage caused by this tool. Always obtain proper authorization before testing any systems.
