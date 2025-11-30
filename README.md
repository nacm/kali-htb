# HTB Automated Flag Reveal System

A comprehensive automated penetration testing tool for Hack The Box (HTB) machines. This system performs network scanning, vulnerability detection, and automated exploitation attempts using various Kali Linux tools.

## 🎯 Features

- **AI-Powered by Default**: OpenAI GPT-4 integration for intelligent analysis and dynamic decision-making
- **Automated Network Scanning**: Uses nmap for port discovery and service enumeration
- **Dynamic Phase Execution**: All phases adapt based on AI recommendations
- **Vulnerability Detection**: Identifies common security weaknesses across multiple protocols
- **Dynamic Scanning Strategy**: Adjusts scan approach in real-time based on AI analysis
- **Automated Exploitation**: Attempts exploitation based on AI-suggested strategies
- **Flag Extraction**: Automatically extracts and reports flags from various sources
- **Comprehensive Logging**: Detailed logging of all activities including AI interactions
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

Python 3.7 or higher is required.

**AI-Powered Analysis (Default Mode)**

The tool runs in AI mode by default for best results. To enable AI features:

**Quick Setup (Recommended):**
```bash
# Run the automated setup script
./setup_ai.sh
```

**Manual Setup:**
```bash
# Install required libraries
pip install openai python-dotenv

# Create .env file with your API key
cp .env.example .env
nano .env  # Edit and add your actual API key
```

**Alternative: Environment Variable**
```bash
# Set your OpenAI API key
export OPENAI_API_KEY='your-api-key-here'

# Or add to your ~/.bashrc or ~/.zshrc for persistence
echo 'export OPENAI_API_KEY="your-api-key-here"' >> ~/.bashrc
```

Get your API key from: https://platform.openai.com/api-keys

**Note:** 
- The `.env` file is automatically loaded and is included in `.gitignore` for security
- If AI setup is incomplete, the tool falls back to standard mode automatically
- Use `--no-ai` flag to explicitly disable AI mode

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
# Scan a target IP (AI mode by default)
python3 htb_auto_pwn.py -t 10.10.10.100

# Scan with custom output file
python3 htb_auto_pwn.py -t 10.10.10.100 -o my_results.json

# Verbose mode for detailed logging
python3 htb_auto_pwn.py -t 10.10.10.100 -v

# Disable AI mode (use standard scanning only)
python3 htb_auto_pwn.py -t 10.10.10.100 --no-ai

# Combine options
python3 htb_auto_pwn.py -t 10.10.10.100 -v -o results.json
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
--no-ai         Disable AI-powered analysis (AI is enabled by default)
```

### AI-Powered Features (Default Mode)

The tool uses OpenAI's GPT-4 by default for:

1. **Analyze Scan Results**: Intelligently interprets nmap output to identify promising attack vectors
2. **Dynamic Scanning**: Performs targeted scans on priority services based on AI recommendations
3. **Vulnerability Assessment**: Identifies potential CVEs and vulnerability types from service versions
4. **Exploitation Strategy**: Suggests optimal exploitation order and specific tools to use
5. **Attack Vector Prioritization**: Ranks ports and services by likelihood of successful exploitation
6. **Detailed Exploit Suggestions**: For each vulnerability, AI provides:
   - Specific exploit names and types (Metasploit, manual, searchsploit)
   - Exact commands to run
   - CVE numbers where applicable
   - Success probability estimates
   - Step-by-step manual exploitation guides
   - Recommended tools and cautions

**AI Output in Terminal:**
- All AI prompts are displayed before sending to OpenAI
- Full AI responses are shown in the terminal and logged
- Formatted summaries with color-coded sections
- Exploit suggestions displayed for each found vulnerability

Example AI insights:
- \"SSH version appears outdated, recommend checking for CVE-2018-15473\"
- \"Web server running Apache 2.4.29 - check for path traversal vulnerabilities\"
- \"Priority ports: 445 (SMB) has highest chance of exploitation\"
- \"Recommended: Run enum4linux on SMB, then try EternalBlue exploit\"

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
  "ai_analysis": {
    "attack_vectors": [...],
    "priority_ports": [...],
    "vulnerabilities": [...],
    "strategy": "aggressive/targeted/stealth",
    "reasoning": "..."
  },
  "vulnerabilities": [...],
  "exploitation_strategy": {
    "exploitation_order": [...],
    "commands": [...],
    "notes": [...]
  },
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
1. **Quick Scan**: Fast scan of top 100 ports to identify open services (1-2 minutes)
   - Shows progress updates during scanning
   - Provides connectivity diagnostics if scan fails
2. **Detailed Scan**: Deep scan with version detection, OS fingerprinting, and vulnerability scripts (5-10 minutes)
   - Real-time progress indicators
   - Automatic partial result parsing if timeout occurs
   - Detailed error messages with actionable suggestions

### Phase 1.5: AI Analysis (Optional)
1. **Intelligent Analysis**: AI examines all discovered services and versions
2. **Attack Vector Identification**: Identifies most promising exploitation paths
3. **Dynamic Targeted Scanning**: Runs additional focused scans on priority services
4. **Vulnerability Mapping**: Correlates service versions with known CVEs

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
- The script will automatically attempt to parse partial results if a timeout occurs
- Check network connectivity: `ping <target>`
- Target may be rate-limiting or heavily filtered
- Try increasing timeout values in the script for very slow targets
- The script provides manual command suggestions when timeouts occur

**No flags found:**
- Some machines require manual exploitation
- Check log files for clues
- Review JSON output for detailed scan results
- Try running with `--ai` flag for intelligent recommendations

**AI-related issues:**
- **"AI analysis disabled"**: Install OpenAI library with `pip install openai`
- **"OPENAI_API_KEY not set"**: Set environment variable `export OPENAI_API_KEY='your-key'`
- **"AI analysis failed"**: Check API key validity and internet connectivity
- **Rate limits**: OpenAI API has rate limits; wait a moment and retry
- **Cost concerns**: AI features use GPT-4 API which incurs costs (~$0.01-0.05 per scan)

## 📚 Resources

- [Hack The Box](https://www.hackthebox.com/)
- [Nmap Documentation](https://nmap.org/docs.html)
- [Kali Linux Tools](https://www.kali.org/tools/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OpenAI API Documentation](https://platform.openai.com/docs/)

## 📄 License

This tool is provided for educational purposes only. Use responsibly and only on authorized systems.

## 🤝 Contributing

Feel free to submit issues, suggestions, or improvements!

## ⚠️ Disclaimer

This tool is for authorized security testing only. The author is not responsible for misuse or damage caused by this tool. Always obtain proper authorization before testing any systems.
