# AI-Powered Analysis Setup Guide

This guide will help you set up the AI-powered features of HTB Auto Pwn.

## Prerequisites

- Python 3.7 or higher
- OpenAI API account
- Active internet connection

## Step 1: Install Required Libraries

```bash
pip install openai python-dotenv
```

Or using the requirements file:

```bash
pip install -r requirements.txt
```

**What gets installed:**
- `openai` - OpenAI API client library
- `python-dotenv` - For loading environment variables from .env file

## Step 2: Get Your OpenAI API Key

1. Visit https://platform.openai.com/api-keys
2. Sign up or log in to your OpenAI account
3. Click "Create new secret key"
4. Copy your API key (it starts with `sk-`)
5. **Important**: Save your key securely - you won't be able to see it again!

## Step 3: Set Your API Key

### Option A: .env File (Recommended)

The easiest and safest method is to use a `.env` file:

**Method 1: Use the provided template**
```bash
# Copy the example file
cp .env.example .env

# Edit the file with your API key
nano .env  # or use vim, code, etc.
```

**Method 2: Create directly**
```bash
# Create .env file with your API key
echo 'OPENAI_API_KEY=sk-your-actual-api-key-here' > .env
```

The `.env` file should look like:
```
OPENAI_API_KEY=sk-proj-abc123...
```

**Benefits:**
- ✅ Automatically loaded by the script
- ✅ Not tracked by git (in .gitignore)
- ✅ No need to export every session
- ✅ Easy to update

### Option B: Environment Variable

**For current session:**
```bash
export OPENAI_API_KEY='sk-your-api-key-here'
```

**For permanent setup (bash):**
```bash
echo 'export OPENAI_API_KEY="sk-your-api-key-here"' >> ~/.bashrc
source ~/.bashrc
```

**For permanent setup (zsh):**
```bash
echo 'export OPENAI_API_KEY="sk-your-api-key-here"' >> ~/.zshrc
source ~/.zshrc
```

## Step 4: Test AI Features

Run a scan with AI enabled:

```bash
python3 htb_auto_pwn.py -t 10.10.10.100 --ai
```

You should see:
```
[INFO] AI-powered analysis enabled
```

## What AI Features Provide

### 1. Intelligent Scan Analysis
- Analyzes nmap results to identify promising attack vectors
- Correlates service versions with known vulnerabilities
- Prioritizes targets based on exploitation likelihood
- **Shows full AI prompts and responses in terminal and logs**

### 2. Dynamic Targeted Scanning
- Runs additional focused scans on priority services
- Executes service-specific nmap scripts based on AI recommendations
- Adapts scanning strategy to discovered services

### 3. Exploitation Strategy
- Suggests optimal exploitation order
- Recommends specific tools and commands
- Provides reasoning for attack approach
- **Displays formatted strategy with commands and warnings**

### 4. Vulnerability Intelligence
- Identifies potential CVEs from service versions
- Maps services to common vulnerability types
- Suggests mitigation checks

### 5. Detailed Exploit Suggestions (NEW!)
- **For each vulnerability found, AI provides:**
  - Specific exploit names and types (Metasploit/manual/searchsploit)
  - Exact commands to execute
  - CVE numbers where applicable
  - Success probability estimates (high/medium/low)
  - Step-by-step manual exploitation guides
  - Recommended tools list
  - Important cautions and warnings
  - Reference links to exploit databases
- **All prompts and responses logged for analysis**

## Example AI Output

```bash
$ python3 htb_auto_pwn.py -t 10.10.10.3 --ai

[INFO] AI-powered analysis enabled
[INFO] 🤖 AI analyzing scan results...

============================================================
AI PROMPT - Scan Analysis
============================================================
You are a penetration testing expert analyzing network scan results.

Scan Results:
{
  "host": "10.10.10.3",
  "ports": [
    {"port": 21, "service": "ftp", "version": "vsftpd 2.3.4"},
    {"port": 22, "service": "ssh", "version": "OpenSSH 4.7"},
    {"port": 80, "service": "http", "version": "Apache 2.2.8"}
  ]
}

Based on these results:
1. Identify the most promising attack vectors
2. Suggest specific scanning strategies...
============================================================

============================================================
AI RESPONSE - Scan Analysis
============================================================
{
  "attack_vectors": [
    "vsftpd 2.3.4 backdoor exploitation (CVE-2011-2523)",
    "Anonymous FTP enumeration",
    "Web application vulnerability scanning"
  ],
  "priority_ports": [21, 80],
  "vulnerabilities": [
    "CVE-2011-2523 (vsftpd backdoor)",
    "Outdated Apache 2.2.8",
    "Outdated OpenSSH 4.7"
  ],
  "strategy": "aggressive",
  "reasoning": "vsftpd 2.3.4 has a well-known backdoor..."
}
============================================================

[INFO] ✓ AI analysis complete
[INFO] Strategy: aggressive
[INFO] Reasoning: vsftpd 2.3.4 has a well-known backdoor...

[PHASE 2.5] AI Exploit Analysis
[INFO] Getting exploit suggestions for 3 vulnerabilities...

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
  • telnet

⚠️  Cautions:
  • This is a well-known exploit, may be detected
  • Test connection before assuming success
```

**All prompts and responses are:**
- ✅ Displayed in the terminal with color coding
- ✅ Saved to log file for later review
- ✅ Included in JSON output for programmatic access

## Cost Considerations

- AI features use OpenAI's GPT-4 API
- Average cost per scan: $0.01 - $0.05
- Costs vary based on:
  - Number of open ports discovered
  - Complexity of services found
  - Length of scan output

**Tip**: Monitor your usage at https://platform.openai.com/usage

## Troubleshooting

### "AI analysis disabled"
- Install OpenAI library: `pip install openai`
- Verify installation: `python3 -c "import openai; print('OK')"`

### "OPENAI_API_KEY not set"
- Check environment variable: `echo $OPENAI_API_KEY`
- Ensure key is exported (not just set)
- Try running in a new terminal session

### "AI analysis failed"
- Verify API key is valid
- Check internet connectivity: `curl https://api.openai.com`
- Check OpenAI service status: https://status.openai.com
- Review error in verbose mode: `--ai -v`

### Rate Limit Errors
- OpenAI has rate limits for API calls
- Wait 60 seconds and retry
- Consider upgrading your OpenAI tier for higher limits

## Disabling AI Features

AI features are **opt-in** and disabled by default. Simply omit the `--ai` flag to use standard scanning without AI.

```bash
# Standard scan (no AI)
python3 htb_auto_pwn.py -t 10.10.10.100

# AI-powered scan
python3 htb_auto_pwn.py -t 10.10.10.100 --ai
```

## Privacy & Security

- Scan results are sent to OpenAI's API for analysis
- Data is processed according to OpenAI's privacy policy
- No sensitive data is permanently stored by OpenAI (per their policy)
- For sensitive targets, use standard mode without `--ai` flag

## Best Practices

1. **Start with standard scans** to understand baseline behavior
2. **Use AI for complex targets** where manual analysis would be time-consuming
3. **Review AI recommendations** before executing suggested commands
4. **Combine with manual analysis** for best results
5. **Monitor API costs** through OpenAI dashboard

## Resources

- [OpenAI API Documentation](https://platform.openai.com/docs/)
- [OpenAI Pricing](https://openai.com/pricing)
- [OpenAI Usage Dashboard](https://platform.openai.com/usage)
- [OpenAI Support](https://help.openai.com/)
