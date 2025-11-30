# .env File Configuration

This document explains how the `.env` file works for storing your OpenAI API key securely.

## What is a .env file?

A `.env` file is a simple text file that stores environment variables. It's a common practice in software development to store sensitive configuration (like API keys) separate from your code.

## Why use .env?

✅ **Security**: Keeps API keys out of your code and version control
✅ **Convenience**: No need to export variables every session  
✅ **Portability**: Easy to share configurations without sharing secrets
✅ **Best Practice**: Industry standard for configuration management

## File Structure

The `.env` file in this project contains:

```bash
# OpenAI API Key for AI-powered analysis
OPENAI_API_KEY=sk-your-api-key-here
```

## Setup Instructions

### Step 1: Create the .env file

**Option A: Use the setup script (easiest)**
```bash
./setup_ai.sh
```

**Option B: Copy from template**
```bash
cp .env.example .env
```

**Option C: Create manually**
```bash
echo 'OPENAI_API_KEY=sk-your-actual-key-here' > .env
```

### Step 2: Add your API key

Edit the `.env` file:
```bash
nano .env
# or
vim .env
# or
code .env
```

Replace `sk-your-api-key-here` with your actual OpenAI API key.

### Step 3: Set proper permissions (important!)

```bash
chmod 600 .env
```

This ensures only you can read/write the file.

## How It Works

1. When you run `htb_auto_pwn.py`, the script automatically:
   - Looks for a `.env` file in the same directory
   - Loads any variables found in the file
   - Makes them available to the script via `os.getenv()`

2. The script uses `python-dotenv` library to load the file:
   ```python
   from dotenv import load_dotenv
   load_dotenv()  # Loads .env file
   api_key = os.getenv('OPENAI_API_KEY')
   ```

## Security Features

### Included in .gitignore

The `.env` file is automatically excluded from git commits:

```bash
# From .gitignore
.env
.env.local
.env.*.local
```

This prevents accidentally committing your API key to version control.

### File Permissions

After setup, the file has `600` permissions (read/write for owner only):
```bash
-rw------- 1 user user 237 Nov 30 04:02 .env
```

## Verification

Check if your .env is loaded correctly:

```bash
# Test 1: Check if file exists
ls -la .env

# Test 2: Verify contents (careful - this shows your key!)
cat .env

# Test 3: Test loading in Python
python3 -c "from dotenv import load_dotenv; import os; load_dotenv(); print('Key loaded:', 'Yes' if os.getenv('OPENAI_API_KEY') else 'No')"
```

## Troubleshooting

### "OPENAI_API_KEY not set"

**Solution 1:** Verify .env file exists
```bash
ls -la .env
```

**Solution 2:** Check file contents
```bash
cat .env | grep OPENAI_API_KEY
```

**Solution 3:** Ensure python-dotenv is installed
```bash
pip install python-dotenv
```

### "python-dotenv not installed"

```bash
pip install python-dotenv
# or
pip install -r requirements.txt
```

### Key still shows template value

Edit your `.env` file and replace:
```bash
OPENAI_API_KEY=sk-your-api-key-here
```

With your actual key:
```bash
OPENAI_API_KEY=sk-proj-abc123xyz...
```

### File permissions error

```bash
chmod 600 .env
```

## Multiple Environments

You can create different .env files for different purposes:

- `.env` - Default file (loaded automatically)
- `.env.local` - Local overrides (also in .gitignore)
- `.env.production` - Production settings
- `.env.development` - Development settings

## Backup Your Key

Since `.env` is not committed to git, make sure to:

1. **Save your API key somewhere secure** (password manager)
2. **Keep a backup** of your `.env` file in a secure location
3. **Don't lose your OpenAI API key** - you can't view it again on OpenAI's site

## Alternative: Environment Variables

If you prefer not to use a `.env` file, you can still use environment variables:

```bash
# Temporary (current session only)
export OPENAI_API_KEY='sk-your-key-here'

# Permanent (add to shell config)
echo 'export OPENAI_API_KEY="sk-your-key-here"' >> ~/.bashrc
source ~/.bashrc
```

The script will check both `.env` file and environment variables.

## What Gets Committed to Git?

✅ **Committed** (safe):
- `.env.example` - Template with placeholder values
- `.gitignore` - Excludes .env files
- Documentation about .env files

❌ **Not Committed** (secret):
- `.env` - Your actual API key
- `.env.local` - Local configuration
- Any `.env.*` files with real credentials

## Best Practices

1. ✅ Always use `.env` for API keys and secrets
2. ✅ Never commit `.env` to version control
3. ✅ Keep a backup of your API keys securely
4. ✅ Use restrictive file permissions (600)
5. ✅ Share `.env.example` as a template
6. ✅ Document what variables are needed
7. ❌ Never share your actual `.env` file
8. ❌ Don't hardcode API keys in source code
9. ❌ Don't include API keys in screenshots or logs

## Resources

- [python-dotenv Documentation](https://github.com/theskumar/python-dotenv)
- [12-Factor App - Config](https://12factor.net/config)
- [OpenAI API Keys](https://platform.openai.com/api-keys)
