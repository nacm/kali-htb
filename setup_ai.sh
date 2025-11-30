#!/bin/bash
# Quick setup script for HTB Auto Pwn AI features

echo "╔═══════════════════════════════════════════════╗"
echo "║   HTB Auto Pwn - AI Setup Assistant          ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if .env file exists
if [ -f ".env" ]; then
    echo -e "${YELLOW}[!] .env file already exists${NC}"
    read -p "Do you want to overwrite it? (y/n): " overwrite
    if [ "$overwrite" != "y" ] && [ "$overwrite" != "Y" ]; then
        echo "Setup cancelled."
        exit 0
    fi
fi

# Install dependencies
echo -e "\n${BLUE}[*] Installing required Python packages...${NC}"
pip install openai python-dotenv

if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[!] Installation failed. Try: pip install --user openai python-dotenv${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Dependencies installed${NC}"

# Get API key
echo -e "\n${BLUE}[*] Setting up OpenAI API Key${NC}"
echo -e "${YELLOW}Get your API key from: https://platform.openai.com/api-keys${NC}"
echo ""
read -p "Enter your OpenAI API key (or press Enter to set manually later): " api_key

if [ -z "$api_key" ]; then
    # Create .env from template
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "${YELLOW}[!] Created .env file from template${NC}"
        echo -e "${YELLOW}[!] Edit .env file and add your API key${NC}"
    else
        echo "OPENAI_API_KEY=sk-your-api-key-here" > .env
        echo -e "${YELLOW}[!] Created .env file${NC}"
        echo -e "${YELLOW}[!] Edit .env file and replace 'sk-your-api-key-here' with your actual key${NC}"
    fi
else
    # Validate API key format
    if [[ $api_key =~ ^sk-[a-zA-Z0-9\-]+$ ]]; then
        echo "OPENAI_API_KEY=$api_key" > .env
        echo -e "${GREEN}[✓] API key saved to .env file${NC}"
    else
        echo -e "${YELLOW}[!] API key format looks incorrect (should start with 'sk-')${NC}"
        echo "OPENAI_API_KEY=$api_key" > .env
        echo -e "${YELLOW}[!] Saved anyway - please verify it's correct${NC}"
    fi
fi

# Set permissions
chmod 600 .env
echo -e "${GREEN}[✓] Set secure permissions on .env file${NC}"

# Test setup
echo -e "\n${BLUE}[*] Testing setup...${NC}"
python3 -c "
import os
try:
    from dotenv import load_dotenv
    load_dotenv()
    api_key = os.getenv('OPENAI_API_KEY')
    if api_key and api_key != 'sk-your-api-key-here':
        print('${GREEN}[✓] API key loaded successfully${NC}')
        print(f'${GREEN}[✓] Key starts with: {api_key[:10]}...${NC}')
    else:
        print('${YELLOW}[!] API key not set or using template value${NC}')
        print('${YELLOW}[!] Edit .env file and add your actual API key${NC}')
except Exception as e:
    print(f'${YELLOW}[!] Error: {e}${NC}')
" 2>/dev/null

echo -e "\n╔═══════════════════════════════════════════════╗"
echo "║            Setup Complete!                    ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}You can now use AI features with:${NC}"
echo -e "  ${BLUE}python3 htb_auto_pwn.py -t <target> --ai${NC}"
echo ""
echo -e "${YELLOW}For more information, see: AI_SETUP.md${NC}"
