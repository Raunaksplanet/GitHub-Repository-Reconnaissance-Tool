#!/usr/bin/env python3
"""
GitHub Repository Reconnaissance & Secret Finder Tool
"""

import os
import re
import subprocess
import argparse
import json
import tempfile
from pathlib import Path
from datetime import datetime
import sys

class GitHubRecon:
    def __init__(self, repo_path=None, output_file=None):
        self.repo_path = repo_path or os.getcwd()
        self.output_file = output_file
        self.results = {
            'metadata': {},
            'deleted_files': [],
            'secrets_found': [],
            'sensitive_files': [],
            'git_history': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # Enhanced regex patterns for secret detection
        self.regex_patterns = {
            'google_api': r'AIza[0-9A-Za-z\-_]{35}',
            'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
            'google_captcha': r'6L[0-9A-Za-z\-_]{38}|^6[0-9a-zA-Z_-]{39}$',
            'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
            'amazon_aws_access_key_id': r'A[SK]IA[0-9A-Z]{16}',
            'amazon_mws_auth_token': r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'amazon_aws_url': r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
            'facebook_access_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'authorization_basic': r'basic\s+[a-zA-Z0-9=:_\+\/-]{5,100}',
            'authorization_bearer': r'bearer\s+[a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
            'authorization_api': r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
            'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
            'twilio_api_key': r'SK[0-9a-fA-F]{32}',
            'twilio_account_sid': r'AC[a-zA-Z0-9_\-]{32}',
            'twilio_app_sid': r'AP[a-zA-Z0-9_\-]{32}',
            'paypal_braintree_access_token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            'square_oauth_secret': r'sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
            'square_access_token': r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
            'stripe_standard_api': r'sk_live_[0-9a-zA-Z]{24}',
            'stripe_restricted_api': r'rk_live_[0-9a-zA-Z]{24}',
            'github_access_token': r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
            'rsa_private_key': r'-----BEGIN RSA PRIVATE KEY-----',
            'ssh_dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----',
            'ssh_ec_private_key': r'-----BEGIN EC PRIVATE KEY-----',
            'pgp_private_block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'json_web_token': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
            'slack_token': r'"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"',
            'ssh_privkey': r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
            'heroku_api_key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            'possible_creds': r"(?i)(password\s*[`=:\"]+\s*[^\s]+|password is\s*[`=:\"]*\s*[^\s]+|pwd\s*[`=:\"]*\s*[^\s]+|passwd\s*[`=:\"]+\s*[^\s]+)",
        }

    def run_command(self, cmd):
        """Execute shell command and return output"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=self.repo_path)
            return result.stdout, result.stderr
        except Exception as e:
            return "", str(e)

    def get_repo_info(self):
        """Get repository metadata"""
        print("[+] Gathering repository information...")
        
        # Get git remote URL
        remote_url, _ = self.run_command("git remote -v")
        self.results['metadata']['remote_url'] = remote_url.strip()
        
        # Get current branch
        branch, _ = self.run_command("git branch --show-current")
        self.results['metadata']['current_branch'] = branch.strip()
        
        # Get commit count
        commit_count, _ = self.run_command("git rev-list --count HEAD")
        self.results['metadata']['commit_count'] = commit_count.strip()

    def find_deleted_files(self):
        """Find deleted files in git history"""
        print("[+] Searching for deleted files in git history...")
        
        # Your original command enhanced
        cmd1 = "git log --diff-filter=D --summary | grep delete"
        output1, _ = self.run_command(cmd1)
        
        # Alternative approach with more details
        cmd2 = "git log --diff-filter=D --stat --oneline"
        output2, _ = self.run_command(cmd2)
        
        deleted_files = []
        
        # Parse output from first command
        for line in output1.split('\n'):
            if 'delete' in line:
                deleted_files.append(line.strip())
        
        # Parse output from second command
        for line in output2.split('\n'):
            if line:
                deleted_files.append(line.strip())
        
        self.results['deleted_files'] = list(set(deleted_files))

    def search_secrets_in_file(self, file_path):
        """Search for secrets in a specific file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            secrets_found = []
            for pattern_name, pattern in self.regex_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    secret = {
                        'file': file_path,
                        'pattern': pattern_name,
                        'match': match.group(),
                        'line_number': content[:match.start()].count('\n') + 1
                    }
                    secrets_found.append(secret)
            
            return secrets_found
        except Exception as e:
            return []

    def scan_for_secrets(self):
        """Scan entire repository for secrets"""
        print("[+] Scanning for secrets in code...")
        
        # Get list of all files in repository
        find_cmd = "git ls-files"
        files_output, _ = self.run_command(find_cmd)
        files = files_output.split('\n')
        
        all_secrets = []
        sensitive_extensions = ['.key', '.pem', '.p12', '.pfx', '.cer', '.crt', '.csr', '.der', '.jks', '.keystore']
        
        for file_path in files:
            if not file_path:
                continue
                
            full_path = os.path.join(self.repo_path, file_path)
            
            # Check if file is sensitive by extension
            if any(file_path.endswith(ext) for ext in sensitive_extensions):
                self.results['sensitive_files'].append(file_path)
            
            # Search for secrets in file
            secrets = self.search_secrets_in_file(full_path)
            all_secrets.extend(secrets)
        
        self.results['secrets_found'] = all_secrets

    def analyze_git_history(self):
        """Analyze git history for sensitive information"""
        print("[+] Analyzing git history...")
        
        # Get all commits with details
        cmd = "git log --oneline -n 100"
        output, _ = self.run_command(cmd)
        self.results['git_history'] = output.split('\n')

    def generate_report(self):
        """Generate a human-readable report"""
        print("\n" + "="*60)
        print("GITHUB REPOSITORY RECONNAISSANCE REPORT")
        print("="*60)
        
        print(f"\n[REPOSITORY INFO]")
        for key, value in self.results['metadata'].items():
            print(f"  {key}: {value}")
        
        print(f"\n[DELETED FILES] ({len(self.results['deleted_files'])} found)")
        for file in self.results['deleted_files'][:10]:
            print(f"  - {file}")
        
        print(f"\n[SENSITIVE FILES] ({len(self.results['sensitive_files'])} found)")
        for file in self.results['sensitive_files'][:10]:
            print(f"  - {file}")
        
        print(f"\n[SECRETS FOUND] ({len(self.results['secrets_found'])} found)")
        for secret in self.results['secrets_found'][:10]:
            print(f"  - File: {secret['file']}")
            print(f"    Type: {secret['pattern']}")
            print(f"    Match: {secret['match'][:50]}...")
            print(f"    Line: {secret['line_number']}")
            print()

    def run_full_scan(self):
        """Run complete reconnaissance scan"""
        print("Starting GitHub Repository Reconnaissance...")
        
        # Check if it's a git repository
        if not os.path.exists(os.path.join(self.repo_path, '.git')):
            print(f"Error: {self.repo_path} is not a git repository!")
            return
        
        self.get_repo_info()
        self.find_deleted_files()
        self.scan_for_secrets()
        self.analyze_git_history()
        
        # Generate reports
        self.generate_report()
        
        print("\n[+] Scan completed!")

def main():
    parser = argparse.ArgumentParser(description="GitHub Repository Reconnaissance & Secret Finder")
    parser.add_argument("-p", "--path", help="Path to git repository (default: current directory)")
    parser.add_argument("-o", "--output", help="Output file for results (JSON format)")
    parser.add_argument("--secrets-only", action="store_true", help="Only scan for secrets")
    parser.add_argument("--deleted-only", action="store_true", help="Only find deleted files")
    
    args = parser.parse_args()
    
    recon = GitHubRecon(args.path, args.output)
    
    if args.secrets_only:
        recon.scan_for_secrets()
        recon.generate_report()
    elif args.deleted_only:
        recon.find_deleted_files()
        print("\n[DELETED FILES]")
        for file in recon.results['deleted_files']:
            print(f"- {file}")
    else:
        recon.run_full_scan()

if __name__ == "__main__":
    main()
