#!/usr/bin/env python3
"""
Mail Monitor - Production Email Threat Detection
Scans Gmail for threats and takes action
"""

import imaplib
import email
import re
import json
import sys
import configparser
from datetime import datetime
from typing import List, Dict, Any

class MailMonitor:
    """Production email threat monitor"""
    
    def __init__(self, config_file: str = None):
        if config_file:
            self.load_config(config_file)
        else:
            self.username = None
            self.password = None
        
        self.mail = None
        
        # Production threat patterns
        self.threat_keywords = [
            'urgent', 'verify', 'suspended', 'click here', 'act now',
            'wire transfer', 'bitcoin', 'cryptocurrency', 'refund',
            'update payment', 'confirm identity', 'security alert',
            'account locked', 'verify now', 'limited time'
        ]
        
        self.malicious_domains = [
            '.tk', '.ml', '.ga', '.cf', '.zip', '.mov', '.click',
            '.top', '.download', '.work', '.surf'
        ]
        
        self.threat_patterns = [
            r'bit\.ly/\w+',           # URL shorteners
            r'tinyurl\.com/\w+',
            r'\d+\.\d+\.\d+\.\d+',    # IP addresses
            r'[a-z0-9]+\.onion',      # Tor domains
            r'[hH][xX]{2}[pP]',       # Defanged URLs
            r'[0-9a-f]{32,}',         # Potential hashes
        ]
    
    def load_config(self, config_file: str):
        """Load configuration from INI file"""
        config = configparser.ConfigParser()
        config.read(config_file)
        
        self.username = config.get('gmail', 'username')
        self.password = config.get('gmail', 'password')
        self.scan_limit = config.getint('monitoring', 'max_emails_per_scan', fallback=50)
        self.quarantine_threshold = config.getfloat('thresholds', 'quarantine', fallback=0.7)
        self.flag_threshold = config.getfloat('thresholds', 'flag', fallback=0.5)
        self.block_threshold = config.getfloat('thresholds', 'block_sender', fallback=0.9)
    
    def connect(self) -> bool:
        """Connect to Gmail IMAP"""
        try:
            self.mail = imaplib.IMAP4_SSL('imap.gmail.com')
            self.mail.login(self.username, self.password)
            self.mail.select('inbox')
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def get_recent_emails(self, limit: int = None) -> List[Dict]:
        """Get recent emails from inbox"""
        if not self.mail:
            return []
        
        limit = limit or getattr(self, 'scan_limit', 50)
        
        try:
            result, data = self.mail.search(None, 'ALL')
            email_ids = data[0].split()
            recent_ids = email_ids[-limit:] if len(email_ids) > limit else email_ids
            
            emails = []
            for email_id in recent_ids:
                result, data = self.mail.fetch(email_id, '(RFC822)')
                raw_email = data[0][1]
                email_message = email.message_from_bytes(raw_email)
                
                emails.append({
                    'id': email_id.decode(),
                    'from': email_message.get('From', ''),
                    'subject': email_message.get('Subject', ''),
                    'date': email_message.get('Date', ''),
                    'body': self._extract_body(email_message)
                })
            
            return emails
            
        except Exception as e:
            print(f"Error retrieving emails: {e}")
            return []
    
    def _extract_body(self, email_message) -> str:
        """Extract text from email body"""
        body = ""
        
        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        pass
        else:
            try:
                body = email_message.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                body = str(email_message.get_payload())
        
        return body
    
    def analyze_threat(self, email_data: Dict) -> Dict[str, Any]:
        """Analyze email for threats - production logic"""
        
        subject = email_data.get('subject', '').lower()
        body = email_data.get('body', '').lower()
        sender = email_data.get('from', '').lower()
        
        threat_score = 0.0
        threats_detected = []
        
        # Keyword analysis
        for keyword in self.threat_keywords:
            if keyword in subject:
                threat_score += 0.15  # Subject keywords are more serious
                threats_detected.append(f"Threat keyword in subject: {keyword}")
            elif keyword in body:
                threat_score += 0.08
                threats_detected.append(f"Threat keyword in body: {keyword}")
        
        # Domain analysis
        for domain in self.malicious_domains:
            if domain in sender:
                threat_score += 0.25
                threats_detected.append(f"Malicious sender domain: {domain}")
            if domain in body:
                threat_score += 0.20
                threats_detected.append(f"Malicious URL domain: {domain}")
        
        # Pattern analysis
        text = f"{subject} {body}"
        for pattern in self.threat_patterns:
            matches = re.findall(pattern, text)
            if matches:
                threat_score += 0.18 * len(matches)
                threats_detected.append(f"Suspicious pattern: {pattern}")
        
        # URL analysis
        urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', body)
        for url in urls:
            if any(bad_domain in url for bad_domain in self.malicious_domains):
                threat_score += 0.35
                threats_detected.append(f"Malicious URL detected")
            if re.match(r'.*\d+\.\d+\.\d+\.\d+.*', url):
                threat_score += 0.25
                threats_detected.append("URL uses IP address instead of domain")
        
        # Determine action based on thresholds
        if threat_score >= getattr(self, 'block_threshold', 0.9):
            action = "BLOCK"
        elif threat_score >= getattr(self, 'quarantine_threshold', 0.7):
            action = "QUARANTINE"
        elif threat_score >= getattr(self, 'flag_threshold', 0.5):
            action = "FLAG"
        elif threat_score >= 0.2:
            action = "MONITOR"
        else:
            action = "ALLOW"
        
        return {
            'email_id': email_data['id'],
            'sender': email_data['from'],
            'subject': email_data['subject'],
            'threat_score': round(threat_score, 3),
            'action': action,
            'threats': threats_detected,
            'timestamp': datetime.now().isoformat()
        }
    
    def scan_mailbox(self, limit: int = None) -> List[Dict]:
        """Scan mailbox for threats"""
        
        if not self.connect():
            return []
        
        emails = self.get_recent_emails(limit)
        scan_results = []
        
        for email_data in emails:
            result = self.analyze_threat(email_data)
            scan_results.append(result)
        
        self.mail.close()
        return scan_results
    
    def save_scan_results(self, results: List[Dict], output_file: str = None):
        """Save scan results to JSON file"""
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"mail_scan_{timestamp}.json"
        
        scan_summary = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_emails_scanned': len(results),
            'threats_detected': len([r for r in results if r['threats']]),
            'high_risk_emails': len([r for r in results if r['action'] in ['QUARANTINE', 'BLOCK']]),
            'results': results
        }
        
        with open(output_file, 'w') as f:
            json.dump(scan_summary, f, indent=2)
        
        return output_file


def main():
    """Production command line interface"""
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python mailmonitor.py <config_file> [email_limit]")
        print("  python mailmonitor.py <username> <password> [email_limit]")
        print("")
        print("Examples:")
        print("  python mailmonitor.py gmail_config.ini")
        print("  python mailmonitor.py user@gmail.com app_password 100")
        return 1
    
    # Initialize monitor
    if len(sys.argv) >= 3 and '@' in sys.argv[1]:
        # Direct credentials
        monitor = MailMonitor()
        monitor.username = sys.argv[1]
        monitor.password = sys.argv[2]
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 50
    else:
        # Config file
        config_file = sys.argv[1]
        monitor = MailMonitor(config_file)
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else None
    
    print("MAIL MONITOR - THREAT SCAN")
    print("=" * 40)
    
    # Run scan
    results = monitor.scan_mailbox(limit)
    
    if not results:
        print("No emails scanned or scan failed")
        return 1
    
    # Analysis summary
    total = len(results)
    threats = [r for r in results if r['threats']]
    high_risk = [r for r in results if r['action'] in ['QUARANTINE', 'BLOCK']]
    
    print(f"Emails scanned: {total}")
    print(f"Threats detected: {len(threats)}")
    print(f"High risk emails: {len(high_risk)}")
    
    # Action breakdown
    actions = {}
    for result in results:
        action = result['action']
        actions[action] = actions.get(action, 0) + 1
    
    print("\nAction Summary:")
    for action, count in sorted(actions.items()):
        print(f"  {action}: {count}")
    
    # Save results
    output_file = monitor.save_scan_results(results)
    print(f"\nResults saved: {output_file}")
    
    # Show critical threats
    critical = [r for r in results if r['action'] == 'BLOCK']
    if critical:
        print(f"\nCRITICAL THREATS ({len(critical)}):")
        for result in critical:
            print(f"  {result['subject'][:60]} (Score: {result['threat_score']})")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())