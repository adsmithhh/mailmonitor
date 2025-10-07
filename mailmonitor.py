#!/usr/bin/env python3
"""
Simple Mail Monitor - Threat Detection for Gmail
Keep it simple: scan emails, detect threats, take action
"""

import imaplib
import email
import re
import json
import sys
from datetime import datetime
from typing import List, Dict, Any

class SimpleMailMonitor:
    """Dead simple email threat monitor"""
    
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.mail = None
        
        # Simple threat patterns - no fancy AI needed
        self.bad_keywords = [
            'urgent', 'verify', 'suspended', 'click here', 'act now',
            'wire transfer', 'bitcoin', 'cryptocurrency', 'refund',
            'update payment', 'confirm identity', 'security alert'
        ]
        
        self.bad_domains = [
            '.tk', '.ml', '.ga', '.cf', '.zip', '.mov', '.click'
        ]
        
        self.suspicious_patterns = [
            r'bit\.ly/\w+',           # Shortened URLs
            r'\d+\.\d+\.\d+\.\d+',    # IP addresses
            r'[a-z0-9]+\.onion',      # Tor domains
            r'[hH][xX]{2}[pP]',       # Defanged URLs
        ]
    
    def connect(self) -> bool:
        """Connect to Gmail"""
        try:
            self.mail = imaplib.IMAP4_SSL('imap.gmail.com')
            self.mail.login(self.username, self.password)
            self.mail.select('inbox')
            print(f"✅ Connected to {self.username}")
            return True
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False
    
    def get_emails(self, limit: int = 50) -> List[Dict]:
        """Get recent emails"""
        if not self.mail:
            return []
        
        try:
            # Search for recent emails
            result, data = self.mail.search(None, 'ALL')
            email_ids = data[0].split()
            
            # Get the most recent ones
            recent_ids = email_ids[-limit:] if len(email_ids) > limit else email_ids
            
            emails = []
            for email_id in recent_ids:
                result, data = self.mail.fetch(email_id, '(RFC822)')
                raw_email = data[0][1]
                email_message = email.message_from_bytes(raw_email)
                
                # Extract basic info
                email_data = {
                    'id': email_id.decode(),
                    'from': email_message.get('From', ''),
                    'subject': email_message.get('Subject', ''),
                    'date': email_message.get('Date', ''),
                    'body': self._get_body(email_message)
                }
                emails.append(email_data)
            
            print(f"📧 Retrieved {len(emails)} emails")
            return emails
            
        except Exception as e:
            print(f"❌ Error getting emails: {e}")
            return []
    
    def _get_body(self, email_message) -> str:
        """Extract email body text"""
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
    
    def scan_email(self, email_data: Dict) -> Dict[str, Any]:
        """Scan single email for threats - keep it simple"""
        
        subject = email_data.get('subject', '').lower()
        body = email_data.get('body', '').lower()
        sender = email_data.get('from', '').lower()
        
        threats = []
        risk_score = 0
        
        # Check for bad keywords
        for keyword in self.bad_keywords:
            if keyword in subject or keyword in body:
                threats.append(f"Suspicious keyword: {keyword}")
                risk_score += 20
        
        # Check sender domain
        for domain in self.bad_domains:
            if domain in sender:
                threats.append(f"Suspicious domain: {domain}")
                risk_score += 30
        
        # Check for suspicious patterns
        text = subject + " " + body
        for pattern in self.suspicious_patterns:
            if re.search(pattern, text):
                threats.append(f"Suspicious pattern: {pattern}")
                risk_score += 25
        
        # Simple URL check
        urls = re.findall(r'https?://[^\s]+', body)
        for url in urls:
            if any(bad in url for bad in self.bad_domains):
                threats.append(f"Suspicious URL: {url[:50]}...")
                risk_score += 40
        
        # Determine action
        if risk_score >= 80:
            action = "BLOCK"
        elif risk_score >= 60:
            action = "QUARANTINE"
        elif risk_score >= 40:
            action = "FLAG"
        elif risk_score >= 20:
            action = "MONITOR"
        else:
            action = "ALLOW"
        
        return {
            'email_id': email_data['id'],
            'from': email_data['from'],
            'subject': email_data['subject'],
            'risk_score': risk_score,
            'action': action,
            'threats': threats,
            'scan_time': datetime.now().isoformat()
        }
    
    def scan_all(self, limit: int = 50) -> List[Dict]:
        """Scan multiple emails"""
        
        if not self.connect():
            return []
        
        emails = self.get_emails(limit)
        results = []
        
        print(f"\n🔍 Scanning {len(emails)} emails...")
        
        for i, email_data in enumerate(emails, 1):
            result = self.scan_email(email_data)
            results.append(result)
            
            # Simple progress
            status = result['action']
            score = result['risk_score']
            print(f"{i:3d}. {status:10s} (Score: {score:2d}) - {result['subject'][:50]}")
        
        self.mail.close()
        return results
    
    def save_results(self, results: List[Dict], filename: str = None):
        """Save results to JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump({
                'scan_time': datetime.now().isoformat(),
                'total_emails': len(results),
                'results': results
            }, f, indent=2)
        
        print(f"💾 Results saved to {filename}")


def main():
    """Simple command line interface"""
    
    if len(sys.argv) < 3:
        print("Usage: python mailmonitor.py <username> <password> [limit]")
        print("Example: python mailmonitor.py user@gmail.com app_password 20")
        return
    
    username = sys.argv[1]
    password = sys.argv[2]
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else 50
    
    print("📧 SIMPLE MAIL MONITOR")
    print("=" * 50)
    
    monitor = SimpleMailMonitor(username, password)
    results = monitor.scan_all(limit)
    
    if results:
        # Summary
        print(f"\n📊 SCAN SUMMARY")
        print("-" * 30)
        
        actions = {}
        for result in results:
            action = result['action']
            actions[action] = actions.get(action, 0) + 1
        
        for action, count in actions.items():
            print(f"{action:12s}: {count:3d} emails")
        
        # Save results
        monitor.save_results(results)
        
        # Show threats
        threats_found = [r for r in results if r['threats']]
        if threats_found:
            print(f"\n⚠️  THREATS DETECTED: {len(threats_found)}")
            for result in threats_found:
                print(f"- {result['subject'][:40]} (Score: {result['risk_score']})")
    
    print("\n✅ Scan complete!")


if __name__ == "__main__":
    main()