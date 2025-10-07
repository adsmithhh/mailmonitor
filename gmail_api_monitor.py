#!/usr/bin/env python3
"""
Mail Monitor with Gmail API Support
Enhanced version using Gmail API instead of IMAP
"""

import os
import json
import pickle
from datetime import datetime
from typing import List, Dict, Any

try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    GMAIL_API_AVAILABLE = True
except ImportError:
    GMAIL_API_AVAILABLE = False

from mailmonitor_v3 import HybridMailMonitor  # Import our existing hybrid system

class GmailApiMonitor(HybridMailMonitor):
    """Enhanced Mail Monitor using Gmail API"""
    
    # Gmail API scopes
    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
    
    def __init__(self, config_file: str = None, use_api: bool = True):
        super().__init__(config_file)
        self.use_api = use_api and GMAIL_API_AVAILABLE
        self.service = None
        
        if self.use_api:
            self._authenticate_gmail_api()
    
    def _authenticate_gmail_api(self):
        """Authenticate with Gmail API"""
        creds = None
        
        # Load existing credentials
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)
        
        # If no valid credentials, get new ones
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists('credentials.json'):
                    print("❌ credentials.json not found")
                    print("📋 Download from Google Cloud Console:")
                    print("   1. Go to console.cloud.google.com")
                    print("   2. APIs & Services → Credentials")
                    print("   3. Create OAuth 2.0 Client ID (Desktop)")
                    print("   4. Download as 'credentials.json'")
                    return False
                
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', self.SCOPES)
                creds = flow.run_local_server(port=0)
            
            # Save credentials for future use
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)
        
        self.service = build('gmail', 'v1', credentials=creds)
        return True
    
    def get_emails_api(self, max_results: int = 50) -> List[Dict]:
        """Get emails using Gmail API"""
        if not self.service:
            return []
        
        try:
            # Get message list
            results = self.service.users().messages().list(
                userId='me', maxResults=max_results).execute()
            messages = results.get('messages', [])
            
            emails = []
            
            for msg in messages:
                # Get full message
                message = self.service.users().messages().get(
                    userId='me', id=msg['id']).execute()
                
                # Extract headers
                headers = message['payload'].get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
                sender = next((h['value'] for h in headers if h['name'] == 'From'), '')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), '')
                
                # Extract body
                body = self._extract_body_api(message['payload'])
                
                emails.append({
                    'id': msg['id'],
                    'from': sender,
                    'subject': subject,
                    'date': date,
                    'body': body,
                    'labels': message.get('labelIds', [])
                })
            
            return emails
            
        except Exception as e:
            print(f"❌ Gmail API error: {e}")
            return []
    
    def _extract_body_api(self, payload) -> str:
        """Extract body text from Gmail API payload"""
        body = ""
        
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    body += self._decode_base64(data)
                elif 'parts' in part:
                    body += self._extract_body_api(part)
        elif payload['mimeType'] == 'text/plain':
            data = payload['body']['data']
            body += self._decode_base64(data)
        
        return body
    
    def _decode_base64(self, data: str) -> str:
        """Decode base64 Gmail API data"""
        import base64
        try:
            return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        except:
            return ""
    
    def scan_mailbox_enhanced(self, limit: int = None) -> List[Dict]:
        """Enhanced mailbox scanning with API features"""
        
        if self.use_api and self.service:
            print("🔗 Using Gmail API...")
            emails = self.get_emails_api(limit or 50)
        else:
            print("📧 Using IMAP fallback...")
            # Fall back to IMAP method - need to use async properly
            import asyncio
            return asyncio.run(super().scan_emails(limit=limit))
        
        if not emails:
            return []
        
        scan_results = []
        
        for email_data in emails:
            # Use async analyze_email from parent class
            import asyncio
            result = asyncio.run(self.analyze_email(email_data))
            
            # Add API-specific features
            result['api_features'] = {
                'labels': email_data.get('labels', []),
                'message_id': email_data['id'],
                'api_enhanced': True
            }
            
            scan_results.append(result)
        
        return scan_results
    
    def get_labels(self) -> List[Dict]:
        """Get Gmail labels using API"""
        if not self.service:
            return []
        
        try:
            results = self.service.users().labels().list(userId='me').execute()
            return results.get('labels', [])
        except Exception as e:
            print(f"❌ Error getting labels: {e}")
            return []
    
    def mark_as_spam(self, message_id: str) -> bool:
        """Mark message as spam using API"""
        if not self.service:
            return False
        
        try:
            self.service.users().messages().modify(
                userId='me',
                id=message_id,
                body={'addLabelIds': ['SPAM']}
            ).execute()
            return True
        except Exception as e:
            print(f"❌ Error marking as spam: {e}")
            return False


def main():
    """Enhanced CLI with Gmail API support"""
    
    if not GMAIL_API_AVAILABLE:
        print("⚠️ Gmail API libraries not installed")
        print("📦 Install with: pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client")
        print("🔄 Falling back to IMAP mode...")
        
        # Fall back to regular version
        from mailmonitor_v3 import main as main_v3
        return main_v3()
    
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python gmail_api_monitor.py <config_file> [--api] [limit]")
        print("  python gmail_api_monitor.py gmail_config.ini --api 50")
        print("")
        print("Features:")
        print("  --api     Use Gmail API (enhanced features)")
        print("  --imap    Use IMAP (fallback mode)")
        return 1
    
    config_file = sys.argv[1]
    use_api = '--api' in sys.argv
    limit = None
    
    # Parse limit
    for arg in sys.argv[2:]:
        if arg.isdigit():
            limit = int(arg)
            break
    
    print("📧 GMAIL API MAIL MONITOR")
    print("=" * 40)
    
    # Initialize monitor
    monitor = GmailApiMonitor(config_file, use_api=use_api)
    
    # Show available labels if using API
    if use_api and monitor.service:
        labels = monitor.get_labels()
        print(f"📋 Gmail labels available: {len(labels)}")
    
    # Run enhanced scan
    results = monitor.scan_mailbox_enhanced(limit)
    
    if not results:
        print("❌ No emails scanned or scan failed")
        return 1
    
    # Enhanced analysis
    total = len(results)
    threats = [r for r in results if r['threats']]
    high_risk = [r for r in results if r['action'] in ['QUARANTINE', 'BLOCK']]
    api_enhanced = [r for r in results if r.get('api_features', {}).get('api_enhanced')]
    
    print(f"📊 ENHANCED SCAN RESULTS")
    print(f"Emails scanned: {total}")
    print(f"Threats detected: {len(threats)}")
    print(f"High risk emails: {len(high_risk)}")
    if api_enhanced:
        print(f"API enhanced: {len(api_enhanced)}")
    
    # Save results
    output_file = monitor.save_results(results, "gmail_api_scan.json")
    print(f"💾 Results saved: {output_file}")
    
    # Auto-action on high threats (if API available)
    if use_api and monitor.service and high_risk:
        print(f"\n🚨 Taking action on {len(high_risk)} high-risk emails...")
        for result in high_risk:
            if result['action'] == 'BLOCK':
                message_id = result.get('api_features', {}).get('message_id')
                if message_id:
                    if monitor.mark_as_spam(message_id):
                        print(f"✅ Marked as spam: {result['subject'][:50]}")
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())