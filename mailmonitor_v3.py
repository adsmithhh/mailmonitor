#!/usr/bin/env python3
"""
Mail Monitor v3 - Hybrid Production System
Combines real Gmail monitoring with enhanced modular architecture
"""

import imaplib
import email
import re
import json
import sys
import configparser
import asyncio
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass

try:
    import yaml
except ImportError:
    yaml = None

@dataclass
class ThreatResult:
    """Standardized threat analysis result"""
    score: float
    confidence: float
    threats: List[str]
    category: str
    details: Dict[str, Any]

class AnalysisProvider:
    """Base class for threat analysis providers"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.weight = config.get('weight', 1.0)
        self.enabled = config.get('enabled', True)
    
    async def analyze(self, email_data: Dict) -> ThreatResult:
        """Override in subclasses"""
        raise NotImplementedError

class KeywordAnalyzer(AnalysisProvider):
    """Keyword-based threat detection"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.threat_keywords = config.get('keywords', [
            'urgent', 'verify', 'suspended', 'click here', 'act now',
            'wire transfer', 'bitcoin', 'cryptocurrency', 'refund',
            'update payment', 'confirm identity', 'security alert'
        ])
    
    async def analyze(self, email_data: Dict) -> ThreatResult:
        subject = email_data.get('subject', '').lower()
        body = email_data.get('body', '').lower()
        
        threats = []
        score = 0.0
        
        for keyword in self.threat_keywords:
            if keyword in subject:
                score += 0.20  # Higher weight for subject
                threats.append(f"Threat keyword in subject: {keyword}")
            elif keyword in body:
                score += 0.10
                threats.append(f"Threat keyword in body: {keyword}")
        
        return ThreatResult(
            score=min(score, 1.0),
            confidence=0.8,
            threats=threats,
            category="keyword",
            details={"keywords_found": len(threats)}
        )

class DomainAnalyzer(AnalysisProvider):
    """Domain and URL threat detection"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.malicious_domains = config.get('domains', [
            '.tk', '.ml', '.ga', '.cf', '.zip', '.mov', '.click'
        ])
        self.patterns = config.get('patterns', [
            r'bit\.ly/\w+', r'tinyurl\.com/\w+', r'\d+\.\d+\.\d+\.\d+',
            r'[a-z0-9]+\.onion', r'[hH][xX]{2}[pP]'
        ])
    
    async def analyze(self, email_data: Dict) -> ThreatResult:
        sender = email_data.get('from', '').lower()
        body = email_data.get('body', '').lower()
        
        threats = []
        score = 0.0
        
        # Check sender domain
        for domain in self.malicious_domains:
            if domain in sender:
                score += 0.30
                threats.append(f"Malicious sender domain: {domain}")
        
        # Check URLs in body
        urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', body)
        for url in urls:
            for domain in self.malicious_domains:
                if domain in url:
                    score += 0.25
                    threats.append(f"Malicious URL domain: {domain}")
        
        # Check suspicious patterns
        text = f"{email_data.get('subject', '')} {body}"
        for pattern in self.patterns:
            if re.search(pattern, text):
                score += 0.15
                threats.append(f"Suspicious pattern: {pattern}")
        
        return ThreatResult(
            score=min(score, 1.0),
            confidence=0.9,
            threats=threats,
            category="domain",
            details={"urls_found": len(urls), "patterns_matched": len(threats)}
        )

class MockThreatIntel(AnalysisProvider):
    """Mock threat intelligence for offline testing"""
    
    async def analyze(self, email_data: Dict) -> ThreatResult:
        # Simple mock - check for obviously bad indicators
        sender = email_data.get('from', '').lower()
        body = email_data.get('body', '').lower()
        
        threats = []
        score = 0.0
        
        # Mock threat intel patterns
        if any(bad in sender for bad in ['phishing', 'scam', 'fake']):
            score += 0.40
            threats.append("Sender matches threat intelligence")
        
        if any(bad in body for bad in ['malware', 'virus', 'exploit']):
            score += 0.35
            threats.append("Content matches threat patterns")
        
        return ThreatResult(
            score=score,
            confidence=0.7,
            threats=threats,
            category="threat_intel",
            details={"mock_analysis": True}
        )

class HybridMailMonitor:
    """Hybrid mail monitor - offline analysis + real Gmail capability"""
    
    def __init__(self, config_file: str = None, offline_mode: bool = False):
        self.offline_mode = offline_mode
        self.config = self._load_config(config_file)
        self.analyzers = self._initialize_analyzers()
        
        # Gmail connection (only in online mode)
        self.mail = None
        if not offline_mode:
            self.username = self.config.get('gmail', {}).get('username')
            self.password = self.config.get('gmail', {}).get('password')
    
    def _load_config(self, config_file: str) -> Dict:
        """Load configuration from YAML or INI"""
        if not config_file:
            return self._default_config()
        
        config_path = Path(config_file)
        if not config_path.exists():
            return self._default_config()
        
        if config_file.endswith('.yml') or config_file.endswith('.yaml'):
            if yaml:
                with open(config_file, 'r') as f:
                    return yaml.safe_load(f)
        else:
            # INI format
            parser = configparser.ConfigParser()
            parser.read(config_file)
            return {
                'gmail': dict(parser['gmail']) if 'gmail' in parser else {},
                'analyzers': {
                    'keyword': {'enabled': True, 'weight': 0.25},
                    'domain': {'enabled': True, 'weight': 0.35},
                    'threat_intel': {'enabled': True, 'weight': 0.40}
                },
                'thresholds': dict(parser['thresholds']) if 'thresholds' in parser else {}
            }
        
        return self._default_config()
    
    def _default_config(self) -> Dict:
        """Default configuration"""
        return {
            'analyzers': {
                'keyword': {
                    'enabled': True,
                    'weight': 0.40,  # Increased weight
                    'keywords': [
                        'urgent', 'verify', 'suspended', 'click here', 'act now',
                        'wire transfer', 'bitcoin', 'cryptocurrency', 'refund'
                    ]
                },
                'domain': {
                    'enabled': True,
                    'weight': 0.35,
                    'domains': ['.tk', '.ml', '.ga', '.cf', '.zip', '.mov'],
                    'patterns': [r'bit\.ly/\w+', r'\d+\.\d+\.\d+\.\d+']
                },
                'threat_intel': {
                    'enabled': True,
                    'weight': 0.25  # Reduced for mock
                }
            },
            'thresholds': {
                'monitor': 0.15,    # Lowered thresholds
                'flag': 0.35,
                'quarantine': 0.55,
                'block': 0.75
            }
        }
    
    def _initialize_analyzers(self) -> Dict[str, AnalysisProvider]:
        """Initialize analysis providers"""
        analyzers = {}
        analyzer_config = self.config.get('analyzers', {})
        
        if analyzer_config.get('keyword', {}).get('enabled', True):
            analyzers['keyword'] = KeywordAnalyzer(analyzer_config['keyword'])
        
        if analyzer_config.get('domain', {}).get('enabled', True):
            analyzers['domain'] = DomainAnalyzer(analyzer_config['domain'])
        
        if analyzer_config.get('threat_intel', {}).get('enabled', True):
            analyzers['threat_intel'] = MockThreatIntel(analyzer_config['threat_intel'])
        
        return analyzers
    
    async def analyze_email(self, email_data: Dict) -> Dict[str, Any]:
        """Analyze email using all providers"""
        
        results = {}
        total_weighted_score = 0.0
        all_threats = []
        
        # Run all analyzers
        for name, analyzer in self.analyzers.items():
            if analyzer.enabled:
                result = await analyzer.analyze(email_data)
                results[name] = {
                    'score': result.score,
                    'confidence': result.confidence,
                    'threats': result.threats,
                    'details': result.details
                }
                
                # Weighted scoring
                weighted_score = result.score * analyzer.weight
                total_weighted_score += weighted_score
                all_threats.extend(result.threats)
        
        # Determine action based on thresholds
        thresholds = self.config.get('thresholds', {})
        if total_weighted_score >= float(thresholds.get('block', 0.9)):
            action = "BLOCK"
        elif total_weighted_score >= float(thresholds.get('quarantine', 0.7)):
            action = "QUARANTINE"
        elif total_weighted_score >= float(thresholds.get('flag', 0.5)):
            action = "FLAG"
        elif total_weighted_score >= float(thresholds.get('monitor', 0.2)):
            action = "MONITOR"
        else:
            action = "ALLOW"
        
        return {
            'email_id': email_data.get('id', 'unknown'),
            'sender': email_data.get('from', ''),
            'subject': email_data.get('subject', ''),
            'total_score': round(total_weighted_score, 3),
            'action': action,
            'threats': all_threats,
            'analyzer_results': results,
            'timestamp': datetime.now().isoformat()
        }
    
    def connect_gmail(self) -> bool:
        """Connect to Gmail (online mode only)"""
        if self.offline_mode:
            return False
        
        try:
            self.mail = imaplib.IMAP4_SSL('imap.gmail.com')
            self.mail.login(self.username, self.password)
            self.mail.select('inbox')
            return True
        except Exception as e:
            print(f"Gmail connection failed: {e}")
            return False
    
    def get_gmail_emails(self, limit: int = 50) -> List[Dict]:
        """Get emails from Gmail (online mode only)"""
        if self.offline_mode or not self.mail:
            return []
        
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
    
    async def scan_emails(self, emails: List[Dict] = None, limit: int = 50) -> List[Dict]:
        """Scan emails (offline data or live Gmail)"""
        
        if emails is None:
            if self.offline_mode:
                # Use test data for offline mode
                emails = self._get_test_emails()
            else:
                # Get from Gmail
                if not self.connect_gmail():
                    return []
                emails = self.get_gmail_emails(limit)
                self.mail.close()
        
        results = []
        for email_data in emails:
            result = await self.analyze_email(email_data)
            results.append(result)
        
        return results
    
    def _get_test_emails(self) -> List[Dict]:
        """Test emails for offline mode"""
        return [
            {
                'id': 'test1',
                'from': 'colleague@company.com',
                'subject': 'Meeting agenda',
                'body': 'Please review the agenda for tomorrow\'s meeting.'
            },
            {
                'id': 'test2',
                'from': 'security@paypaI.com',  # Typosquatting
                'subject': 'URGENT: Account suspended - verify now!',
                'body': 'Click here immediately: https://evil.tk/verify or send bitcoin payment to unlock your account!'
            }
        ]
    
    def save_results(self, results: List[Dict], output_file: str = None) -> str:
        """Save scan results"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"scan_results_v3_{timestamp}.json"
        
        summary = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_emails': len(results),
            'threats_detected': len([r for r in results if r['threats']]),
            'high_risk': len([r for r in results if r['action'] in ['QUARANTINE', 'BLOCK']]),
            'offline_mode': self.offline_mode,
            'results': results
        }
        
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        return output_file

async def main():
    """Hybrid CLI interface"""
    
    if len(sys.argv) < 2:
        print("Mail Monitor v3 - Hybrid System")
        print("Usage:")
        print("  python mailmonitor_v3.py --offline [test_emails]")
        print("  python mailmonitor_v3.py config.ini [limit]")
        print("  python mailmonitor_v3.py config.yml [limit]")
        return 1
    
    # Parse arguments
    if sys.argv[1] == '--offline':
        offline_mode = True
        config_file = None
        limit = 10
    else:
        offline_mode = False
        config_file = sys.argv[1]
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    
    print("MAIL MONITOR V3 - HYBRID ANALYSIS")
    print("=" * 50)
    print(f"Mode: {'OFFLINE' if offline_mode else 'LIVE GMAIL'}")
    
    # Initialize monitor
    monitor = HybridMailMonitor(config_file, offline_mode)
    
    # Run scan
    results = await monitor.scan_emails(limit=limit)
    
    if not results:
        print("No emails to analyze")
        return 1
    
    # Analysis summary
    total = len(results)
    threats = [r for r in results if r['threats']]
    high_risk = [r for r in results if r['action'] in ['QUARANTINE', 'BLOCK']]
    
    print(f"\nScan Results:")
    print(f"  Emails analyzed: {total}")
    print(f"  Threats detected: {len(threats)}")
    print(f"  High risk emails: {len(high_risk)}")
    
    # Action breakdown
    actions = {}
    for result in results:
        action = result['action']
        actions[action] = actions.get(action, 0) + 1
    
    print(f"\nActions:")
    for action, count in sorted(actions.items()):
        print(f"  {action}: {count}")
    
    # Save results
    output_file = monitor.save_results(results)
    print(f"\nResults saved: {output_file}")
    
    # Show critical threats
    critical = [r for r in results if r['action'] == 'BLOCK']
    if critical:
        print(f"\nCRITICAL THREATS:")
        for result in critical:
            print(f"  {result['subject'][:60]} (Score: {result['total_score']})")
    
    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))