#!/usr/bin/env python3
"""
Production test for mail monitor
"""

from mailmonitor import MailMonitor

def test_threat_detection():
    """Test production threat detection"""
    
    monitor = MailMonitor()
    
    # Test safe email
    safe_email = {
        'id': '1',
        'from': 'colleague@company.com', 
        'subject': 'Weekly meeting agenda',
        'body': 'Please review the agenda for our weekly team meeting.'
    }
    
    result = monitor.analyze_threat(safe_email)
    assert result['action'] == 'ALLOW'
    assert result['threat_score'] < 0.2
    print("✅ Safe email test passed")
    
    # Test high-threat email
    threat_email = {
        'id': '2',
        'from': 'security@paypaI.com',  # Typosquatting
        'subject': 'URGENT: Account suspended - verify now!',
        'body': 'Your account will be locked! Click here: https://192.168.1.1/verify?token=abc123 or send bitcoin payment to unlock.'
    }
    
    result = monitor.analyze_threat(threat_email)
    assert result['action'] in ['QUARANTINE', 'BLOCK']
    assert result['threat_score'] >= 0.5
    assert len(result['threats']) > 0
    print("✅ High-threat email test passed")
    
    print("🎉 Production tests passed!")

if __name__ == "__main__":
    test_threat_detection()