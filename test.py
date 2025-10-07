#!/usr/bin/env python3
"""
Simple test for mailmonitor - no fancy frameworks
"""

from mailmonitor import SimpleMailMonitor

def test_threat_detection():
    """Test basic threat detection"""
    
    monitor = SimpleMailMonitor("test@test.com", "test")
    
    # Test safe email
    safe_email = {
        'id': '1',
        'from': 'friend@gmail.com', 
        'subject': 'Meeting tomorrow',
        'body': 'Hi, let\'s meet at the coffee shop tomorrow at 2pm.'
    }
    
    result = monitor.scan_email(safe_email)
    assert result['action'] == 'ALLOW'
    assert result['risk_score'] < 20
    print("✅ Safe email test passed")
    
    # Test suspicious email
    threat_email = {
        'id': '2',
        'from': 'noreply@suspicious.tk',
        'subject': 'URGENT: Verify your account now!',
        'body': 'Click here immediately: http://evil.zip/verify or your account will be suspended!'
    }
    
    result = monitor.scan_email(threat_email)
    assert result['action'] in ['QUARANTINE', 'BLOCK']
    assert result['risk_score'] >= 60
    assert len(result['threats']) > 0
    print("✅ Threat email test passed")
    
    print("\n🎉 All tests passed!")

if __name__ == "__main__":
    test_threat_detection()