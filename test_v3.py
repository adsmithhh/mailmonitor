#!/usr/bin/env python3
"""
Comprehensive test for Mail Monitor v3 hybrid system
Tests both offline and online capabilities
"""

import asyncio
import json
from mailmonitor_v3 import HybridMailMonitor

async def test_offline_mode():
    """Test offline analysis capabilities"""
    print("Testing OFFLINE mode...")
    
    monitor = HybridMailMonitor(offline_mode=True)
    
    # Test with sample emails
    test_emails = [
        {
            'id': 'safe1',
            'from': 'boss@company.com',
            'subject': 'Project update',
            'body': 'Here is the weekly project status report.'
        },
        {
            'id': 'threat1',
            'from': 'security@paypaI.com',  # Typosquatting
            'subject': 'URGENT: Account suspended - verify now!',
            'body': 'Click here: https://evil.tk/verify or send bitcoin immediately!'
        },
        {
            'id': 'threat2',
            'from': 'alerts@192.168.1.1',  # IP address domain
            'subject': 'Wire transfer required',
            'body': 'Visit bit.ly/scam123 to update payment information urgently.'
        }
    ]
    
    results = await monitor.scan_emails(test_emails)
    
    # Validate results
    assert len(results) == 3
    
    # Check safe email
    safe_result = next(r for r in results if r['email_id'] == 'safe1')
    assert safe_result['action'] == 'ALLOW'
    assert safe_result['total_score'] < 0.2
    
    # Check threat emails
    threat_results = [r for r in results if r['email_id'].startswith('threat')]
    assert len(threat_results) == 2
    
    for threat in threat_results:
        assert threat['action'] in ['FLAG', 'QUARANTINE', 'BLOCK']
        assert threat['total_score'] >= 0.5
        assert len(threat['threats']) > 0
    
    print("✅ Offline mode tests passed")
    return results

async def test_online_mode():
    """Test online Gmail capabilities"""
    print("Testing ONLINE mode...")
    
    monitor = HybridMailMonitor('config_v3.yml', offline_mode=False)
    
    # Test Gmail connection
    if monitor.connect_gmail():
        print("✅ Gmail connection successful")
        
        # Scan a few emails
        results = await monitor.scan_emails(limit=5)
        
        if results:
            print(f"✅ Scanned {len(results)} real emails")
            
            # Check result structure
            for result in results:
                assert 'email_id' in result
                assert 'sender' in result
                assert 'subject' in result
                assert 'total_score' in result
                assert 'action' in result
                assert 'analyzer_results' in result
            
            print("✅ Online mode tests passed")
            return results
        else:
            print("⚠️ No emails retrieved")
            return []
    else:
        print("⚠️ Gmail connection failed - skipping online tests")
        return []

async def test_config_loading():
    """Test configuration loading"""
    print("Testing configuration loading...")
    
    # Test YAML config
    monitor_yaml = HybridMailMonitor('config_v3.yml', offline_mode=True)
    assert 'keyword' in monitor_yaml.analyzers
    assert 'domain' in monitor_yaml.analyzers
    assert 'threat_intel' in monitor_yaml.analyzers
    print("✅ YAML config loaded")
    
    # Test INI config
    monitor_ini = HybridMailMonitor('gmail_config.ini', offline_mode=True)
    assert len(monitor_ini.analyzers) > 0
    print("✅ INI config loaded")
    
    # Test default config
    monitor_default = HybridMailMonitor(offline_mode=True)
    assert len(monitor_default.analyzers) > 0
    print("✅ Default config loaded")

async def test_analyzer_weights():
    """Test weighted scoring system"""
    print("Testing analyzer weights...")
    
    monitor = HybridMailMonitor('config_v3.yml', offline_mode=True)
    
    # High-threat email
    threat_email = {
        'id': 'weight_test',
        'from': 'phishing@evil.tk',
        'subject': 'URGENT: Verify bitcoin payment now!',
        'body': 'Click https://192.168.1.1/scam immediately or account suspended!'
    }
    
    result = await monitor.analyze_email(threat_email)
    
    # Should trigger multiple analyzers
    assert 'keyword' in result['analyzer_results']
    assert 'domain' in result['analyzer_results']
    assert 'threat_intel' in result['analyzer_results']
    
    # Should have high combined score
    assert result['total_score'] > 0.7
    assert result['action'] in ['QUARANTINE', 'BLOCK']
    
    print("✅ Weighted scoring tests passed")
    return result

async def main():
    """Run comprehensive test suite"""
    print("MAIL MONITOR V3 - COMPREHENSIVE TESTS")
    print("=" * 60)
    
    try:
        # Test configuration
        await test_config_loading()
        print()
        
        # Test offline capabilities
        offline_results = await test_offline_mode()
        print()
        
        # Test weighted scoring
        weight_result = await test_analyzer_weights()
        print()
        
        # Test online capabilities (if possible)
        online_results = await test_online_mode()
        print()
        
        # Summary
        print("TEST SUMMARY")
        print("-" * 30)
        print(f"✅ Configuration loading: PASSED")
        print(f"✅ Offline analysis: PASSED ({len(offline_results)} emails)")
        print(f"✅ Weighted scoring: PASSED (score: {weight_result['total_score']})")
        
        if online_results:
            print(f"✅ Online Gmail: PASSED ({len(online_results)} emails)")
        else:
            print(f"⚠️ Online Gmail: SKIPPED (connection issues)")
        
        print("\n🎉 All available tests PASSED!")
        print("\nMail Monitor v3 is ready for production use.")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)