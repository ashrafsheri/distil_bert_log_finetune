#!/usr/bin/env python3
"""
Quick test script for the real-time anomaly detection system
Tests both API and standalone detector
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from models.ensemble_detector import EnsembleAnomalyDetector


def test_standalone():
    """Test standalone detector"""
    print("="*80)
    print("TESTING STANDALONE DETECTOR")
    print("="*80)
    
    # Load detector
    repo_root = Path(__file__).parent.parent
    model_dir = repo_root / 'artifacts/ensemble_model_export'
    
    if not model_dir.exists():
        print(f"❌ Model directory not found: {model_dir}")
        print("Please run notebook 07 to export the models first.")
        return False
    
    detector = EnsembleAnomalyDetector(model_dir=model_dir, window_size=20, device='cpu')
    
    # Test cases
    test_logs = [
        # Normal logs
        "192.168.1.1 - - [22/Oct/2025:10:30:45 +0000] \"GET / HTTP/1.1\" 200 1234",
        "192.168.1.1 - - [22/Oct/2025:10:30:46 +0000] \"GET /favicon.ico HTTP/1.1\" 200 2345",
        "192.168.1.1 - - [22/Oct/2025:10:30:47 +0000] \"GET /api/users HTTP/1.1\" 200 3456",
        
        # Attack logs
        "192.168.1.1 - - [22/Oct/2025:10:30:48 +0000] \"GET /admin' OR '1'='1 HTTP/1.1\" 403 0",
        "192.168.1.1 - - [22/Oct/2025:10:30:49 +0000] \"GET /search?q=<script>alert(1)</script> HTTP/1.1\" 200 1234",
        "192.168.1.1 - - [22/Oct/2025:10:30:50 +0000] \"GET /../../../etc/passwd HTTP/1.1\" 403 0",
    ]
    
    print("\nTesting detection on sample logs:\n")
    
    for i, log_line in enumerate(test_logs, 1):
        result = detector.detect(log_line)
        
        is_anomaly = result['is_anomaly']
        score = result['anomaly_score']
        
        status = "🔴 ANOMALY" if is_anomaly else "🟢 NORMAL"
        
        print(f"{i}. {status} (score: {score:.3f})")
        print(f"   Log: {log_line[:80]}")
        
        if is_anomaly:
            rule = result['rule_based']
            if rule['is_attack']:
                print(f"   Rule-based: {rule['attack_types']}")
            
            iso = result['isolation_forest']
            if iso['is_anomaly']:
                print(f"   Isolation Forest: {iso['score']:.4f}")
            
            trans = result['transformer']
            if trans['is_anomaly']:
                print(f"   Transformer: {trans['score']:.4f}")
        
        print()
    
    print("✓ Standalone detector test complete!\n")
    return True


def test_api():
    """Test API connectivity"""
    import requests
    
    print("="*80)
    print("TESTING API")
    print("="*80)
    
    api_url = "http://localhost:8000"
    
    # Check if API is running
    try:
        response = requests.get(f"{api_url}/health", timeout=2)
        if response.status_code == 200:
            print("✓ API is running and healthy!")
            data = response.json()
            print(f"  Vocabulary size: {data['vocab_size']:,}")
            print(f"  Threshold: {data['threshold']:.4f}")
            return True
        else:
            print(f"❌ API returned error: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ API is not running")
        print("\nTo start the API:")
        print("  cd realtime_anomaly_detection/api")
        print("  python server.py")
        return False
    except Exception as e:
        print(f"❌ Error connecting to API: {e}")
        return False


def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("REAL-TIME ANOMALY DETECTION SYSTEM - TEST SUITE")
    print("="*80 + "\n")
    
    # Test standalone detector
    standalone_ok = test_standalone()
    
    # Test API
    api_ok = test_api()
    
    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    print(f"  Standalone Detector: {'✓ PASS' if standalone_ok else '✗ FAIL'}")
    print(f"  API Server: {'✓ PASS' if api_ok else '✗ FAIL'}")
    print("="*80 + "\n")
    
    if standalone_ok and api_ok:
        print("🎉 All tests passed! System is ready for real-time streaming.")
        print("\nNext steps:")
        print("  cd realtime_anomaly_detection/streaming")
        print("  python log_streamer.py --log-file ../../data/apache_logs/synthetic_nodejs_apache_10k.log")
    elif standalone_ok:
        print("⚠️  Detector works but API is not running.")
        print("\nTo start the API:")
        print("  cd realtime_anomaly_detection/api")
        print("  python server.py")
    else:
        print("❌ Tests failed. Please check the model files exist in:")
        print("  artifacts/ensemble_model_export/")


if __name__ == "__main__":
    main()
