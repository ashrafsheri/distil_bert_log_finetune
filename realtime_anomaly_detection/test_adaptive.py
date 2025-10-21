#!/usr/bin/env python3
"""
Test Adaptive Online Learning System
Demonstrates 3-phase detection: warmup → training → full ensemble
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from models.adaptive_detector import AdaptiveEnsembleDetector


def test_adaptive_learning():
    """Test adaptive detector with online learning"""
    print("="*80)
    print("TESTING ADAPTIVE ONLINE LEARNING DETECTOR")
    print("="*80)
    
    # Load detector
    repo_root = Path(__file__).parent.parent
    model_dir = repo_root / 'artifacts/ensemble_model_export'
    
    if not model_dir.exists():
        print(f"❌ Model directory not found: {model_dir}")
        return False
    
    # Initialize adaptive detector with small warmup for testing
    detector = AdaptiveEnsembleDetector(
        model_dir=model_dir,
        warmup_logs=100,  # Small warmup for testing (use 50000 in production)
        window_size=20,
        device='cpu'
    )
    
    print("✓ Adaptive detector initialized\n")
    
    # Phase 1: Warmup - collect baseline (98 normal + 2 attacks)
    print("=" * 70)
    print("PHASE 1: WARMUP (First 100 logs)")
    print("  Active models: Rule-based only")
    print("  Isolation Forest: collecting baseline")
    print("=" * 70)
    print()
    
    # Test logs
    normal_logs = [
        "192.168.1.1 - - [22/Oct/2025:10:30:45 +0000] \"GET / HTTP/1.1\" 200 1234",
        "192.168.1.1 - - [22/Oct/2025:10:30:46 +0000] \"GET /favicon.ico HTTP/1.1\" 200 2345",
        "192.168.1.1 - - [22/Oct/2025:10:30:47 +0000] \"GET /api/users HTTP/1.1\" 200 3456",
    ]
    
    attack_logs = [
        "192.168.1.1 - - [22/Oct/2025:10:30:48 +0000] \"GET /admin' OR '1'='1 HTTP/1.1\" 403 0",
        "192.168.1.1 - - [22/Oct/2025:10:30:49 +0000] \"GET /search?q=<script>alert(1)</script> HTTP/1.1\" 200 1234",
    ]
    
    print("\n" + "="*80)
    print("PHASE 1: WARMUP (First 100 logs)")
    print("="*80)
    print("Active models: Rule-based + Isolation Forest")
    print("Collecting templates for transformer training...\n")
    
    # Simulate 100 logs
    for i in range(98):
        log = normal_logs[i % len(normal_logs)]
        result = detector.detect(log)
        if i % 20 == 0:
            print(f"  [{i+1}/100] Phase: {result['phase']} | Templates: {len(detector.id_to_template)}")
    
    print(f"\n  [98/100] Phase: warmup | Templates: {len(detector.id_to_template)}")
    
    # Process attack logs
    print("\nTesting attacks during warmup:")
    for log in attack_logs:
        result = detector.detect(log)
        status = "🔴 DETECTED" if result['is_anomaly'] else "🟢 MISSED"
        print(f"  {status} - {log[:60]}...")
        if result['is_anomaly']:
            print(f"    Rule: {result['rule_based']['attack_types']}")
    
    print(f"\n  [100/100] ✓ Warmup complete! Templates collected: {len(detector.id_to_template)}")
    
    # Trigger training
    print("\n" + "="*80)
    print("PHASE 2: TRAINING TRANSFORMER")
    print("="*80)
    print("Training in background on collected templates...")
    
    # Process one more log to trigger training
    result = detector.detect(normal_logs[0])
    
    # Wait for training to complete
    import time
    max_wait = 60
    waited = 0
    while detector.training_in_progress and waited < max_wait:
        time.sleep(1)
        waited += 1
        if waited % 5 == 0:
            print(f"  Training... ({waited}s)")
    
    if detector.transformer_ready:
        print(f"\n✓ Training complete!")
        print(f"  Vocabulary: {len(detector.id_to_template)} templates")
        print(f"  Threshold: {detector.transformer_threshold:.4f}")
    else:
        print(f"\n⚠️  Training still in progress after {max_wait}s")
    
    # Phase 3: Full ensemble
    print("\n" + "="*80)
    print("PHASE 3: FULL ENSEMBLE DETECTION")
    print("="*80)
    print("Active models: Rule-based + Isolation Forest + Transformer\n")
    
    print("Testing attacks with full ensemble:")
    for log in attack_logs:
        result = detector.detect(log)
        status = "🔴 DETECTED" if result['is_anomaly'] else "🟢 MISSED"
        score = result['anomaly_score']
        
        print(f"  {status} (score: {score:.3f})")
        print(f"    Log: {log[:70]}...")
        
        if result['is_anomaly']:
            rule = result['rule_based']
            iso = result['isolation_forest']
            trans = result['transformer']
            
            print(f"    Rule-based: {'✓' if rule['is_attack'] else '✗'} {rule.get('attack_types', [])}")
            print(f"    Iso Forest: {'✓' if iso['is_anomaly'] else '✗'} (score: {iso['score']:.2f})")
            if detector.transformer_ready:
                print(f"    Transformer: {'✓' if trans['is_anomaly'] else '✗'} (score: {trans['score']:.2f})")
        print()
    
    print("="*80)
    print("✓ Adaptive online learning test complete!")
    print("="*80)
    
    return True


if __name__ == "__main__":
    test_adaptive_learning()
