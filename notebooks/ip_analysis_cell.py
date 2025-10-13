# IP-Based Anomaly Analysis Cell
# Add this cell after the ensemble detection in notebook 07

# ============================================================================
# IP-LEVEL ANOMALY ANALYSIS
# ============================================================================

print("\n" + "="*80)
print("IP-BASED ANOMALY DETECTION ANALYSIS")
print("="*80)

# 1. IP-Level Statistics
print("\n1. IP-LEVEL STATISTICS")
print("-" * 80)

ip_stats = df.groupby('ip').agg({
    'line_num': 'count',
    'rule_is_attack': 'sum',
    'iso_is_anomaly': 'sum',
    'transformer_is_anomaly': 'sum',
    'ensemble_is_anomaly': 'sum',
    'ip_request_count': 'first',
    'ip_error_rate': 'first',
    'ip_unique_paths': 'first',
    'status': lambda x: (x >= 400).sum()  # Error count
}).rename(columns={
    'line_num': 'total_requests',
    'rule_is_attack': 'rule_attacks',
    'iso_is_anomaly': 'iso_anomalies',
    'transformer_is_anomaly': 'transformer_anomalies',
    'ensemble_is_anomaly': 'ensemble_anomalies',
    'status': 'error_count'
})

# Calculate attack rate per IP
ip_stats['attack_rate'] = ip_stats['ensemble_anomalies'] / ip_stats['total_requests']

# Classify IPs by risk
ip_stats['risk_level'] = pd.cut(
    ip_stats['attack_rate'],
    bins=[-0.01, 0.1, 0.5, 1.01],
    labels=['Low Risk', 'Medium Risk', 'High Risk']
)

print(f"Total unique IPs: {len(ip_stats)}")
print(f"\nRisk distribution:")
print(ip_stats['risk_level'].value_counts())

# 2. Top Anomalous IPs
print("\n\n2. TOP 10 MOST ANOMALOUS IPs")
print("-" * 80)

top_anomalous = ip_stats.sort_values('ensemble_anomalies', ascending=False).head(10)

for idx, (ip, row) in enumerate(top_anomalous.iterrows(), 1):
    print(f"\n#{idx}. IP: {ip} [{row['risk_level']}]")
    print(f"    Total requests:     {int(row['total_requests']):,}")
    print(f"    Ensemble anomalies: {int(row['ensemble_anomalies']):,} ({row['attack_rate']*100:.1f}%)")
    print(f"    Rule-based:         {int(row['rule_attacks']):,}")
    print(f"    Isolation Forest:   {int(row['iso_anomalies']):,}")
    print(f"    Transformer:        {int(row['transformer_anomalies']):,}")
    print(f"    Unique paths:       {int(row['ip_unique_paths']):,}")
    print(f"    Error rate:         {row['ip_error_rate']*100:.1f}%")

# 3. Attack Pattern Analysis
print("\n\n3. IP ATTACK PATTERN ANALYSIS")
print("-" * 80)

# Find IPs with specific attack patterns
print("\nScanning behavior (high unique paths + high error rate):")
scanners = ip_stats[
    (ip_stats['ip_unique_paths'] > ip_stats['ip_unique_paths'].quantile(0.9)) &
    (ip_stats['ip_error_rate'] > 0.5)
].sort_values('ip_unique_paths', ascending=False)

if len(scanners) > 0:
    print(f"  Found {len(scanners)} potential scanners:")
    for ip, row in scanners.head(5).iterrows():
        print(f"    • {ip}: {int(row['ip_unique_paths'])} paths, {row['ip_error_rate']*100:.0f}% errors")
else:
    print("  No scanners detected")

print("\nRequest flooding (very high request count):")
flooders = ip_stats[
    ip_stats['total_requests'] > ip_stats['total_requests'].quantile(0.95)
].sort_values('total_requests', ascending=False)

if len(flooders) > 0:
    print(f"  Found {len(flooders)} potential flooders:")
    for ip, row in flooders.head(5).iterrows():
        print(f"    • {ip}: {int(row['total_requests']):,} requests ({row['attack_rate']*100:.1f}% attacks)")
else:
    print("  No request flooding detected")

print("\nFocused attackers (high attack rate, moderate volume):")
focused_attackers = ip_stats[
    (ip_stats['attack_rate'] > 0.7) &
    (ip_stats['total_requests'] > 10)
].sort_values('attack_rate', ascending=False)

if len(focused_attackers) > 0:
    print(f"  Found {len(focused_attackers)} focused attackers:")
    for ip, row in focused_attackers.head(5).iterrows():
        print(f"    • {ip}: {row['attack_rate']*100:.0f}% attack rate over {int(row['total_requests'])} requests")
else:
    print("  No focused attackers detected")

# 4. Session Timeline for Most Suspicious IP
print("\n\n4. SESSION TIMELINE (Most Suspicious IP)")
print("-" * 80)

if len(top_anomalous) > 0:
    most_suspicious_ip = top_anomalous.index[0]
    print(f"\nIP: {most_suspicious_ip}")
    
    # Get all logs from this IP
    ip_logs = df[df['ip'] == most_suspicious_ip].sort_values('timestamp')
    
    print(f"Session duration: {ip_logs['timestamp'].min()} to {ip_logs['timestamp'].max()}")
    print(f"Total requests: {len(ip_logs)}")
    
    # Show first 10 requests
    print(f"\nFirst 10 requests:")
    for i, (idx, log) in enumerate(ip_logs.head(10).iterrows(), 1):
        marker = "🚨 ATTACK" if log['ensemble_is_anomaly'] else "✓ Normal"
        attack_types = []
        if log['rule_is_attack']:
            attack_types.append(f"Rule:{log.get('rule_attack_type', 'unknown')}")
        if log['iso_is_anomaly']:
            attack_types.append("IsoForest")
        if log['transformer_is_anomaly']:
            attack_types.append("Transformer")
        
        attack_info = f" [{', '.join(attack_types)}]" if attack_types else ""
        
        print(f"  {i:2d}. {marker:<15} {log['method']} {log['path'][:60]:<60} → {log['status']}{attack_info}")
    
    if len(ip_logs) > 10:
        print(f"\n  ... ({len(ip_logs) - 10} more requests)")

# 5. Behavioral Metrics Summary
print("\n\n5. IP BEHAVIORAL METRICS")
print("-" * 80)

print(f"\nRequest volume distribution:")
print(f"  Mean requests/IP:   {ip_stats['total_requests'].mean():.1f}")
print(f"  Median requests/IP: {ip_stats['total_requests'].median():.1f}")
print(f"  Max requests/IP:    {ip_stats['total_requests'].max():.0f}")
print(f"  Std dev:            {ip_stats['total_requests'].std():.1f}")

print(f"\nPath diversity distribution:")
print(f"  Mean unique paths/IP:   {ip_stats['ip_unique_paths'].mean():.1f}")
print(f"  Median unique paths/IP: {ip_stats['ip_unique_paths'].median():.1f}")
print(f"  Max unique paths/IP:    {ip_stats['ip_unique_paths'].max():.0f}")

print(f"\nError rate distribution:")
print(f"  Mean error rate:   {ip_stats['ip_error_rate'].mean()*100:.1f}%")
print(f"  Median error rate: {ip_stats['ip_error_rate'].median()*100:.1f}%")
print(f"  IPs with >50% errors: {(ip_stats['ip_error_rate'] > 0.5).sum()}")

# 6. Detection Method Effectiveness by IP
print("\n\n6. DETECTION METHOD EFFECTIVENESS")
print("-" * 80)

# Calculate which method is most effective per IP
detection_summary = pd.DataFrame({
    'Rule-based only': ((ip_stats['rule_attacks'] > 0) & 
                        (ip_stats['iso_anomalies'] == 0) & 
                        (ip_stats['transformer_anomalies'] == 0)).sum(),
    'IsoForest only': ((ip_stats['rule_attacks'] == 0) & 
                       (ip_stats['iso_anomalies'] > 0) & 
                       (ip_stats['transformer_anomalies'] == 0)).sum(),
    'Transformer only': ((ip_stats['rule_attacks'] == 0) & 
                         (ip_stats['iso_anomalies'] == 0) & 
                         (ip_stats['transformer_anomalies'] > 0)).sum(),
    'Multiple methods': ((ip_stats['rule_attacks'] > 0).astype(int) + 
                         (ip_stats['iso_anomalies'] > 0).astype(int) + 
                         (ip_stats['transformer_anomalies'] > 0).astype(int) > 1).sum(),
    'All three methods': ((ip_stats['rule_attacks'] > 0) & 
                          (ip_stats['iso_anomalies'] > 0) & 
                          (ip_stats['transformer_anomalies'] > 0)).sum()
}, index=['IPs detected']).T

print(detection_summary)

print("\n" + "="*80)
print("IP-BASED ANALYSIS COMPLETE")
print("="*80)

# Store results for later use
ip_analysis_results = {
    'ip_stats': ip_stats,
    'top_anomalous': top_anomalous,
    'scanners': scanners,
    'flooders': flooders,
    'focused_attackers': focused_attackers
}
