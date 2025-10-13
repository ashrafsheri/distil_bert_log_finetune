# IP-Based Anomaly Detection Analysis

## Current Implementation Review

### ✅ **YES - The System DOES Perform IP-Based Anomaly Detection**

The current hybrid attack detection system has **THREE layers** of IP-based anomaly detection:

---

## 1. Statistical Feature Engineering (Isolation Forest)

**Location**: Section 3 - Feature Engineering

**IP-Based Features Extracted**:

```python
# Per-IP aggregated statistics
ip_stats = df.groupby('ip').agg({
    'line_num': 'count',        # Total request count per IP
    'status': lambda x: (x >= 400).sum(),  # Error count per IP  
    'path': 'nunique',          # Unique paths accessed per IP
})

# Computed features:
- ip_request_count     # How many requests from this IP
- ip_error_count       # How many errors from this IP
- ip_unique_paths      # How many different paths accessed
- ip_error_rate        # Error rate (errors/requests)
```

**What It Detects**:
- ✅ **Request spam**: High `ip_request_count` indicates flooding/DDoS
- ✅ **Error-prone IPs**: High `ip_error_rate` indicates scanning/probing
- ✅ **Scanning behavior**: High `ip_unique_paths` indicates reconnaissance
- ✅ **Statistical outliers**: Isolation Forest flags IPs with unusual behavioral patterns

**Example Anomalies Caught**:
- IP with 1000+ requests (normal: 10-50) → Likely DDoS/spam
- IP with 80% error rate (normal: 5-10%) → Likely scanner
- IP accessing 200+ unique paths (normal: 5-20) → Likely reconnaissance

---

## 2. Transformer Sequence Modeling (Session-Based)

**Location**: Section 4 - Transformer Detection

**How It Works**:

```python
# Groups logs by IP address (treats each IP as a session)
for ip, group in df_sorted.groupby('ip'):
    templates = group['template_id'].tolist()
    
    # Creates sequences of requests from the same IP
    for i in range(0, len(templates) - 1, STRIDE):
        window = templates[i:i + WINDOW_SIZE]  # 20 consecutive requests
        sequences.append(window)
```

**IP-Based Detection**:
- ✅ **Session anomalies**: Detects unusual request patterns from same IP
- ✅ **Attack sequences**: Identifies attack chains (e.g., SQL injection attempts)
- ✅ **Behavioral shifts**: Detects when an IP changes behavior mid-session
- ✅ **Temporal patterns**: Catches rapid-fire requests or slow scans

**What Makes It IP-Aware**:
1. **Groups by IP** - Each sequence is from a single IP's activity
2. **Temporal ordering** - Preserves request order within IP session
3. **Context-aware** - Model learns normal vs abnormal IP behavior patterns
4. **Session continuity** - 20-request sliding window captures attack chains

**Example Anomalies Caught**:
- IP starts with normal requests, then sudden SQL injection attempts
- IP rapidly iterating through paths (e.g., `/user/1`, `/user/2`, ..., `/user/100`)
- IP alternating between different attack types (XSS → SQLi → Path Traversal)

---

## 3. Rule-Based Detection (Content-Based)

**Location**: Section 2 - Rule-Based Detection

**IP Context**:
While rule-based detection focuses on request content (SQL, XSS, etc.), it's applied **per-request** which means:
- Each detection is tagged with the source IP
- Results can be aggregated by IP to identify malicious IPs
- Used in ensemble to flag IPs with attack signatures

---

## IP-Based Anomaly Detection Capabilities Summary

### Current Capabilities ✅

| Anomaly Type | Detection Method | Confidence |
|-------------|------------------|------------|
| **Request spam/flooding** | Isolation Forest (`ip_request_count`) | High |
| **DDoS from single IP** | Isolation Forest (high request volume) | High |
| **Scanning/probing** | Isolation Forest (`ip_unique_paths`, `ip_error_rate`) | High |
| **Brute force attacks** | Transformer (repeated failed auth patterns) | Medium-High |
| **Attack sequences** | Transformer (session-based modeling) | High |
| **Behavioral anomalies** | Transformer + Isolation Forest | High |
| **Error-prone IPs** | Isolation Forest (`ip_error_rate`) | High |
| **Path enumeration** | Isolation Forest + Transformer | Medium-High |
| **Session hijacking** | Transformer (sudden behavior change) | Medium |
| **Distributed attacks** | Limited (single-IP focused) | Low |

### What It DOES Detect

✅ **Single-IP Attack Patterns**:
- Spam/flooding from one IP
- Scanning behavior (accessing many paths)
- Attack sequences (SQLi → XSS → Path Traversal)
- Error-prone IPs (failed login attempts, 404s)
- Unusual request volumes
- Abnormal path access patterns
- Rapid-fire requests
- Session-based anomalies

### What It DOES NOT Detect (Limitations)

❌ **Multi-IP Coordinated Attacks**:
- Distributed DDoS (attack from 1000 different IPs)
- Coordinated scanning (different IPs scanning different parts)
- IP rotation attacks (attacker switches IPs frequently)

❌ **Cross-IP Patterns**:
- Same attack signature from multiple IPs (requires aggregation)
- IP reputation (no external threat feeds)
- Geolocation-based anomalies (IP from unusual country)

---

## Examples of IP-Based Detections

### Example 1: Request Spam Detection

```
IP: 192.168.1.100
Requests: 1,247 (normal: 10-50)
Unique paths: 12
Error rate: 5%

Detection:
- Isolation Forest: ANOMALY (high ip_request_count)
- Reason: Request spam / potential DDoS
- Confidence: High
```

### Example 2: Scanner Detection

```
IP: 10.0.0.55
Requests: 234
Unique paths: 189 (normal: 5-20)
Error rate: 73% (mostly 404s)

Detection:
- Isolation Forest: ANOMALY (high ip_unique_paths, high ip_error_rate)
- Transformer: ANOMALY (unusual request sequence pattern)
- Reason: Web scanner / reconnaissance
- Confidence: Very High
```

### Example 3: Brute Force Attack

```
IP: 172.16.0.99
Requests: 456
Unique paths: 1 (/login)
Error rate: 99% (all 401 Unauthorized)

Detection:
- Isolation Forest: ANOMALY (extreme ip_error_rate, low diversity)
- Transformer: ANOMALY (repetitive failed auth pattern)
- Reason: Brute force attack on /login
- Confidence: Very High
```

### Example 4: Attack Sequence

```
IP: 203.0.113.42
Request sequence:
1. GET /products?id=1 HTTP/1.1 200
2. GET /products?id=2 HTTP/1.1 200
3. GET /products?id=' OR '1'='1 HTTP/1.1 500  ← SQL injection attempt
4. GET /products?id=' UNION SELECT NULL-- HTTP/1.1 500
5. GET /products?id=<script>alert(1)</script> HTTP/1.1 400  ← XSS attempt

Detection:
- Rule-based: ATTACK (SQL injection + XSS signatures)
- Transformer: ANOMALY (sudden shift from normal to attack patterns)
- Reason: Multi-stage attack from same IP
- Confidence: Very High
```

---

## How to Analyze IP-Based Anomalies

### Check IP-Level Statistics

```python
# Get IP-level anomaly summary
ip_summary = df.groupby('ip').agg({
    'rule_is_attack': 'sum',
    'iso_is_anomaly': 'sum',
    'transformer_is_anomaly': 'sum',
    'ensemble_is_anomaly': 'sum',
    'ip_request_count': 'first',
    'ip_error_rate': 'first',
    'ip_unique_paths': 'first'
}).sort_values('ensemble_is_anomaly', ascending=False)

print("Top 10 most anomalous IPs:")
print(ip_summary.head(10))
```

### Identify Attack IPs

```python
# Find IPs with high attack rates
attack_ips = df.groupby('ip').agg({
    'ensemble_is_anomaly': ['sum', 'count']
})
attack_ips.columns = ['attacks', 'total_requests']
attack_ips['attack_rate'] = attack_ips['attacks'] / attack_ips['total_requests']

# IPs with >50% attack rate
malicious_ips = attack_ips[attack_ips['attack_rate'] > 0.5]
print(f"Potentially malicious IPs: {len(malicious_ips)}")
```

### Analyze IP Request Patterns

```python
# Get full session history for a specific IP
suspicious_ip = '192.168.1.100'
ip_logs = df[df['ip'] == suspicious_ip].sort_values('timestamp')

print(f"Session analysis for {suspicious_ip}:")
print(f"  Total requests: {len(ip_logs)}")
print(f"  Time span: {ip_logs['timestamp'].max() - ip_logs['timestamp'].min()}")
print(f"  Unique paths: {ip_logs['path'].nunique()}")
print(f"  Attack requests: {ip_logs['ensemble_is_anomaly'].sum()}")
print(f"\nRequest timeline:")
for i, row in ip_logs.iterrows():
    marker = "🚨" if row['ensemble_is_anomaly'] else "✓"
    print(f"  {marker} [{row['timestamp']}] {row['method']} {row['path']} → {row['status']}")
```

---

## Enhancing IP-Based Detection

### Recommended Additions

#### 1. **IP Reputation Scoring**

```python
# Add IP reputation score based on historical behavior
ip_reputation = df.groupby('ip').agg({
    'ensemble_is_anomaly': 'sum',  # Total attacks
    'line_num': 'count'  # Total requests
}).rename(columns={'ensemble_is_anomaly': 'attack_count', 'line_num': 'total_count'})

ip_reputation['reputation_score'] = 1 - (ip_reputation['attack_count'] / ip_reputation['total_count'])
ip_reputation['risk_level'] = pd.cut(
    ip_reputation['reputation_score'],
    bins=[0, 0.3, 0.7, 1.0],
    labels=['High Risk', 'Medium Risk', 'Low Risk']
)

df = df.merge(ip_reputation[['reputation_score', 'risk_level']], left_on='ip', right_index=True)
```

#### 2. **Request Rate Analysis**

```python
# Detect rapid-fire requests (potential DDoS)
df['time_diff'] = df.groupby('ip')['timestamp'].diff().dt.total_seconds()

# Flag IPs with many requests in <1 second
rapid_requests = df[df['time_diff'] < 1.0].groupby('ip').size()
ddos_ips = rapid_requests[rapid_requests > 10].index.tolist()

print(f"Potential DDoS sources: {ddos_ips}")
```

#### 3. **Multi-IP Correlation**

```python
# Detect distributed attacks (same pattern from multiple IPs)
from sklearn.cluster import DBSCAN

# Extract attack signature features
attack_logs = df[df['ensemble_is_anomaly'] == 1]
attack_features = attack_logs[['path_length', 'path_depth', 'has_suspicious_chars']]

# Cluster similar attacks
clustering = DBSCAN(eps=0.5, min_samples=5).fit(attack_features)
attack_logs['attack_cluster'] = clustering.labels_

# Find distributed attack campaigns
for cluster_id in set(clustering.labels_):
    if cluster_id == -1:  # Noise
        continue
    cluster_ips = attack_logs[attack_logs['attack_cluster'] == cluster_id]['ip'].unique()
    if len(cluster_ips) > 5:  # Multiple IPs with same attack pattern
        print(f"Distributed attack cluster {cluster_id}: {len(cluster_ips)} IPs")
```

---

## Conclusion

**YES**, the current system performs comprehensive IP-based anomaly detection through:

1. **Statistical Analysis** (Isolation Forest) - Detects volume, error rate, and path diversity anomalies
2. **Sequence Modeling** (Transformer) - Detects behavioral and temporal anomalies within IP sessions
3. **Rule Matching** (Signatures) - Detects content-based attacks tied to IPs

**Strengths**:
- Strong single-IP anomaly detection
- Session-based behavioral analysis
- Multi-method ensemble approach

**Limitations**:
- Limited multi-IP correlation
- No IP reputation/geolocation
- Not optimized for distributed attacks

**For enhanced IP-based detection**, consider adding the reputation scoring, rate analysis, and multi-IP correlation enhancements described above.
