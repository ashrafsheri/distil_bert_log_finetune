# How the Transformer Anomaly Detection Works

## Overview

The transformer model learns **normal patterns** in log sequences during training, then detects **deviations from those patterns** during inference. It treats logs as a language and predicts what should come next.

---

## 🧠 Core Concept: Template-Based Sequence Modeling

### Step 1: Log → Template Conversion

Each log is converted to a **template ID** by normalizing it:

```python
# Original log:
"192.168.1.1 - - [27/Oct/2025:10:00:00 +0000] "GET /api/users/123 HTTP/1.1" 200 450"

# Converted to message:
"GET /api/users/123 HTTP/1.1 200"

# Normalized to template:
"GET /api/users/<NUM> HTTP/1.1 <NUM>"  ← Template ID: 5

# Another log:
"GET /api/users/456 HTTP/1.1 200"
# Same template! → Also ID: 5
```

**Normalization rules:**
- Numbers → `<NUM>`
- IP addresses → `<IP>`
- Hex strings → `<HEX>`
- UUIDs → `<UUID>`
- Dates → `<DATE>`
- Times → `<TIME>`

### Step 2: Build Sequences

For each session (user/IP), we maintain a sliding window of templates:

```python
Session: 192.168.1.100
Window size: 20

Sequence: [5, 5, 5, 12, 12, 7, 5, 5, ...]
          ↑  ↑  ↑   ↑   ↑   ↑
          GET /api/users (repeated)
                      GET /api/profile
                                GET /api/data
```

### Step 3: Training Phase (First 50,000 logs)

The transformer learns to **predict the next template** in a sequence:

```
Training example:
Input:  [5, 5, 12, 12, ?, ?, ?, ...]
Target: [5, 12, 12, 7, ?, ?, ?, ...]
         ↑   ↑   ↑   ↑
         Learn: After 5→5, expect 12
                After 5→12, expect 12
                After 12→12, expect 7
```

**What it learns:**
- Common request patterns (e.g., login → profile → data)
- Typical user workflows
- Normal navigation sequences
- Expected error patterns

### Step 4: Scoring Phase (After Training)

For each new sequence, calculate **Negative Log-Likelihood (NLL)**:

```
Given sequence: [5, 5, 12]

Transformer predicts probabilities:
Position 0 → Position 1: P(5 after 5) = 0.8 (high - normal!)
Position 1 → Position 2: P(12 after 5,5) = 0.6 (medium - ok)

NLL = -log(0.8) + -log(0.6) = 0.22 + 0.51 = 0.73 (LOW SCORE)
```

**Lower NLL = Normal behavior** (model expected this)
**Higher NLL = Anomalous behavior** (model surprised by this)

---

## 🚨 What Makes a Sequence Anomalous?

### Example 1: Unexpected Template in Context

**Normal Training Pattern:**
```
User workflow: Login → Profile → Settings → Logout
Template IDs: [3, 7, 9, 15]  ← Seen 1000+ times during training
```

**Anomalous Sequence:**
```
User workflow: Login → Profile → /etc/passwd → Logout
Template IDs: [3, 7, 42, 15]
                      ↑
              Never seen template 42 in this context!
              
NLL = -log(0.9) + -log(0.85) + -log(0.001) + -log(0.7)
    = 0.10 + 0.16 + 6.91 + 0.36 = 7.53 (HIGH SCORE!)
                    ↑
            Model gives very low probability to template 42
            appearing after [3, 7]
```

### Example 2: Unusual Sequence Order

**Normal Training Pattern:**
```
API workflow: GET /api/data → GET /api/details → POST /api/update
Template IDs: [5, 8, 11]  ← Common workflow
```

**Anomalous Sequence:**
```
Attack workflow: POST /api/update → GET /api/data → POST /api/update → POST /api/update
Template IDs: [11, 5, 11, 11]
              ↑        ↑    ↑
         Starts with POST (unusual)
                 Back to GET (weird)
                      Repeated POSTs (suspicious)

NLL = -log(0.2) + -log(0.3) + -log(0.1) + -log(0.15)
    = 1.61 + 1.20 + 2.30 + 1.90 = 7.01 (HIGH SCORE!)
```

### Example 3: Rapid Context Switching

**Normal Training Pattern:**
```
Typical user session (template IDs):
[5, 5, 5, 7, 7, 9, 9, 5, 5]
 ↑     ↑     ↑     ↑  
 GET /api/users (browsing)
       GET /api/profile
             GET /api/settings
                   Back to users (normal navigation)
```

**Anomalous Sequence:**
```
Scanning behavior:
[5, 12, 18, 24, 31, 42, 55, 67, 73, 88, 91, 103, ...]
 ↑   ↑   ↑   ↑   ↑   ↑
 All different templates in rapid succession
 No pattern the model recognizes
 
NLL = Sum of all -log(P_i) where each P_i is low
    = 1.5 + 2.1 + 2.8 + 3.2 + 2.9 + 3.5 + ... = 18.4 (VERY HIGH!)
```

### Example 4: Error Escalation

**Normal Training Pattern:**
```
Occasional errors are normal:
[5, 5, 5, 5, 18(404), 5, 5, 5]  ← Single 404 is OK
```

**Anomalous Sequence:**
```
Brute force / enumeration:
[18(404), 18(404), 18(404), 18(404), 18(404), 18(404), 18(404), ...]
 ↑        ↑        ↑        ↑
 Repeated failures - never seen in training!
 
NLL = -log(0.1) + -log(0.05) + -log(0.02) + -log(0.01) + ...
    = 2.30 + 3.00 + 3.91 + 4.61 + ... = 13.82 (VERY HIGH!)
```

---

## 📊 Concrete Examples with Real Logs

### Normal Sequence (Low Score)

```nginx
192.168.1.100 - - [27/Oct/2025:10:00:00 +0000] "GET /api/users HTTP/1.1" 200 450
192.168.1.100 - - [27/Oct/2025:10:00:01 +0000] "GET /api/users HTTP/1.1" 200 450
192.168.1.100 - - [27/Oct/2025:10:00:02 +0000] "GET /api/profile HTTP/1.1" 200 320
192.168.1.100 - - [27/Oct/2025:10:00:03 +0000] "GET /api/data HTTP/1.1" 200 1200
192.168.1.100 - - [27/Oct/2025:10:00:04 +0000] "POST /api/update HTTP/1.1" 200 150
```

**Template sequence:** `[5, 5, 7, 12, 11]`

**Transformer prediction:**
- After [5]: Next is probably 5 or 7 (browsing) → **P=0.85** ✅
- After [5,5]: Next is probably 7 (profile) → **P=0.78** ✅
- After [5,5,7]: Next is 12 (data) → **P=0.82** ✅
- After [5,5,7,12]: Next is 11 (update) → **P=0.75** ✅

**NLL Score:** ~0.9 (Very low - normal behavior)

---

### Anomalous Sequence 1: SQL Injection Attack (High Score)

```nginx
192.168.1.200 - - [27/Oct/2025:10:05:00 +0000] "GET /api/login HTTP/1.1" 200 450
192.168.1.200 - - [27/Oct/2025:10:05:01 +0000] "GET /api/search?q=' OR 1=1-- HTTP/1.1" 403 120
192.168.1.200 - - [27/Oct/2025:10:05:02 +0000] "GET /api/search?q='; DROP TABLE-- HTTP/1.1" 403 120
192.168.1.200 - - [27/Oct/2025:10:05:03 +0000] "GET /api/search?q=admin'-- HTTP/1.1" 403 120
```

**Template sequence:** `[3, 42, 42, 42]`
- Template 42: `GET /api/search?q=<*> HTTP/1.1 <NUM>`

**Transformer prediction:**
- After [3]: Next is probably 7 (profile) → Sees 42 → **P=0.01** ❌
- After [3,42]: Next should be different → Sees 42 again → **P=0.05** ❌
- After [3,42,42]: Model very confused → **P=0.02** ❌

**NLL Score:** ~8.5 (Very high - anomalous!)

---

### Anomalous Sequence 2: Directory Traversal (High Score)

```nginx
192.168.1.201 - - [27/Oct/2025:10:10:00 +0000] "GET /api/data HTTP/1.1" 200 1200
192.168.1.201 - - [27/Oct/2025:10:10:01 +0000] "GET /api/../etc/passwd HTTP/1.1" 403 50
192.168.1.201 - - [27/Oct/2025:10:10:02 +0000] "GET /api/../../etc/shadow HTTP/1.1" 403 50
192.168.1.201 - - [27/Oct/2025:10:10:03 +0000] "GET /api/../../../root/.ssh HTTP/1.1" 403 50
```

**Template sequence:** `[12, 67, 68, 69]`
- Templates 67, 68, 69: Path traversal patterns (VERY RARE in training)

**Transformer prediction:**
- After [12]: Next is usually 5 or 11 → Sees 67 → **P=0.001** ❌
- After [12,67]: Never seen this → Sees 68 → **P=0.002** ❌
- After [12,67,68]: Completely unfamiliar → **P=0.001** ❌

**NLL Score:** ~12.8 (Extremely high - definite attack!)

---

### Anomalous Sequence 3: Port Scanning Behavior (High Score)

```nginx
192.168.1.202 - - [27/Oct/2025:10:15:00 +0000] "GET /api/admin HTTP/1.1" 403 120
192.168.1.202 - - [27/Oct/2025:10:15:01 +0000] "GET /api/config HTTP/1.1" 403 120
192.168.1.202 - - [27/Oct/2025:10:15:02 +0000] "GET /api/backup HTTP/1.1" 403 120
192.168.1.202 - - [27/Oct/2025:10:15:03 +0000] "GET /api/debug HTTP/1.1" 403 120
192.168.1.202 - - [27/Oct/2025:10:15:04 +0000] "GET /api/test HTTP/1.1" 403 120
192.168.1.202 - - [27/Oct/2025:10:15:05 +0000] "GET /api/dev HTTP/1.1" 403 120
```

**Template sequence:** `[15, 18, 22, 28, 31, 35]`
- All different templates, all 403 errors

**Transformer prediction:**
- Rapid switching between many different endpoints → **Low probabilities**
- Consistent 403 pattern → **Never seen in training**
- No coherent workflow → **Model confused**

**NLL Score:** ~10.2 (Very high - enumeration attack!)

---

### Anomalous Sequence 4: Credential Stuffing (High Score)

```nginx
192.168.1.203 - - [27/Oct/2025:10:20:00 +0000] "POST /api/login HTTP/1.1" 401 80
192.168.1.203 - - [27/Oct/2025:10:20:01 +0000] "POST /api/login HTTP/1.1" 401 80
192.168.1.203 - - [27/Oct/2025:10:20:02 +0000] "POST /api/login HTTP/1.1" 401 80
192.168.1.203 - - [27/Oct/2025:10:20:03 +0000] "POST /api/login HTTP/1.1" 401 80
192.168.1.203 - - [27/Oct/2025:10:20:04 +0000] "POST /api/login HTTP/1.1" 401 80
192.168.1.203 - - [27/Oct/2025:10:20:05 +0000] "POST /api/login HTTP/1.1" 200 450
```

**Template sequence:** `[24(401), 24(401), 24(401), 24(401), 24(401), 3(200)]`
- Template 24: `POST /api/login HTTP/1.1 <NUM>` (401)
- Template 3: `POST /api/login HTTP/1.1 <NUM>` (200)

**Transformer prediction:**
- Repeated failures → **P decreases with each failure**
- Normal users don't fail 5 times in a row
- After [24]: P(24 again) = 0.3 (ok, maybe mistyped)
- After [24,24]: P(24 again) = 0.1 (unusual)
- After [24,24,24]: P(24 again) = 0.02 (very suspicious)

**NLL Score:** ~9.5 (High - brute force attack!)

---

## 🎯 Threshold Calculation

After training, the transformer scores 1000 random sequences from training data and uses the **95th percentile** as the threshold:

```python
Normal sequences: [0.5, 0.8, 1.2, 0.9, 1.5, 1.1, ...]  
95th percentile: ~3.5

Threshold = 3.5

If NLL > 3.5 → Anomaly!
```

---

## 🔄 How It All Works Together

```
1. Log arrives:
   "GET /api/admin HTTP/1.1 403"

2. Convert to template:
   "GET /api/admin HTTP/1.1 <NUM>" → ID: 15

3. Add to session window:
   Session 192.168.1.100: [5, 5, 7, 12, 15]

4. Transformer scores sequence:
   - P(5|start) = 0.85
   - P(5|5) = 0.80
   - P(7|5,5) = 0.78
   - P(12|5,5,7) = 0.82
   - P(15|5,5,7,12) = 0.10  ← LOW! Unexpected admin access
   
5. Calculate NLL:
   = -log(0.85) - log(0.80) - log(0.78) - log(0.82) - log(0.10)
   = 0.16 + 0.22 + 0.25 + 0.20 + 2.30
   = 3.13

6. Compare to threshold:
   3.13 < 3.5 → Not quite anomalous (borderline)
   
   But combined with rule-based detection of "admin" path
   and Isolation Forest flagging unusual access pattern...
   
7. Ensemble decides: ANOMALY!
```

---

## 💡 Key Insights

1. **Context Matters**: The same template can be normal or anomalous depending on what came before
2. **Learns Patterns**: Transformer learns typical user workflows, not just individual requests
3. **Statistical**: Uses probability - doesn't need hardcoded rules
4. **Adaptive**: Improves as it sees more normal traffic
5. **Complements Other Models**: 
   - Rule-based catches known attacks
   - Isolation Forest catches statistical outliers
   - Transformer catches behavioral anomalies

---

## 🧪 Testing Transformer Detection

To see the transformer in action, you need:
1. ✅ 50,000+ logs processed (training trigger)
2. ✅ Diverse normal traffic (so it learns patterns)
3. ✅ Then send anomalous sequences

The contextual test script (`test_contextual_evolution.py`) will show much better results after training!
