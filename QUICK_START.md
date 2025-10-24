# Quick Start Guide - Enhanced Frontend

## 🚀 What's New?

Your log dashboard now shows **detailed anomaly scores from each detection model** and allows you to **configure detection thresholds** without touching code!

---

## 📋 Quick Overview

### New Columns in Logs Table

| Column | What It Shows | How to Use |
|--------|--------------|------------|
| **Anomaly Score** | Visual bar + percentage (0-100%) | Quick glance at threat confidence |
| **Details** | Expand button (▼) | Click to see individual model scores |

### New Components

1. **⚙️ Threshold Settings** (top-right of dashboard)
   - Configure detection sensitivity
   - Adjust model weights
   - Settings persist across sessions

2. **📚 Model Legend** (above logs table)
   - Explains each detection model
   - Shows attack types detected
   - Usage tips and score ranges

---

## 🎯 How to Use - 3 Steps

### Step 1: View Basic Information

Just load the dashboard - you'll see:
- ✅ Total logs, threats, safe logs, threat rate (top cards)
- ✅ Anomaly score bar for each log
- ✅ Color coding: Red = threat, Green = safe

### Step 2: Investigate Threats

When you see a red highlighted log:
1. **Click the ▼ button** in the Details column
2. **View expanded panel** showing:
   - Rule-Based: Attack types detected
   - Isolation Forest: Statistical anomaly score
   - Transformer: Sequence anomaly (NLL) score
   - Ensemble Decision: Final weighted score
3. **Understand why** it was flagged

### Step 3: Tune Detection (Optional)

If you're getting too many/few alerts:
1. **Click ⚙️ Threshold Settings**
2. **Adjust sliders:**
   - **Higher** values = fewer alerts (stricter)
   - **Lower** values = more alerts (sensitive)
3. **Click "Apply Changes"**
4. **Monitor results** and fine-tune

---

## 📊 Understanding the Scores

### The 3 Models

```
🔵 Rule-Based
   ├─ Looks for: SQL injection, XSS, path traversal
   ├─ Output: Attack/Clean + confidence %
   └─ Good for: Known attack patterns

🟡 Isolation Forest  
   ├─ Looks for: Unusual request patterns
   ├─ Output: Anomaly score (0-5+)
   └─ Good for: Unknown threats, behavior anomalies

🟢 Transformer
   ├─ Looks for: Abnormal request sequences
   ├─ Output: NLL score (0-15+)
   └─ Good for: Context-aware detection
```

### Final Decision

```
Ensemble combines all 3 models:
  ┌─────────────────────────────┐
  │ Rule Vote × Weight (0.3)    │─┐
  │ ISO Vote × Weight (0.6)     │─┼─→ Average → % Score
  │ Trans Vote × Weight (0.7)   │─┘
  └─────────────────────────────┘
           ↓
    If Score > 50% → THREAT
```

---

## 🎨 Visual Guide

### Expanded Log Details

```
┌─────────────────────────────────────────────────────────┐
│ Click ▼ to expand any log row                           │
└─────────────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│ ENSEMBLE MODEL SCORES                                    │
├──────────────┬─────────────────┬────────────────────────┤
│ Rule-Based   │ Isolation Forest│ Transformer            │
├──────────────┼─────────────────┼────────────────────────┤
│ ⚠ Attack     │ ✓ Normal       │ ⚠ Anomaly             │
│ Conf: 85%    │ Score: 0.342   │ NLL: 8.2              │
│              │ [===]          │ [=======]             │
│ Attack Types:│                │                        │
│ • SQL Inject │                │                        │
│ • XSS        │                │                        │
└──────────────┴─────────────────┴────────────────────────┘
│ ENSEMBLE DECISION                                        │
│ Final Score: [========] 75%                             │
│ Model Votes: Rule: 1 | ISO: 0 | Trans: 1               │
└─────────────────────────────────────────────────────────┘
```

### Threshold Settings Panel

```
┌─────────────────────────────────────┐
│ ⚙️ THRESHOLD SETTINGS                │
├─────────────────────────────────────┤
│ Ensemble Threshold:        [====] 0.50│
│ Transformer NLL:      [=======] 6.5│
│ Isolation Forest:          [===] 0.5│
│                                     │
│ MODEL WEIGHTS                       │
│ Rule-Based:              [===] 0.3 │
│ Isolation Forest:    [======] 0.6 │
│ Transformer:        [=======] 0.7 │
│                                     │
│ [Reset to Default] [Apply Changes] │
└─────────────────────────────────────┘
```

---

## ⚙️ Recommended Settings

### Default (Balanced)
```yaml
ensemble_threshold: 0.5      # 50%
transformer_nll: 6.5         # Moderate
isolation_forest: 0.5        # Moderate

rule_weight: 0.3             # Low priority
iso_weight: 0.6              # Medium priority
trans_weight: 0.7            # High priority
```

### High Security (Catch Everything)
```yaml
ensemble_threshold: 0.3      # 30% - Very sensitive
transformer_nll: 5.0         # Low tolerance
isolation_forest: 0.3        # Flag more outliers

rule_weight: 0.5             # Trust patterns
iso_weight: 0.7              # Value statistics
trans_weight: 0.8            # Trust ML heavily
```

### Production (Fewer False Positives)
```yaml
ensemble_threshold: 0.7      # 70% - Stricter
transformer_nll: 8.0         # Higher tolerance
isolation_forest: 0.7        # Accept outliers

rule_weight: 0.8             # Only known attacks
iso_weight: 0.4              # Less statistical
trans_weight: 0.5            # Moderate ML
```

---

## 💡 Pro Tips

### Tip 1: Check Model Agreement
- **All 3 agree** = High confidence
- **2 out of 3** = Probable threat
- **Only 1 flags** = Investigate context

### Tip 2: Watch for Patterns
- Same IP triggering multiple models? → Likely attack
- Only ISO Forest flagging? → Could be legitimate unusual behavior
- Only Transformer flagging? → New pattern, train model

### Tip 3: Adjust Incrementally
- Change thresholds by **0.1 at a time**
- Monitor for **1 hour** before adjusting again
- Document your changes
- Reset if unsure

### Tip 4: Use Attack Types
- Rule-based shows **specific attack types**
- Use this to categorize threats
- Create reports by attack category

### Tip 5: Color Coding
- **Red background** = Threat row
- **Red progress bar** = High anomaly score
- **Green progress bar** = Low/safe score
- **Red badges** = Attack detected

---

## 🔍 Common Scenarios

### Scenario 1: Obvious Attack
```
Log: GET /api/users?id=1 OR 1=1-- HTTP/1.1

Expanded View:
├─ Rule-Based: ✗ Attack (SQL Injection) - 95% confidence
├─ ISO Forest: ✗ Anomaly - Score: 1.8
├─ Transformer: ✗ Anomaly - NLL: 9.2
└─ Ensemble: 92% → THREAT ✗

Action: Block IP, investigate user
```

### Scenario 2: False Positive
```
Log: GET /api/rare-endpoint HTTP/1.1

Expanded View:
├─ Rule-Based: ✓ Clean - 0% confidence
├─ ISO Forest: ✗ Anomaly - Score: 2.1 (unusual endpoint)
├─ Transformer: ✓ Normal - NLL: 4.8
└─ Ensemble: 37% → SAFE ✓

Action: Whitelist endpoint, adjust ISO threshold
```

### Scenario 3: New Attack Pattern
```
Log: GET /api/user/<script>alert(1)</script> HTTP/1.1

Expanded View:
├─ Rule-Based: ✗ Attack (XSS) - 88% confidence
├─ ISO Forest: ✓ Normal - Score: 0.4
├─ Transformer: ✗ Anomaly - NLL: 7.8
└─ Ensemble: 67% → THREAT ✗

Action: Block, update filters, retrain model
```

---

## 📖 Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| Refresh Dashboard | F5 |
| Open Settings | (Click ⚙️) |
| Expand First Log | (Click ▼) |
| Close Settings | ESC |
| Navigate Table | Arrow Keys |

---

## 🐛 Quick Troubleshooting

| Problem | Quick Fix |
|---------|-----------|
| Settings not saving | Check browser localStorage is enabled |
| Details not expanding | Hard refresh (Ctrl+F5) |
| Missing scores | Restart backend services |
| Visual glitches | Clear browser cache |
| WebSocket disconnected | Check backend status |

---

## 📞 Need Help?

1. **Read the Model Legend** on the dashboard
2. **Check FRONTEND_VISUAL_GUIDE.md** for detailed docs
3. **Review browser console** for errors (F12)
4. **Contact admin** if issues persist

---

## 🎓 Learning Path

**Day 1:** Understand the 3 models  
**Day 2:** Practice expanding logs  
**Day 3:** Experiment with thresholds  
**Day 4:** Analyze model agreement patterns  
**Week 2:** Fine-tune for your environment  

---

## ✅ Checklist for Admins

- [ ] Verify backend is running latest version
- [ ] Test WebSocket connection
- [ ] Check Elasticsearch schema updated
- [ ] Load test data to verify display
- [ ] Document initial threshold settings
- [ ] Train users on new features
- [ ] Monitor false positive/negative rates
- [ ] Set up alerts for high anomaly rates

---

**Happy Monitoring! 🎉**

For detailed documentation, see:
- `FRONTEND_VISUAL_GUIDE.md` - Complete visual guide
- `FRONTEND_IMPROVEMENTS.md` - Technical details
- `CHANGES_SUMMARY.md` - What changed
