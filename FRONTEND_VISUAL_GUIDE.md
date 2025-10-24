# Frontend Style and Functionality Improvements - Complete Guide

## 🎯 Overview

The frontend has been significantly enhanced to provide detailed visibility into the ensemble anomaly detection system, showing individual model scores, ensemble decisions, and configurable thresholds.

---

## ✨ New Features

### 1. **Expandable Log Details**

Each log entry can now be expanded to show detailed information about how the anomaly detection ensemble made its decision.

**How to use:**
1. Look for the **Details** column (far right)
2. Click the **▼** (down arrow) button
3. View the expanded panel with 3 model scores

**What you see:**
```
┌────────────────────────────────────────────────────────┐
│ ENSEMBLE MODEL SCORES                                   │
├─────────────────┬─────────────────┬────────────────────┤
│ Rule-Based      │ Isolation Forest│ Transformer        │
│ ✓ Clean/Attack  │ ✓ Normal/Anomaly│ ✓ Normal/Anomaly   │
│ Confidence: X%  │ Score: X.XXX    │ NLL Score: X.XXX   │
│ Attack Types    │ [Progress Bar]  │ [Progress Bar]     │
│ (if detected)   │                 │                    │
└─────────────────┴─────────────────┴────────────────────┘
```

---

### 2. **Anomaly Score Visualization**

**New Column:** Anomaly Score  
- Shows ensemble decision score (0-100%)
- Visual progress bar
- Color-coded:
  - 🔴 Red: Threat detected (>50%)
  - 🟢 Green: Safe (<50%)

**Example:**
```
| Anomaly Score              |
|----------------------------|
| [████████░░] 82%          | ← Threat
| [███░░░░░░░] 25%          | ← Safe
```

---

### 3. **Threshold Settings Panel**

Click the **⚙️ Threshold Settings** button in the dashboard header to open the configuration panel.

#### **Detection Thresholds**

**1. Ensemble Threshold** (0.0 - 1.0)
- Default: `0.5` (50%)
- Final score needed to flag as anomaly
- **Higher** → Fewer false positives, may miss subtle attacks
- **Lower** → More sensitive, more false alarms

**2. Transformer NLL Threshold** (0.0 - 15.0)
- Default: `6.5`
- Negative Log-Likelihood threshold
- Measures how "surprising" a log sequence is
- **Higher** → More tolerance for unusual patterns
- **Lower** → Flag any deviation from normal

**3. Isolation Forest Threshold** (0.0 - 5.0)
- Default: `0.5`
- Statistical anomaly score
- Based on request patterns and behavior
- **Higher** → Accept more statistical outliers
- **Lower** → Flag unusual statistics quickly

#### **Model Weights**

Configure how much each model influences the final decision:

**1. Rule-Based Weight** (0.0 - 1.0)
- Default: `0.3`
- Pattern matching for known attacks
- High precision, but limited to known signatures

**2. Isolation Forest Weight** (0.0 - 1.0)
- Default: `0.6`
- Statistical anomaly detection
- Catches unusual behavior without knowing specific attacks

**3. Transformer Weight** (0.0 - 1.0)
- Default: `0.7`
- Deep learning sequence analysis
- Learns normal patterns, flags deviations

**Ensemble Formula:**
```
Final Score = (Rule×W₁ + ISO×W₂ + Trans×W₃) / (W₁ + W₂ + W₃)

Where:
- Rule = 0 or 1 (vote from rule-based detector)
- ISO = 0 or 1 (vote from isolation forest)
- Trans = 0 or 1 (vote from transformer)
- W₁, W₂, W₃ = weights for each model

If Final Score > Ensemble Threshold → ANOMALY
```

**Example Calculation:**
```
Rule-Based:      Vote = 1, Weight = 0.3 → 0.3
Isolation Forest: Vote = 0, Weight = 0.6 → 0.0
Transformer:      Vote = 1, Weight = 0.7 → 0.7
────────────────────────────────────────────
Total: (0.3 + 0.0 + 0.7) / (0.3 + 0.6 + 0.7) = 0.625 (62.5%)

If Ensemble Threshold = 0.5 → ANOMALY DETECTED ✓
```

---

### 4. **Model Legend Panel**

New educational panel explaining each model in the ensemble.

**Components:**

**🔵 Rule-Based Detection**
- Pattern matching for known attack signatures
- Detects: SQL injection, XSS, path traversal, command injection
- High precision for known attacks
- Limited to predefined patterns

**🟡 Isolation Forest**
- Statistical anomaly detection
- Analyzes request patterns: rate, unique paths, error patterns
- Detects unusual behavior without knowing specific attacks
- Score range: 0.0 (normal) to 5.0+ (anomalous)

**🟢 Transformer (Deep Learning)**
- Sequence-based detection using attention mechanisms
- Learns normal request patterns over time
- Flags deviations from learned behavior
- Uses Negative Log-Likelihood (NLL) scoring
- NLL range: 0.0-6.5 (normal) | 6.5+ (anomalous)

**🔷 Ensemble Decision**
- Combines all three models using weighted voting
- Produces final score from 0% to 100%
- Threshold-based flagging (default: 50%)

---

## 🎨 Visual Improvements

### Color Scheme

| Element | Color | Usage |
|---------|-------|-------|
| **Threats** | Red (#e94560) | Anomalies, attacks, errors |
| **Safe** | Green (#10B981) | Normal logs, healthy status |
| **Warning** | Yellow (#F59E0B) | Moderate concerns |
| **Primary** | Cyan (#0ef6cc) | Interactive elements, highlights |
| **Background** | Dark Blue | Main background |
| **Cards** | Blue/30 | Semi-transparent panels |

### Typography

- **Headers**: Bold, larger text for section titles
- **Monospace**: IP addresses, API paths, scores
- **Small Caps**: Column headers (uppercase, tracked)
- **Color-coded text**: Red for threats, green for safe

### Layout Improvements

1. **Responsive Grid**: Adapts to screen size (1-4 columns)
2. **Truncated URLs**: Long API paths truncated with ellipsis, full text on hover
3. **Smooth Animations**: Expand/collapse transitions
4. **Visual Feedback**: Hover effects, click states
5. **Progress Bars**: Visual score representation

---

## 📊 Dashboard Layout

```
┌──────────────────────────────────────────────────────────┐
│ LOG DASHBOARD                    🟢 Connected ⚙️ Settings │
│ Real-time monitoring of system logs and threat detection │
└──────────────────────────────────────────────────────────┘

┌──────────┬──────────┬──────────┬──────────┐
│📊 Total  │⚠️ Threats│✓ Safe    │⚡ Threat  │
│ Logs     │ Detected │ Logs     │ Rate     │
│  1,234   │   42     │  1,192   │  3.4%    │
└──────────┴──────────┴──────────┴──────────┘

┌──────────────────────────────────────────────────────────┐
│ ENSEMBLE MODEL GUIDE                                      │
│                                                           │
│ 🔵 Rule-Based: Pattern matching for known attacks        │
│ 🟡 Isolation Forest: Statistical anomaly detection       │
│ 🟢 Transformer: Deep learning sequence analysis          │
│ 🔷 Ensemble: Weighted combination of all models          │
│                                                           │
│ 💡 How to Use:                                           │
│ • Click ▼ to view model scores                           │
│ • Use ⚙️ to adjust thresholds                            │
│ • Higher threshold = fewer false alarms                  │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ RECENT LOGS                                               │
│ Real-time log monitoring and threat detection            │
├──────┬─────┬────────┬────────┬─────────┬────────┬───────┤
│Time  │ IP  │  API   │ Status │ Anomaly │ Threat │Details│
│      │     │        │        │  Score  │ Status │       │
├──────┼─────┼────────┼────────┼─────────┼────────┼───────┤
│12:04 │ 1.1 │ /api   │  200   │ [██] 25%│ ✓ Safe │   ▼   │
│12:05 │ 2.2 │ /bad   │  403   │ [████] │ ⚠ Threat│   ▼   │
│      │     │        │        │   82%   │        │       │
└──────┴─────┴────────┴────────┴─────────┴────────┴───────┘
```

---

## 🔧 Configuration Guide

### For Security Analysts

**High-Security Environment** (Maximize Detection):
```
Ensemble Threshold:    0.3  (30% - more sensitive)
Transformer NLL:       5.0  (lower tolerance)
Isolation Forest:      0.3  (flag more outliers)

Rule Weight:           0.5  (trust patterns more)
ISO Forest Weight:     0.7  (value statistics)
Transformer Weight:    0.8  (prioritize ML)
```

**Production Environment** (Balance):
```
Ensemble Threshold:    0.5  (50% - default)
Transformer NLL:       6.5  (default tolerance)
Isolation Forest:      0.5  (default)

Rule Weight:           0.3  (default)
ISO Forest Weight:     0.6  (default)
Transformer Weight:    0.7  (default)
```

**Low-Risk Environment** (Reduce False Positives):
```
Ensemble Threshold:    0.7  (70% - stricter)
Transformer NLL:       8.0  (higher tolerance)
Isolation Forest:      0.7  (accept more outliers)

Rule Weight:           0.8  (trust only known patterns)
ISO Forest Weight:     0.4  (less statistical weight)
Transformer Weight:    0.5  (moderate ML trust)
```

---

## 📱 Responsive Design

The frontend adapts to different screen sizes:

**Desktop (>1024px):**
- 4-column stats grid
- Full table with all columns
- Expanded details panel side-by-side

**Tablet (768px - 1024px):**
- 2-column stats grid
- Scrollable table
- Stacked details panel

**Mobile (<768px):**
- 1-column stats grid
- Horizontal scroll table
- Full-width details panel

---

## 🚀 Performance

**Optimizations:**
- Expandable rows render on-demand
- Settings stored in localStorage (no API calls)
- Efficient React rendering with keys
- Conditional rendering for details
- WebSocket for real-time updates (no polling)

**Bundle Size Impact:**
- ThresholdSettings: ~3 KB
- ModelLegend: ~2 KB
- Enhanced LogsTable: ~5 KB
- Total addition: ~10 KB gzipped

---

## 🐛 Troubleshooting

### Threshold Settings Not Saving
**Problem:** Changes reset on page reload  
**Solution:**
1. Check browser console for localStorage errors
2. Ensure cookies/localStorage enabled in browser
3. Try clearing browser cache
4. Use "Reset to Default" and reapply

### Details Panel Not Expanding
**Problem:** Click ▼ but nothing happens  
**Solution:**
1. Hard refresh (Ctrl+F5 or Cmd+Shift+R)
2. Check browser console for JavaScript errors
3. Ensure React is loaded properly
4. Verify log has anomaly_details data

### Missing Model Scores
**Problem:** Expanded panel shows empty values  
**Solution:**
1. Verify backend is sending anomaly_details
2. Check WebSocket connection status
3. Ensure Elasticsearch has updated schema
4. Restart anomaly detection service

### Visual Glitches
**Problem:** Layout broken or styles missing  
**Solution:**
1. Clear browser cache completely
2. Check Tailwind CSS is loading
3. Verify no CSS conflicts
4. Test in different browser

---

## 📖 Usage Examples

### Example 1: Investigating an Anomaly

1. **Notice red highlighted row** in table
2. **Check Anomaly Score**: 78% (high confidence)
3. **Click Details (▼)** to expand
4. **Review model decisions:**
   - Rule-Based: ✗ Attack (SQL injection detected)
   - Isolation Forest: ✓ Normal (0.234 score)
   - Transformer: ✗ Anomaly (NLL: 8.2)
5. **Conclusion:** 2 out of 3 models flagged it
   - Rule-based detected SQL injection pattern
   - Transformer found unusual sequence
   - Only ISO Forest voted normal

**Action:** High confidence anomaly, investigate further

### Example 2: Tuning for False Positives

**Scenario:** Too many false alarms on legitimate API testing

1. **Open Threshold Settings (⚙️)**
2. **Increase Ensemble Threshold** from 0.5 to 0.6
3. **Increase Transformer NLL** from 6.5 to 7.5
4. **Decrease Transformer Weight** from 0.7 to 0.5
5. **Apply Changes**
6. **Monitor results** for next hour
7. **Adjust further** if needed

**Result:** Fewer false positives, maintains security

### Example 3: Understanding Model Disagreement

**Log shows:**
- Rule-Based: ✓ Clean
- Isolation Forest: ✗ Anomaly (score: 2.3)
- Transformer: ✓ Normal
- Ensemble: 37% (Safe)

**Interpretation:**
- No known attack patterns (rule-based clean)
- Statistical outlier (ISO Forest flagged)
- Normal sequence pattern (transformer clean)
- Final score below 50% threshold → Marked Safe

**Possible cause:** Legitimate unusual behavior (e.g., rare but valid API call)

---

## 🎓 Training Guide

### For New Users

**Week 1: Basics**
- Understand the 4 stats cards
- Learn to identify threats (red highlighting)
- Practice expanding log details
- Review the Model Legend

**Week 2: Model Understanding**
- Study each model's purpose
- Compare model scores on different logs
- Identify patterns in model agreement/disagreement
- Learn attack type classifications

**Week 3: Configuration**
- Experiment with threshold settings
- Document threshold changes
- Monitor impact of adjustments
- Find optimal settings for your environment

**Week 4: Advanced**
- Correlate model scores with actual threats
- Tune weights based on model accuracy
- Create custom threshold profiles
- Train others on the system

---

## 📚 Additional Resources

- **Backend API Docs**: See `API_DOCUMENTATION.md`
- **Model Details**: See `FRONTEND_IMPROVEMENTS.md`
- **Deployment**: See `DEPLOYMENT_SUMMARY.md`
- **Ensemble Logic**: See `realtime_anomaly_detection/models/ensemble_detector.py`

---

## 🔄 Future Enhancements

Planned improvements:
- [ ] Export logs with detailed model scores (CSV/JSON)
- [ ] Historical trend graphs per model
- [ ] A/B testing of threshold configurations
- [ ] Automated threshold tuning based on feedback
- [ ] Model accuracy metrics dashboard
- [ ] Custom alert rules based on model votes
- [ ] Integration with SIEM systems
- [ ] Mobile app for monitoring

---

## 📞 Support

For issues or questions:
1. Check this guide first
2. Review browser console for errors
3. Verify backend service status
4. Check logs in Elasticsearch
5. Contact system administrator

---

**Version:** 1.0.0  
**Last Updated:** October 25, 2025  
**Authors:** Frontend Development Team
