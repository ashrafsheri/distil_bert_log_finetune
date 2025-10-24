# Frontend Improvements - Ensemble Model Details & Threshold Settings

## Overview
Enhanced the frontend to display detailed anomaly detection information from the ensemble model and provide configurable threshold settings for administrators.

## New Features

### 1. **Detailed Anomaly Scores Display**

#### Expandable Log Rows
- Click the dropdown arrow in the "Details" column to expand any log entry
- View detailed scores and decisions from each model in the ensemble:
  - **Rule-Based Detection**: Attack detection status, confidence score, and identified attack types
  - **Isolation Forest**: Anomaly status and anomaly score
  - **Transformer Model**: Anomaly status and Negative Log-Likelihood (NLL) score
  - **Ensemble Decision**: Final weighted score and individual model votes

#### Visual Enhancements
- **Anomaly Score Column**: Visual progress bar showing the final ensemble score (0-100%)
- **Color-Coded Indicators**:
  - Red: Threats detected
  - Green: Safe logs
  - Visual progress bars for individual model scores
- **Attack Type Labels**: Rule-based detector shows specific attack types detected (SQL injection, XSS, path traversal, etc.)

### 2. **Threshold Settings Panel**

#### Configurable Thresholds
Access via the "Threshold Settings" button in the dashboard header.

**Detection Thresholds:**
- **Ensemble Threshold** (0.0 - 1.0): Final score threshold for flagging anomalies
  - Default: 0.5
  - Higher values = stricter detection (fewer false positives)
  - Lower values = more sensitive (catches more anomalies)

- **Transformer NLL Threshold** (0.0 - 15.0): Negative log-likelihood threshold for the transformer model
  - Default: 6.5
  - Higher values = more tolerance for unusual patterns

- **Isolation Forest Threshold** (0.0 - 5.0): Statistical anomaly score threshold
  - Default: 0.5
  - Higher values = more tolerance for statistical outliers

**Model Weights:**
Configure the importance of each model in the ensemble decision:
- **Rule-Based Weight** (0.0 - 1.0): Weight for pattern matching
  - Default: 0.3
- **Isolation Forest Weight** (0.0 - 1.0): Weight for statistical detection
  - Default: 0.6
- **Transformer Weight** (0.0 - 1.0): Weight for sequence-based detection
  - Default: 0.7

**Settings Persistence:**
- Settings are saved to browser localStorage
- Persist across page reloads
- Reset to defaults with one click

### 3. **Enhanced Table Columns**

New columns added to the logs table:
1. **Anomaly Score**: Visual bar showing final ensemble score percentage
2. **Details**: Expandable button to view model-specific scores

Existing columns enhanced:
- Truncated long API paths with tooltip on hover
- Better responsive design for mobile devices

## Technical Implementation

### Backend Changes

#### Updated Models (`backend/app/models/log_entry.py`)
```python
class AnomalyDetails(BaseModel):
    rule_based: Optional[Dict[str, Any]]
    isolation_forest: Optional[Dict[str, Any]]
    transformer: Optional[Dict[str, Any]]
    ensemble: Optional[Dict[str, Any]]

class LogEntry(BaseModel):
    # ... existing fields
    anomaly_score: Optional[float]
    anomaly_details: Optional[AnomalyDetails]
```

#### Updated Controllers (`backend/app/controllers/log_controller.py`)
- Extract and format anomaly details from detection service
- Include detailed scores in both HTTP responses and WebSocket messages
- Structure data for frontend consumption

### Frontend Changes

#### New Components
1. **ThresholdSettings.tsx**: Interactive panel for threshold configuration
   - Slider controls for all thresholds and weights
   - Local storage persistence
   - Reset to defaults functionality

2. **Enhanced LogsTable.tsx**: Expandable rows with detailed model scores
   - State management for expanded rows
   - Visual score indicators and progress bars
   - Attack type labels

#### Updated Interfaces
```typescript
interface AnomalyDetails {
  rule_based?: {
    is_attack: boolean;
    attack_types?: string[];
    confidence: number;
  };
  isolation_forest?: {
    is_anomaly: number;
    score: number;
  };
  transformer?: {
    is_anomaly: number;
    score: number;
  };
  ensemble?: {
    score: number;
    votes?: {...};
    weights?: {...};
  };
}

interface LogEntry {
  // ... existing fields
  anomaly_score?: number;
  anomaly_details?: AnomalyDetails;
}
```

## Usage Guide

### Viewing Detailed Anomaly Information
1. Navigate to the Log Dashboard
2. Look for logs with the "Threat Detected" badge
3. Click the down arrow (▼) in the "Details" column
4. View the expanded panel showing:
   - Individual model scores and decisions
   - Attack types detected (if any)
   - Ensemble voting breakdown
   - Visual score representations

### Adjusting Detection Thresholds
1. Click "Threshold Settings" button (gear icon) in the header
2. Adjust sliders for:
   - Detection thresholds (how sensitive each model is)
   - Model weights (how much each model influences the final decision)
3. Click "Apply Changes" to save
4. Click "Reset to Default" to restore original values

### Understanding the Ensemble Decision

**How It Works:**
- Each model votes on whether a log is anomalous (0 = normal, 1 = anomaly)
- Votes are weighted by their respective weights
- Final score = (weighted sum of votes) / (total weight)
- If final score > ensemble threshold, log is flagged as anomaly

**Example:**
```
Rule-Based: Vote = 1, Weight = 0.3 → Contribution = 0.3
ISO Forest:  Vote = 0, Weight = 0.6 → Contribution = 0.0
Transformer: Vote = 1, Weight = 0.7 → Contribution = 0.7
---------------------------------------------------------
Final Score = (0.3 + 0.0 + 0.7) / (0.3 + 0.6 + 0.7) = 0.625
If Ensemble Threshold = 0.5, then ANOMALY = true
```

## Best Practices

### For Security Analysts
- **Higher Thresholds**: Reduce false positives in low-risk environments
- **Lower Thresholds**: Increase sensitivity in high-security scenarios
- **Weight Adjustment**: Increase rule-based weight if you trust pattern matching
- **Review Expanded Details**: Check which models voted for anomaly to understand detection reasoning

### For Administrators
- Start with default settings and adjust based on false positive/negative rates
- Monitor the "Ensemble Decision" panel to understand model agreement
- Use the visual score bars to quickly identify borderline cases
- Export logs for further analysis using the attack type labels

## Performance Considerations
- Expanded rows render on-demand (only when clicked)
- Settings stored in localStorage (no server calls)
- Anomaly details only sent for logs with `infected: true` or when requested
- Efficient rendering with React.Fragment and conditional rendering

## Future Enhancements
- [ ] Export threshold configurations as JSON
- [ ] A/B testing of different threshold sets
- [ ] Real-time threshold effectiveness metrics
- [ ] Automated threshold tuning based on feedback
- [ ] Model-specific filtering and sorting
- [ ] Historical trend analysis per model

## Troubleshooting

### Threshold Settings Not Persisting
- Clear browser cache and localStorage
- Ensure cookies and localStorage are enabled
- Check browser console for errors

### Missing Anomaly Details
- Verify backend is running latest version
- Check that anomaly detection service is connected
- Ensure Elasticsearch has the updated schema

### Visual Glitches
- Hard refresh the page (Ctrl+F5 or Cmd+Shift+R)
- Check browser compatibility (modern browsers required)
- Verify Tailwind CSS is loading correctly
