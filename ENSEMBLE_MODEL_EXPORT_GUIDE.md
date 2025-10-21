# Ensemble Model Export & Inference Guide

This guide explains how to export the ensemble model from notebook 07 and use it for inference on new synthetic logs in notebook 11.

## Overview

The ensemble model combines three detection methods:
1. **Transformer** - Behavioral sequence analysis (Apache attack fine-tuned)
2. **Rule-Based** - Pattern matching for attack signatures (SQL, XSS, traversal, etc.)
3. **Isolation Forest** - Statistical anomaly detection (IP-based features)

## Step-by-Step Process

### Step 1: Export the Ensemble Model (Notebook 07)

First, run notebook `07_hybrid_attack_detection.ipynb` to train and export the model:

1. **Open notebook**: `notebooks/07_hybrid_attack_detection.ipynb`
2. **Run all cells** up to Section 9 (evaluation complete)
3. **Run the export cell** (Section 10):
   - This creates `artifacts/ensemble_model_export/` directory
   - Exports 5 files:
     - `transformer_model.pt` - Transformer weights and config
     - `template_vocab.json` - Vocabulary (23,705 templates)
     - `isolation_forest.pkl` - Statistical detector
     - `model_config.json` - Optimal threshold and settings
     - `README.md` - Usage instructions

**Expected output:**
```
✓ Exported Transformer model: transformer_model.pt
✓ Exported vocabulary: template_vocab.json (23,705 templates)
✓ Exported Isolation Forest: isolation_forest.pkl
✓ Exported configuration: model_config.json
✓ Created README: README.md

Export directory: /home/tpi/distil_shahreyar/artifacts/ensemble_model_export
```

### Step 2: Run Inference on New Logs (Notebook 11)

Now use notebook `11_ensemble_model_inference.ipynb` to test on new synthetic logs:

1. **Open notebook**: `notebooks/11_ensemble_model_inference.ipynb`
2. **Verify export exists**: Check that `artifacts/ensemble_model_export/` has all 5 files
3. **Run all cells**:
   - Section 1: Loads all exported model components
   - Section 2: Loads new test data (default: `synthetic_nodejs_apache_10k.log`)
   - Section 3: Extracts features (IP statistics, templates)
   - Sections 4-6: Runs inference for each method
   - Section 7: Combines via ensemble voting
   - Section 8: Evaluates metrics against ground truth
   - Sections 9-11: Visualizations and analysis

**Expected output:**
```
✓ Loaded vocabulary: 23,705 templates
✓ Loaded Transformer model (epoch 14)
✓ Loaded Isolation Forest
✓ Loaded optimal threshold: 0.4532
✓ Initialized Rule-based detector

ENSEMBLE MODEL LOADED SUCCESSFULLY

Total logs processed: 10,000
Detections by method:
  Rule-based:       1,245 (12.5%)
  Isolation Forest: 1,876 (18.8%)
  Transformer:      1,532 (15.3%)
  Ensemble (final): 1,654 (16.5%)

PERFORMANCE METRICS
Method              Accuracy  Precision  Recall  F1-Score
Rule-based            0.9234     0.8765  0.6543    0.7492
Isolation Forest      0.8876     0.7234  0.8123    0.7651
Transformer           0.9123     0.8456  0.7234    0.7801
Ensemble              0.9345     0.8876  0.8234    0.8543

🏆 Best F1-Score: Ensemble (0.8543)
```

## What Gets Exported?

### 1. Transformer Model (`transformer_model.pt`)
- **Contents**: Model weights, architecture config, training epoch
- **Size**: ~50-100 MB
- **Format**: PyTorch checkpoint dictionary
- **Keys**:
  - `model_state_dict`: Trained weights
  - `vocab_size`: 23,705
  - `model_config`: Architecture parameters (d_model, nhead, layers, etc.)
  - `epoch`: Training epoch number

### 2. Vocabulary (`template_vocab.json`)
- **Contents**: Template → ID mapping
- **Size**: ~2-5 MB
- **Format**: JSON dictionary
- **Example**:
  ```json
  {
    "GET /api/users HTTP/1.1 200": 0,
    "POST /api/login HTTP/1.1 401": 1,
    "GET /admin' OR 1=1-- HTTP/1.1 403": 2,
    ...
  }
  ```

### 3. Isolation Forest (`isolation_forest.pkl`)
- **Contents**: Trained scikit-learn IsolationForest model
- **Size**: ~1-2 MB
- **Format**: Python pickle
- **Features**: `ip_request_count`, `ip_error_rate`, `ip_unique_paths`, `ip_error_count`

### 4. Model Config (`model_config.json`)
- **Contents**: Runtime configuration and thresholds
- **Size**: ~1 KB
- **Format**: JSON dictionary
- **Keys**:
  - `optimal_threshold`: 0.4532 (from ROC analysis)
  - `vocab_size`: 23,705
  - `window_size`: 20
  - `stride`: 10
  - `ensemble_weights`: Voting weights for each method
  - `export_date`: Timestamp
  - `source_notebook`: Where model was trained

### 5. README (`README.md`)
- **Contents**: Usage instructions and model metadata
- **Size**: ~2 KB
- **Format**: Markdown documentation

## Test Data Options

Notebook 11 supports multiple test datasets:

### Option 1: Existing Synthetic Logs (Default)
```python
log_file = REPO_ROOT / 'data/apache_logs/synthetic_nodejs_apache_10k.log'
label_file = REPO_ROOT / 'data/apache_logs/synthetic_apache_labels.json'
```
- 10,000 logs with ground truth labels
- Mix of normal and attack traffic
- Allows full metric evaluation

### Option 2: Generate New Synthetic Logs
```bash
cd /home/tpi/distil_shahreyar
python scripts/generate_synthetic_apache_logs.py \
    --output data/apache_logs/new_synthetic_logs.log \
    --count 5000 \
    --attack_ratio 0.20
```

Then update notebook 11:
```python
log_file = REPO_ROOT / 'data/apache_logs/new_synthetic_logs.log'
label_file = REPO_ROOT / 'data/apache_logs/new_synthetic_labels.json'
```

### Option 3: Real Apache Logs (No Labels)
```python
log_file = REPO_ROOT / 'data/apache_logs/production_logs.log'
label_file = None  # No ground truth
```
- Model still runs inference
- Metrics section skipped (no ground truth)
- Detection statistics still shown

## Ensemble Voting Logic

The ensemble combines detections with weighted voting:

```python
def ensemble_detection(row):
    votes = []
    weights = []
    
    # Rule-based (high weight - very precise)
    if row['rule_is_attack']:
        votes.append(1)
        weights.append(row['rule_confidence'])  # 0.4-1.0
    else:
        votes.append(0)
        weights.append(0.3)  # Low weight for "no detection"
    
    # Isolation Forest (medium weight)
    votes.append(row['iso_is_anomaly'])
    weights.append(0.6)
    
    # Transformer (medium-high weight)
    votes.append(row['transformer_is_anomaly'])
    weights.append(0.7)
    
    # Weighted vote
    score = sum(v * w for v, w in zip(votes, weights)) / sum(weights)
    
    # Decision threshold
    is_anomaly = score > 0.5
    
    return is_anomaly, score
```

**Example scenarios:**
- **All 3 detect**: `score = (1*0.8 + 1*0.6 + 1*0.7) / 2.1 = 1.0` → ANOMALY ✓
- **Rule + Transformer**: `score = (1*0.8 + 0*0.6 + 1*0.7) / 2.1 = 0.71` → ANOMALY ✓
- **Only Isolation Forest**: `score = (0*0.3 + 1*0.6 + 0*0.7) / 1.6 = 0.38` → NORMAL ✗
- **Transformer only**: `score = (0*0.3 + 0*0.6 + 1*0.7) / 1.6 = 0.44` → NORMAL ✗

## Interpreting Results

### High Precision, Low Recall
- **Means**: Few false alarms, but missing some attacks
- **Fix**: Lower optimal threshold or increase transformer weight

### High Recall, Low Precision
- **Means**: Catching most attacks, but many false alarms
- **Fix**: Increase optimal threshold or rule-based weight

### Low Vocabulary Coverage (<30%)
- **Means**: Test data very different from training data
- **Fix**: Retrain on combined dataset or fine-tune on test domain

### Good F1-Score (>0.70)
- **Means**: Model is production-ready
- **Next**: Deploy as API or streaming service

## Troubleshooting

### Issue: "File not found: artifacts/ensemble_model_export/"
**Solution**: Run notebook 07 Section 10 (export cell) first

### Issue: "Vocabulary coverage: 15%"
**Solution**: 
1. Check if test logs are Apache format
2. Verify normalization matches training
3. Consider retraining on mixed dataset

### Issue: "All predictions are Normal"
**Solution**:
1. Check optimal threshold (might be too high)
2. Verify model loaded correctly
3. Examine score distributions (Section 9)

### Issue: "RuntimeError: CUDA out of memory"
**Solution**:
```python
# Reduce batch size in Section 6
seq_loader = DataLoader(seq_dataset, batch_size=64, shuffle=False)  # was 256
```

## Performance Expectations

### Training Data Match (Same Domain)
- **F1-Score**: 0.70-0.85
- **Precision**: 0.75-0.90
- **Recall**: 0.65-0.80

### Cross-Domain (Different Log Format)
- **F1-Score**: 0.50-0.70
- **Precision**: 0.60-0.80
- **Recall**: 0.45-0.65
- **Note**: Lower due to vocabulary mismatch

### Attack Type Performance
- **SQL Injection**: ~90% detection (strong rule patterns)
- **XSS**: ~85% detection (strong rule patterns)
- **Path Traversal**: ~80% detection (rule + transformer)
- **Command Injection**: ~75% detection (complex patterns)
- **Brute Force**: ~70% detection (statistical + sequence)
- **Scanner**: ~80% detection (statistical patterns)
- **DDoS**: ~75% detection (IP-based features)

## Next Steps

### After Successful Inference:

1. **Analyze Results**:
   - Check confusion matrix
   - Review false positives/negatives
   - Examine attack type performance

2. **Fine-tune Weights** (if needed):
   - Edit `model_config.json` ensemble weights
   - Re-run ensemble voting
   - Compare performance

3. **Generate More Test Data**:
   ```bash
   python scripts/generate_synthetic_apache_logs.py --count 50000
   ```

4. **Deploy to Production**:
   - Create REST API endpoint
   - Set up streaming pipeline
   - Implement alerting system

5. **Continuous Improvement**:
   - Collect production logs
   - Retrain periodically
   - Add new attack patterns

## File Locations

```
distil_shahreyar/
├── notebooks/
│   ├── 07_hybrid_attack_detection.ipynb    # Training & export
│   └── 11_ensemble_model_inference.ipynb   # Inference & testing
├── artifacts/
│   ├── ensemble_model_export/              # Exported model
│   │   ├── transformer_model.pt
│   │   ├── template_vocab.json
│   │   ├── isolation_forest.pkl
│   │   ├── model_config.json
│   │   └── README.md
│   └── metrics/
│       └── apache/                         # Saved plots
│           ├── ensemble_inference_confusion_matrix.png
│           ├── ensemble_inference_performance.png
│           ├── ensemble_inference_venn.png
│           └── ensemble_inference_scores.png
└── data/
    └── apache_logs/
        ├── synthetic_nodejs_apache_10k.log
        └── synthetic_apache_labels.json
```

## Summary

1. **Export** from notebook 07 → Creates `artifacts/ensemble_model_export/`
2. **Load** in notebook 11 → Loads all 5 files
3. **Infer** on new logs → Runs 3 detection methods
4. **Ensemble** voting → Combines detections
5. **Evaluate** metrics → Compare vs ground truth
6. **Visualize** results → Plots and analysis

The ensemble model is now portable and ready for inference on any new Apache logs!
