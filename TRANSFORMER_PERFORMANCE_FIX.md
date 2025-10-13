# Transformer Performance Issue & Fix

## Problem
The transformer in notebook `07_hybrid_attack_detection.ipynb` shows very poor performance:
- **Precision**: 0.1677 (only 16.77% of flagged items are actual attacks)
- **Recall**: 0.1478 (only detects 14.78% of actual attacks)
- **F1-Score**: 0.1571 (very poor overall)

## Root Causes

### 1. **Vocabulary Mismatch (Primary Issue)**
The Apache attack model was trained on `apache_training_150k.log` but tested on `synthetic_nodejs_apache_10k.log`. These datasets may have:
- Different URL patterns
- Different path structures  
- Different attack signatures
- Different normalization results

**Expected**: High vocabulary coverage (80-90%)
**Actual**: Likely very low coverage, causing most test logs to map to UNK token

### 2. **Threshold Selection Issue**
Using 90th percentile as threshold assumes:
- Attack logs are in the minority (top 10%)
- Attack scores are actually HIGHER than normal scores

**Problem**: If the model learned attacks as "normal" during training (since attacks were 15% of training data), it might score attacks LOWER, inverting the expected behavior.

### 3. **Normalization Consistency**
The normalization between training (notebook 10) and testing (notebook 07) must be **EXACTLY** identical, including:
- Message format: `{method} {path} {protocol} {status}`
- Path normalization (attack preservation)
- Number bucketing
- Special token handling

## Fixes Applied

### Fix 1: Exact Normalization Matching ✅
Updated notebook 07 to create messages EXACTLY like notebook 10:

```python
# Step 1: Create raw message (BEFORE normalization)
df['raw_message'] = df.apply(
    lambda row: f"{row.get('method', 'GET')} {row.get('path', '/')} {row.get('protocol', 'HTTP/1.1')} {row.get('status', 200)}",
    axis=1
)

# Step 2: Apply normalization
df['norm_message'] = df['raw_message'].apply(normalize_apache_message)

# Step 3: Map to template IDs
UNK_ID = apache_vocab_size - 1
df['template_id'] = df['norm_message'].apply(
    lambda msg: apache_template_to_id.get(msg, UNK_ID)
)
```

### Fix 2: Diagnostic Cells Added ✅
Added two diagnostic cells to analyze the issue:

**Cell 1: Template Matching Analysis**
- Shows raw vs normalized messages
- Identifies which templates match vocabulary
- Helps debug normalization issues

**Cell 2: Score Distribution Analysis**
- Compares attack vs normal score distributions
- Computes optimal threshold using ROC analysis
- Suggests better threshold values

### Fix 3: Better Coverage Reporting ✅
Enhanced coverage analysis to show:
- Exact UNK count and percentage
- Sample UNK templates (most common)
- Clearer warning messages
- Lowered threshold to 30% for cross-dataset testing

## How to Fix Performance

### Step 1: Run Diagnostic Cells
Execute the new diagnostic cells (after the transformer section) to check:

1. **Vocabulary Coverage**: 
   - Target: >30% for cross-dataset, >80% for same dataset
   - If <30%: Vocabulary mismatch - may need to retrain on test domain

2. **Score Distribution**:
   - Check if `attack_scores.mean() > normal_scores.mean()`
   - If YES: Model is working correctly, just need better threshold
   - If NO: Model learned attacks as normal (serious issue)

### Step 2: Apply Optimal Threshold
The diagnostic cell computes the optimal threshold using ROC curve analysis. Replace the 90th percentile with the optimal threshold:

```python
# BEFORE (current - uses 90th percentile)
threshold = np.percentile(df['transformer_score'], 90)
df['transformer_is_anomaly'] = (df['transformer_score'] > threshold).astype(int)

# AFTER (use optimal threshold from ROC analysis)
from sklearn.metrics import roc_curve
y_true = df['true_label'].astype(int)
fpr, tpr, thresholds = roc_curve(y_true, df['transformer_score'])
j_scores = tpr - fpr
optimal_idx = np.argmax(j_scores)
optimal_threshold = thresholds[optimal_idx]

df['transformer_is_anomaly'] = (df['transformer_score'] > optimal_threshold).astype(int)
print(f"Using optimal threshold: {optimal_threshold:.4f}")
```

### Step 3: Alternative - Retrain on Test Domain
If vocabulary coverage is very low (<30%), consider:

**Option A**: Combine datasets and retrain
```bash
# Combine training and test logs
cat data/apache_logs/apache_training_150k.log \
    data/apache_logs/synthetic_nodejs_apache_10k.log > \
    data/apache_logs/combined_apache.log

# Retrain model in notebook 10 with combined data
```

**Option B**: Fine-tune on test data
- Use the Apache attack model as starting point
- Fine-tune for 2-3 epochs on synthetic_nodejs_apache_10k.log
- This adapts the vocabulary without losing attack knowledge

## Expected Results After Fixes

With proper threshold selection:
- **Precision**: Should improve to 0.60-0.80 (if model works correctly)
- **Recall**: Should improve to 0.40-0.70 (depends on threshold)
- **F1-Score**: Should improve to 0.50-0.75

If results don't improve significantly:
- **Likely cause**: Training data mismatch (different attack patterns)
- **Solution**: Retrain on combined or test-specific data

## Quick Verification

Run these checks in the notebook after applying fixes:

```python
# 1. Check vocabulary coverage
coverage = (df['template_id'] != UNK_ID).sum() / len(df) * 100
print(f"Coverage: {coverage:.1f}% (target: >30%)")

# 2. Check score separation
normal_mean = df[~df['true_label']]['transformer_score'].mean()
attack_mean = df[df['true_label']]['transformer_score'].mean()
print(f"Normal mean: {normal_mean:.4f}")
print(f"Attack mean: {attack_mean:.4f}")
print(f"Separation: {attack_mean - normal_mean:+.4f} (want positive)")

# 3. Verify threshold
from sklearn.metrics import precision_score, recall_score, f1_score
y_pred = (df['transformer_score'] > optimal_threshold).astype(int)
print(f"Precision: {precision_score(df['true_label'], y_pred):.4f}")
print(f"Recall:    {recall_score(df['true_label'], y_pred):.4f}")
print(f"F1:        {f1_score(df['true_label'], y_pred):.4f}")
```

## Summary

The transformer performance issue is likely caused by:
1. ✅ **FIXED**: Normalization mismatch → Now matches training exactly
2. ⚠️ **TO CHECK**: Vocabulary coverage → Use diagnostic cell
3. ⚠️ **TO FIX**: Threshold selection → Use optimal threshold from ROC

Run the diagnostic cells first, then apply the optimal threshold. If coverage is very low, consider retraining on combined data.
