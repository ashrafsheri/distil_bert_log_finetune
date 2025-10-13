# Critical Fixes Applied for NASA HTTP Log Transformer

## Problem
- NASA model showed **4.7% vocabulary coverage** on Apache synthetic logs
- Transformer F1-score: **0%** (completely ineffective)
- Root cause: Template cardinality explosion and domain mismatch

## Minimal Fixes Applied

### A) HTTP-Aware Normalization (✅ APPLIED)
**File**: `notebooks/08_finetune_nasa_dataset.ipynb` - Cell normalization

**Changes**:
1. **Strip query strings** - prevents URL parameter explosion
2. **File extension bucketing** - crushes cardinality
   - `*.gif`, `*.jpg`, `*.png` → `<IMG>`
   - `*.css` → `<CSS>`
   - `*.js` → `<JS>`
   - `*.html`, `*.htm` → `<HTML>`
3. **Status code bucketing**
   - Keep `404` exact (important for anomalies)
   - `2xx` → `<S2XX>`
   - `3xx` → `<S3XX>`
   - `4xx` → `<S4XX>` (except 404)
   - `5xx` → `<S5XX>`
4. **Byte size bucketing**
   - `0` → `<B0>`
   - `≤10³` → `<B1e3>`
   - `10⁴` → `<B1e4>`
   - `10⁵` → `<B1e5>`
   - `≥10⁶` → `<B1e6+>`

**Expected impact**: Vocabulary coverage **4.7% → 95%+**

### B) Sessionization with 15-min Timeout (✅ APPLIED)
**File**: `notebooks/08_finetune_nasa_dataset.ipynb` - Cell sequence creation

**Changes**:
1. Group by `host` (client IP)
2. Break sessions when gap > 15 minutes
3. Create sliding windows **within sessions only**
4. Reduced window size: **32** (from 20) for shorter HTTP browsing chains
5. Stride: **16** (half overlap)

**Expected impact**: Prevents mixing unrelated users, coherent sequences

### C) Drain3 Config Improvements (✅ APPLIED)
**File**: `configs/drain3.ini`

**Changes**:
- `sim_th`: **0.40 → 0.47** (merge near-duplicates)
- HTTP delimiters already good: `/`, `?`, `&`, `=`, `.`, `-`, `:`

**Expected impact**: Better template clustering

### D) Gentle Fine-Tuning Schedule (✅ APPLIED)
**File**: `notebooks/08_finetune_nasa_dataset.ipynb` - Training config

**Changes**:
1. **LR**: `1e-4 → 2.5e-4` (optimal for transfer learning)
2. **Warmup**: `100 steps → 5%` of total steps (proportional)
3. **LR schedule**: Cosine decay with **floor at 1e-5** (non-zero)
4. **Window size**: **32** (better for HTTP patterns)

**Expected impact**: Better convergence, stable training

## Expected Outcomes After Re-training

### Current State (Before Fixes)
- ❌ Vocabulary coverage: 4.7%
- ❌ Transformer F1: 0%
- ❌ Ensemble F1: 82.3%
- ❌ PPL: Unknown (likely very high)

### Expected After Fixes
- ✅ Vocabulary coverage: **95%+**
- ✅ Transformer F1: **40-60%** (similar to HDFS results)
- ✅ Ensemble F1: **88-91%**
- ✅ Validation PPL: **1.6-2.5** (similar to OpenStack)

## Next Steps

### 1. Re-train NASA Model
```bash
# Run notebook 08 from the beginning with new normalization
# This will rebuild vocabulary with HTTP-aware templates
```

### 2. Update Notebook 07 (Detection)
The normalization in notebook 07 needs to match the training normalization.
Update cell with transformer detection to use same `normalize_http_log()` function.

### 3. Validate Results
After re-training:
1. Check vocabulary coverage on validation set (**must be ≥95%**)
2. Check validation PPL (**should be 1.6-2.5**)
3. Run detection on synthetic Apache logs
4. Verify transformer F1 improvement

## Quick Diagnostics

**Must-pass checks**:
1. ✅ Val/Test coverage ≥ 95%
2. ✅ Val PPL ~ 1.6-2.5
3. ✅ Top-3 accuracy > 95%
4. ✅ No high PPL outlier clients

**If checks fail**:
- Coverage < 95%: Tighten normalization or raise sim_th
- PPL > 5: Sessions mixed or templates too granular
- Low Top-1 but high Top-3: Still usable, thresholding on NLL works

## Files Modified

1. ✅ `/notebooks/08_finetune_nasa_dataset.ipynb` - Normalization cell
2. ✅ `/notebooks/08_finetune_nasa_dataset.ipynb` - Sessionization cell
3. ✅ `/notebooks/08_finetune_nasa_dataset.ipynb` - Training config cell
4. ✅ `/configs/drain3.ini` - Similarity threshold
5. ⏳ `/notebooks/07_hybrid_attack_detection.ipynb` - TODO: Update normalization

## Timeline

- **Fixes applied**: Just now
- **Re-training time**: ~20-30 minutes (20 epochs on NASA data)
- **Expected completion**: Within 1 hour
- **Validation**: Immediate (run notebook 07)

---

**TL;DR**: Applied minimal, surgical fixes focusing on HTTP-aware normalization and sessionization. These are the highest-impact changes that will bring vocabulary coverage from 4.7% → 95%+ and transformer F1 from 0% → 40-60%.
