# Step-by-Step Recovery Plan

## Current Situation
- ❌ Transformer F1: 0% (completely broken)
- ❌ Coverage: 4.2% (should be 95%+)
- ❌ Ensemble degraded: 83.3% F1
- ✅ You've deleted the old model
- ✅ Guardrails are in place

---

## Execute These Steps in Order

### Step 1: Verify Guardrails Are in Place ✅

**Already done!** The following cells have been added/modified:

**Notebook 08 (`08_finetune_nasa_dataset.ipynb`)**:
- ✅ Cell 4.1: Pre-flight vocabulary validation
- ✅ Cell 11: Normalization signature saving
- ✅ Cell 19: Training config with cosine LR + floor

**Notebook 07 (`07_hybrid_attack_detection.ipynb`)**:
- ✅ Cell 14: Enhanced model existence check
- ✅ New cell after 14: Signature verification
- ✅ Cell 15: Enhanced coverage check with auto-disable

---

### Step 2: Re-train NASA Model (Notebook 08)

**Open notebook**: `notebooks/08_finetune_nasa_dataset.ipynb`

**Run cells**: Execute ALL cells from the beginning (1 through 30)

**What to watch for**:

#### Cell 4 - Normalization
```
✓ HTTP-aware normalization applied

Sample normalized messages:
  1. GET / <S2XX> <B1e3>
  2. GET /images/<ID>/<IMG> <S2XX> <B1e4>
  3. GET /shuttle/missions/<ID>/<HTML> <S2XX> <B1e4>
```
✅ Templates should use `<IMG>`, `<HTML>`, `<S2XX>`, `<B1e4>` buckets

#### Cell 4.1 - Pre-flight Check (NEW)
```
======================================================================
PRE-FLIGHT VOCABULARY VALIDATION
======================================================================
✅ Vocabulary size: 287 templates (optimal range: 100-1000)

Template distribution:
  Top-10 templates cover: 67.3% of logs
  ✅ Good concentration - common patterns well-represented
```
✅ Vocabulary should be 200-500 templates (not 1,287!)
✅ No warnings about "too small" or "too large"

#### Cell 5 - Sessionization
```
✓ Sessionization complete
  Total sessions: 12,345
  Total sequences: 45,678
  Average sequence length: 8.7
```
✅ Sequences should be reasonable (not millions)

#### Cell 22 - Training Loop
```
Epoch 1/20:
  Train Loss: 3.2456 | Train PPL: 25.67
  Val Loss:   2.8934 | Val PPL:   18.04
  LR: 0.000238

...

Epoch 20/20:
  Train Loss: 1.0234 | Train PPL: 2.78
  Val Loss:   0.9876 | Val PPL:   2.68  ⬅️ TARGET: 1.6-2.5
  LR: 0.000013

✓ Saved best model (val_loss: 0.9654)
```
✅ Validation PPL should be **1.6-2.5** (not 7.04!)
✅ Training should converge smoothly

#### Cell 30 - Model Summary
```
Best validation PPL: 2.14  ⬅️ Good!
```
✅ Should see improvement from old 7.04

#### Cell 31 - Signature Saving (NEW)
```
======================================================================
NORMALIZATION SIGNATURE SAVED
======================================================================
✓ Metadata saved to: artifacts/nasa_finetune_model/model_meta.json

Signature composite: a3f2e1d4c5b6a789
This signature MUST match at detection time!

Configuration:
  - Normalization: HTTP-aware: strip query, lowercase, ...
  - Drain3 sim_th: 0.47
  - Window size: 32
  - Session timeout: 15min
  - Vocabulary size: 287 templates
======================================================================
```
✅ **CRITICAL**: Note the signature hash - this will be verified at detection

**Time**: ~20-30 minutes for full training

---

### Step 3: Validate Training Results

**Check files created**:
```bash
ls -lh artifacts/nasa_finetune_model/
```

**Should see**:
```
best.pt                    # Model weights (newest)
last.pt                    # Final epoch weights
model_summary.json         # Training metrics
model_meta.json           # ⭐ NEW: Signature + metadata
training_history.csv       # Loss/PPL per epoch
checkpoint_epoch_*.pt      # Periodic checkpoints
```

**Verify metadata**:
```bash
cat artifacts/nasa_finetune_model/model_meta.json
```

**Should contain**:
```json
{
  "created_at": "2025-10-12T...",
  "vocab_size": 287,
  "signature": {
    "composite": "a3f2e1d4c5b6a789",
    ...
  },
  "training_info": {
    "best_val_ppl": 2.14,
    ...
  }
}
```

✅ If `model_meta.json` exists with signature → Training succeeded!

---

### Step 4: Run Detection with Guardrails (Notebook 07)

**Open notebook**: `notebooks/07_hybrid_attack_detection.ipynb`

**Run cells**: Execute cells 1-14 (up to model loading)

#### Cell 14 - Model Check
```
NASA model found - verifying compatibility...
```
✅ Should find model + metadata

#### New Cell after 14 - Signature Verification
```
======================================================================
SIGNATURE VERIFICATION
======================================================================
Training signature: a3f2e1d4c5b6a789
Runtime signature:  a3f2e1d4c5b6a789
Match: ✅ YES

✅ Normalization signatures match - proceeding with transformer
======================================================================
```
✅ Signatures MUST match!
❌ If mismatch → Check that you didn't modify normalization settings in only one notebook

**Continue running**: Cell 15 (Transformer Detection)

#### Cell 15 - Coverage Check
```
======================================================================
VOCABULARY COVERAGE CHECK
======================================================================
Known templates: 8,932/9,427 (94.7%)
Threshold: ≥90%

✅ Coverage sufficient (94.7% ≥ 90%)
✅ Proceeding with transformer scoring
======================================================================

Created 1,234 sequences
✓ Transformer detected 567 anomalies (threshold: 4.2345)
```
✅ Coverage should be **90-95%+** (not 4.2%!)
✅ Transformer should detect reasonable number (not 0, not all)

**Continue running**: Cells 16-19 (Ensemble + Evaluation)

#### Cell 19 - Performance Results
```
======================================================================
PERFORMANCE COMPARISON
======================================================================
          Method  Accuracy  Precision  Recall  F1-Score
      Rule-based    0.9754     1.0000  0.7497    0.8570
Isolation Forest    0.9483     0.6556  1.0000    0.7920
        Ensemble    0.9750     0.9500  0.8200    0.8800  ⬅️ TARGET!
     Transformer    0.9650     0.7800  0.5600    0.6500  ⬅️ WORKING!
```
✅ Transformer F1 should be **40-60%** (not 0%!)
✅ Ensemble F1 should be **88-91%** (not 83.3%!)

---

### Step 5: Verify Success

**Success Criteria**:

1. ✅ Training completed without errors
2. ✅ Validation PPL: 1.6-2.5 (not 7.04)
3. ✅ Vocabulary size: 200-500 (not 1,287)
4. ✅ `model_meta.json` created with signature
5. ✅ Signature verification: MATCH
6. ✅ Coverage check: ≥90% (not 4.2%)
7. ✅ Transformer F1: 40-60% (not 0%)
8. ✅ Ensemble F1: 88-91% (not 83.3%)

**All green?** 🎉 **SUCCESS!**

---

## Troubleshooting

### Issue 1: Signature Mismatch

**Symptoms**:
```
Training signature: a3f2e1d4c5b6a789
Runtime signature:  b7c8d9e1f2a3b456
Match: ❌ NO

⚠️  SIGNATURE MISMATCH!
⚠️  Detection normalization differs from training!
⚠️  Disabling transformer to prevent vocabulary mismatch
```

**Cause**: You changed normalization settings in one notebook but not the other

**Fix**:
1. Check `NORMALIZER_DESC`, `DRAIN_CONFIG`, `EXTRA_HTTP` in both notebooks
2. Make sure they're IDENTICAL
3. Re-run notebook 08 (training) from beginning
4. Re-run notebook 07 (detection) cells 14-15

### Issue 2: Low Coverage After Training

**Symptoms**:
```
Known templates: 421/9,427 (4.5%)
Threshold: ≥90%

❌ COVERAGE TOO LOW (4.5% < 90%)
⚠️  Disabling transformer
```

**Cause**: Model trained on different data domain than detection logs

**Fix Options**:

**Option A** (Best): Re-train on Apache logs instead of NASA
- Use synthetic Apache normal logs for training
- Creates vocabulary specifically for Apache patterns

**Option B**: Relax normalization (make it more general)
- Reduce bucketing granularity
- Lower sim_th to merge more templates

**Option C**: Accept limitation
- Use rules + IsoForest only (~85% F1)
- Transformer stays disabled for this dataset

### Issue 3: Vocabulary Too Large (>1000)

**Symptoms**:
```
⚠️  WARNING: Vocabulary too large (1,834 templates)
   → Template explosion - normalization not aggressive enough
```

**Cause**: Normalization not bucketing enough

**Fix**:
1. Check that HTTP-aware normalization is actually running
2. Verify extension bucketing is working (should see `<IMG>`, `<HTML>`)
3. Verify status bucketing (should see `<S2XX>`, not `200`)
4. Raise `sim_th` in Drain3 (try 0.50 instead of 0.47)

### Issue 4: Vocabulary Too Small (<100)

**Symptoms**:
```
⚠️  WARNING: Vocabulary too small (47 templates)
   → Normalization might be too aggressive
```

**Cause**: Over-aggressive bucketing

**Fix**:
1. Reduce extension bucketing (allow more specific extensions)
2. Lower `sim_th` in Drain3 (try 0.43 instead of 0.47)
3. Keep more status code variants (e.g., separate 200 vs 201)

---

## Timeline

| Step | Task | Duration |
|------|------|----------|
| 1 | Verify guardrails | Already done! |
| 2 | Re-train notebook 08 | 20-30 min |
| 3 | Validate files | 1 min |
| 4 | Run detection notebook 07 | 3-5 min |
| 5 | Verify success | 1 min |
| **TOTAL** | | **~25-40 minutes** |

---

## Expected Before/After

### Before (Current Broken State)
```
Transformer:
  - Vocabulary: 1,287 templates (wrong format)
  - Coverage: 4.2%
  - F1-Score: 0%
  - Status: ❌ Actively hurting ensemble

Ensemble:
  - F1-Score: 83.3%
  - Status: ❌ Degraded by broken transformer
```

### After (Fixed State)
```
Transformer:
  - Vocabulary: 287 templates (HTTP-aware)
  - Coverage: 94.7%
  - F1-Score: 55%
  - Status: ✅ Contributing to ensemble

Ensemble:
  - F1-Score: 89.2%
  - Status: ✅ All methods harmonized

Guardrails:
  - Signature verification: ✅ Active
  - Coverage check: ✅ Active
  - Auto-disable on mismatch: ✅ Active
```

---

## Ready to Start?

1. Open `notebooks/08_finetune_nasa_dataset.ipynb`
2. Run All Cells (should take ~25 minutes)
3. Watch for the success indicators above
4. Then run `notebooks/07_hybrid_attack_detection.ipynb` cells 14+

**You've got this!** 🚀

The guardrails will catch any issues and give you clear error messages if something goes wrong.
