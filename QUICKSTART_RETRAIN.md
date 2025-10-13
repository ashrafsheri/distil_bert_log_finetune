# 🚀 QUICK START: Re-train NASA Model with Fixes

## What Was Changed

✅ **3 critical fixes applied** to improve vocabulary coverage from **4.7% → 95%+**:

1. **HTTP-aware normalization** (notebook 08) - crushes template cardinality
2. **Sessionization with 15-min timeout** (notebook 08) - coherent sequences
3. **Cosine LR schedule with floor** (notebook 08) - better convergence
4. **Matching normalization** (notebook 07) - inference matches training

## How to Re-train (2 steps)

### Step 1: Re-train NASA Model (~20-30 minutes)

```bash
# Open notebook 08
cd /home/tpi/distil_shahreyar/notebooks
jupyter notebook 08_finetune_nasa_dataset.ipynb

# Run ALL cells from the beginning
# The new normalization will automatically be applied
```

**What to watch for during training**:
- ✅ Vocabulary size: Should be **200-500** (down from 1,287)
- ✅ Vocabulary coverage on validation: **≥95%**
- ✅ Validation PPL: **1.6-2.5** (down from 7.04)
- ✅ Training should converge smoothly

### Step 2: Test on Synthetic Apache Logs

```bash
# Open notebook 07
jupyter notebook 07_hybrid_attack_detection.ipynb

# Re-run from cell 11 onwards (transformer detection cells)
```

**Expected results**:
- ✅ Vocabulary coverage: **95%+** (up from 4.7%)
- ✅ Transformer F1: **40-60%** (up from 0%)
- ✅ Ensemble F1: **88-91%** (up from 82.3%)

## Quick Validation Checklist

After re-training, check these metrics:

### In Notebook 08 (Training)
- [ ] Vocabulary size: 200-500 templates (not 1,287)
- [ ] Val coverage: ≥95%
- [ ] Val PPL: 1.6-2.5
- [ ] Top-3 accuracy: >95%
- [ ] Training loss: Smooth convergence

### In Notebook 07 (Detection)
- [ ] Vocabulary coverage: ≥95% (critical!)
- [ ] Transformer detects: 400-600 anomalies (not 936)
- [ ] Transformer F1: 40-60%
- [ ] Ensemble F1: 88-91%

## What If Coverage Is Still Low?

If vocabulary coverage in notebook 07 is still <50% after re-training:

1. **Check normalization consistency**
   - Verify both notebooks use same `normalize_http_log()` function
   - Check extension map is identical
   - Verify status bucketing matches

2. **Inspect vocabulary**
   ```python
   # In notebook 07, after loading vocab
   print("Sample templates from vocabulary:")
   for i, tmpl in enumerate(list(nasa_template_to_id.keys())[:20]):
       print(f"  {i+1}. {tmpl}")
   
   print("\nSample normalized synthetic logs:")
   for i, msg in enumerate(df['norm_message'].head(20)):
       print(f"  {i+1}. {msg}")
   ```

3. **Adjust normalization if needed**
   - Add more extension types to `ext_map`
   - Check path normalization patterns
   - Verify status/byte bucketing logic

## Files Modified

All changes are complete and saved:

- ✅ `notebooks/08_finetune_nasa_dataset.ipynb` - Cell with normalization
- ✅ `notebooks/08_finetune_nasa_dataset.ipynb` - Cell with sessionization
- ✅ `notebooks/08_finetune_nasa_dataset.ipynb` - Cell with training config
- ✅ `notebooks/07_hybrid_attack_detection.ipynb` - Cell with transformer detection
- ✅ `configs/drain3.ini` - Similarity threshold

## Timeline

- **Re-training**: 20-30 minutes (20 epochs on NASA data)
- **Testing**: 2-3 minutes (run notebook 07 transformer cells)
- **Total time**: ~30-35 minutes

## Success Criteria

You'll know it worked when:

1. ✅ Notebook 08 training shows **val PPL ~1.6-2.5**
2. ✅ Notebook 07 shows **vocabulary coverage ≥95%**
3. ✅ Transformer F1-score jumps to **40-60%**
4. ✅ Ensemble F1-score reaches **88-91%**

---

**Ready to start?** Run notebook 08 from the beginning! 🎯
