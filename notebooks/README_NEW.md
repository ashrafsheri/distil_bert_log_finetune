# Notebooks

Jupyter notebooks for the complete log anomaly detection pipeline.

## Pipeline Overview

```
00_prepare_data.ipynb
    ↓ (HDFS + OpenStack logs → Drain3 templates)
01_pretrain_hdfs.ipynb
    ↓ (Pretrain on HDFS, save checkpoint_2M.pt)
02_finetune_openstack.ipynb
    ↓ (Fine-tune on OpenStack, save best.pt)
03_anomaly_detection.ipynb
    ↓ (Calibrate thresholds, detect anomalies)
```

## Notebook Descriptions

### 00_prepare_data.ipynb - Data Preprocessing
**Purpose**: Parse raw logs and mine templates using Drain3

**Features**:
- Robust log parsers for HDFS (compact format) and OpenStack
- Drain3 template mining with proper configuration
- Train/val/test split generation
- Template vocabulary export

**Outputs**:
- `artifacts/hdfs_pretrain/{train,val,test}.parquet`
- `artifacts/hdfs_pretrain/template_vocab.json`
- `artifacts/openstack_finetune/{train,val,test}.parquet`
- `artifacts/openstack_finetune/template_vocab.json`

---

### 01_pretrain_hdfs.ipynb - HDFS Pretraining
**Purpose**: Pretrain template transformer on HDFS logs

**Features**:
- NextTokenTransformer with causal attention
- Sample-based checkpointing (every 1M samples)
- Comprehensive diagnostics (coverage, positional entropy, top-k accuracy)

**Outputs**:
- `artifacts/hdfs_transformer/checkpoint_2M.pt` (epoch-2, for fine-tuning)
- `artifacts/hdfs_transformer/best.pt`
- Training visualizations + metrics

---

### 02_finetune_openstack.ipynb - OpenStack Fine-tuning
**Purpose**: Fine-tune pretrained model on OpenStack logs

**Features**:
- Loads epoch-2 checkpoint from HDFS
- Intelligent embedding resizing
- Optimized for transfer learning (LR 3e-4, β2=0.98)
- Sample checkpointing every 250k samples

**Outputs**:
- `artifacts/openstack_finetune_model/best.pt`
- Training visualizations + comprehensive metrics

---

### 03_anomaly_detection.ipynb - **NEW!** Threshold Calibration & Detection
**Purpose**: Calibrate anomaly thresholds and evaluate detection

**Features**:
- Threshold calibration on normal validation windows (99.5th percentile)
- Multiple scoring methods (NLL, PPL, unseen template rate)
- Comprehensive diagnostics
- Auto-generated recommendations

**Outputs**:
- `artifacts/metrics/openstack/anomaly_detection_results.json`
- `artifacts/metrics/openstack/anomaly_diagnostics.json`
- Threshold calibration + positional entropy plots

---

## Execution Order

1. `00_prepare_data.ipynb` - Generate datasets
2. `01_pretrain_hdfs.ipynb` - Pretrain on HDFS  
3. `02_finetune_openstack.ipynb` - Fine-tune on OpenStack
4. `03_anomaly_detection.ipynb` - **NEW!** Calibrate & detect

---

## Key Improvements (Latest Updates)

### HDFS Pretraining (01)
✅ Added diagnostic analysis cells:
- Template coverage (val/test unseen template detection)
- Positional entropy (loss/PPL by sequence position)
- Top-k accuracy (top-1/3/5/10 next-template prediction)

### OpenStack Fine-tuning (02)
✅ Complete rewrite with transfer learning best practices:
- Uses epoch-2 checkpoint (`checkpoint_2M.pt`)
- Optimized hyperparameters: LR 3e-4, β2=0.98, warmup+cosine
- Intelligent embedding resizing (preserves pretrained weights)
- Aggressive early stopping (patience 1-2 epochs)
- Denser checkpointing (250k vs 1M samples)
- Multi-GPU support

### Anomaly Detection (03)
✅ **NEW NOTEBOOK** - Production-ready detection pipeline:
- Calibrates thresholds on normal windows (99.5th percentile)
- Hard rule: Flag if unseen template rate > 5%
- Comprehensive diagnostics (coverage + positional entropy)
- Auto-recommendations for Drain3/training improvements
- Test set evaluation with precision/recall/F1

---

## Production Deployment

Save these artifacts for deployment:
- `artifacts/openstack_finetune_model/best.pt`
- `artifacts/openstack_finetune/template_vocab.json`
- `artifacts/metrics/openstack/anomaly_detection_results.json` (thresholds)

See `03_anomaly_detection.ipynb` for full inference pipeline code.
