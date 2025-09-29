# Notebooks Guide

This project ships a small suite of notebooks that take you from raw log ingestion through synthetic evaluation. Use this guide as the operating manual for each notebook, including prerequisites, key parameters, generated artifacts, and tips for customization.

---

## 00 · Prepare Data (`notebooks/00_prepare_data.ipynb`)
**Goal**: Download, normalize, and persist HDFS/OpenStack logs into HF datasets + parquet for downstream training.

- **Inputs**
  - Configuration: `configs/data.yaml` (dataset URLs, normalization rules, output dirs)
  - Optional cached archives under `artifacts/cache`
- **Workflow**
  1. Validates SHA hashes, downloads archives, and unpacks raw logs.
  2. Applies regex-based normalizer (IPs, UUIDs, paths) producing token-clean text.
  3. Extracts Drain3 templates and transition stats.
  4. Splits logs by time using `splits` ratios in config.
  5. Saves Hugging Face `Dataset` objects to `artifacts/datasets/*` and parquet copies for replay.
- **Outputs**
  - Normalized datasets (`openstack_train_hf`, `hdfs_train_hf`, etc.)
  - Metadata: `artifacts/metadata/datasets.json`
  - Drain3 artifacts: `artifacts/drain3/*`
- **Customization**
  - Tune normalization rules in `data.yaml` to add Node.js patterns or service-specific placeholders.
  - Adjust split ratios or enforce minimum samples per split through config.

## 01 · Pretrain on HDFS (`notebooks/01_pretrain_hdfs.ipynb`)
**Goal**: Run masked-language-model pretraining on the HDFS corpus to bootstrap a strong log-specific backbone.

- **Inputs**
  - Tokenizer settings from `configs/data.yaml`.
  - HDFS HF dataset (`hdfs_train_hf`, `hdfs_val_hf`).
  - Training hyperparameters from `configs/train_openstack.yaml` (sequence length, batch size, scheduler parameters partially reused).
- **Workflow**
  - Loads base DistilBERT checkpoint (`artifacts/tokenizer` + `artifacts/logbert-mlm-hdfs`).
  - Constructs MLM dataloaders using the normalized HDFS dataset.
  - Trains with `accelerate` (supports multi-GPU/FP16) and saves periodic checkpoints.
  - Logs training/validation loss history and exports metrics.
- **Outputs**
  - Checkpoints under `artifacts/logbert-mlm-hdfs/` (`epoch*_final`, `best`).
  - Training history plots + metrics in `artifacts/eval/hdfs_pretrain/`.
- **Customization**
  - Adjust `mlm_probability`, gradient accumulation, or replay strategy to match hardware.
  - Enable/disable LoRA adapters via `train_openstack.yaml`.

---

## 02 · Fine-tune on OpenStack (`notebooks/02_finetune_openstack.ipynb`)
**Goal**: Take the HDFS-pretrained MLM and specialize it on OpenStack logs (with optional replay) while calibrating an anomaly threshold.

- **Inputs**
  - Pretrained checkpoint from `artifacts/logbert-mlm-hdfs`.
  - OpenStack HF datasets (`openstack_train/val/test_hf`) and optional HDFS replay data.
  - Hyperparameters from `configs/train_openstack.yaml` (epochs, patience, learning rate, etc.).
- **Workflow**
  1. Loads configs, datasets, and merges replay samples based on `replay.ratio`.
  2. Builds an MLM collator pegged to `max_length` and masking probability.
  3. Runs `accelerate` training loop with validation-based early stopping.
  4. Recomputes per-sample losses on val/test sets, sweeps thresholds, and reports metrics.
  5. Saves diagnostics (loss histograms, PR curve) and structured metrics JSON/CSV.
- **Outputs**
  - Best fine-tuned checkpoint at `artifacts/logbert-mlm-os/best`.
  - Threshold sweep CSV + metrics JSON in `artifacts/metrics/openstack/`.
  - Evaluation plots in `artifacts/eval/openstack_finetune_diagnostics.png`.
  - Run configuration snapshot: `artifacts/logbert-mlm-os/run_config.json`.
- **Customization**
  - Modify replay ratio or disable via config.
  - Swap in another dataset (e.g., Node.js) by editing the dataset load cell.
  - Extend threshold analysis with per-service segmentation by editing the evaluation cells.

---

## 03 · Synthetic Log Inference (`notebooks/03_synthetic_log_inference.ipynb`)
**Goal**: Validate the fine-tuned model on large synthetic OpenStack control-plane logs and visualize detector quality.

- **Inputs**
  - Fine-tuned model (`artifacts/logbert-mlm-os/best`) and tokenizer.
  - Stored anomaly threshold from fine-tuning (if available) to compare against newly optimized cuts.
- **Workflow**
  - Generates 50k synthetic OpenStack logs (nova/neutron/cinder/keystone/glance) with ~15% labeled anomalies.
  - Tokenizes logs, computes per-sample MLM losses, and sweeps thresholds for F1 maximization.
  - Compares “trained” vs “synthetic optimal” thresholds, prints metrics, and saves predictions/thresh sweeps.
  - Plots loss distributions, confusion matrix, and ROC curve; stores artifacts under `artifacts/eval/synthetic_pipeline/`.
- **Outputs**
  - `synthetic_predictions.csv`, `threshold_metrics.csv`, `threshold_sweep.csv`, `metrics.json` within `artifacts/eval/synthetic_pipeline/`.
  - Diagnostic plot `diagnostics.png` in the same directory.
- **Customization**
  - Adjust `total_logs` or `anomaly_ratio` when instantiating `OpenStackLogGenerator`.
  - Replace the generator with real log batches to perform offline evaluation on production data.
  - Extend the plotting cell to include service-specific metrics or temporal analyses.

---

## Operating Tips
- Run notebooks in numeric order (00 → 03) when building the full pipeline from scratch.
- Keep `configs/train_openstack.yaml` and `configs/data.yaml` under version control; all notebooks read settings from there, minimizing manual edits.
- Whenever checkpoints or artifacts are regenerated, clear or archive old metrics folders to avoid mixing results across runs.
- For automation, consider exporting critical notebook logic into scripts and invoke them via `papermill` or `nbconvert --execute` for reproducible pipeline runs.

