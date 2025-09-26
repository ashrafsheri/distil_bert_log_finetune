# Log Anomaly Modeling with DistilBERT

Notebook-first workflow for pretraining and fine-tuning a transformer-based log anomaly detector. The pipeline:

1. **Prepare data** (`notebooks/00_prepare_data.ipynb`): download HDFS/OpenStack logs, normalize text, mine templates with Drain3, and generate tokenized Parquet splits.
2. **Pretrain** (`notebooks/01_pretrain_hdfs.ipynb`): multi-GPU masked language modeling on HDFS with Hugging Face Accelerate, saving checkpoints and metrics.
3. **Fine-tune** (`notebooks/02_finetune_openstack.ipynb`): adapt the checkpoint to OpenStack anomalies with optional replay and LoRA, evaluate, and export TorchScript/ONNX models.

## Target Environment

- Linux workstation with **2 × NVIDIA RTX 6000 (Ada)** GPUs (48 GB each)
- CUDA 12.1 drivers or newer
- Python 3.10 (Conda or venv recommended)
- At least 250 GB free disk space for datasets, checkpoints, and exports

## Quick Start

```bash
# 1. Create environment
python3.10 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip

# 2. Install pinned dependencies
pip install -r requirements.txt

# 3. Launch JupyterLab (recommended)
jupyter lab
```

Open the notebooks in order (`00` → `01` → `02`) and run every cell top to bottom. Each notebook is idempotent; rerun cells as needed.

## Apple Silicon (MPS)

Running on macOS with Apple Silicon GPUs is supported out of the box. The training notebooks auto-detect MPS, skip the multi-GPU Accelerate config, and fall back to full precision when needed. Ensure you install the CUDA-free (CPU/MPS) builds of PyTorch from the same `requirements.txt`. If you prefer CPU only, set `ACCELERATE_USE_MPS_DEVICE=0` before launching the notebooks.

## Configuration Files

- `configs/data.yaml`: raw data paths, regex normalization rules, Drain3 parameters, and split ratios.
- `configs/train_hdfs.yaml`: pretraining hyperparameters, checkpoint cadence, Accelerate settings.
- `configs/train_openstack.yaml`: fine-tuning hyperparameters, replay/LoRA toggles, export settings.

Tweak YAML values as needed, then rerun the relevant notebooks. The notebooks validate settings at runtime and will raise if essential files are missing.

## Expected Artifacts

- Tokenizer: `artifacts/tokenizer/`
- Drain3 outputs: `artifacts/drain3/`
- Tokenized datasets: `artifacts/datasets/*.parquet` and `*_hf/`
- Pretraining checkpoints and metrics: `artifacts/logbert-mlm-hdfs/`, `artifacts/metrics/hdfs/`
- Fine-tuned checkpoints and exports: `artifacts/logbert-mlm-os/`, `artifacts/exported_models/`, `artifacts/metrics/openstack/`, `artifacts/eval/`

## Troubleshooting

| Issue | Suggested Fix |
|-------|----------------|
| Download mirrors fail | Edit `configs/data.yaml` with alternative URLs or pre-download the archives and place them under `data/`; rerun `00_prepare_data.ipynb`. |
| SHA mismatch | Delete the corrupt file, update the expected hash (if known), and rerun the download cell. |
| CUDA OOM during training | Reduce `train_batch_size_per_device`, enable gradient checkpointing (`configs/train_hdfs.yaml` / `train_openstack.yaml`), or increase `grad_accumulation_steps`. |
| Accelerate timeout | Check firewall blocks on port 29500 or set a custom port in `configs/train_hdfs.yaml` / `accelerate_config.yaml`. |
| Slow template mining | Adjust `drain3.max_children` or `drain3.depth` in `configs/data.yaml`, or run Drain3 on a smaller chunk first. |

## Verification Checklist

- `00_prepare_data.ipynb`: dataset head tables, normalization preview, Drain3 summary, and dataset stats tables rendered.
- `01_pretrain_hdfs.ipynb`: Accelerate state printed, throughput line in progress bar, validation loss logged every epoch, checkpoints written under `artifacts/logbert-mlm-hdfs/`.
- `02_finetune_openstack.ipynb`: Early stopping message (or full epochs), confusion matrix saved to `artifacts/eval/confusion_matrix.png`, metrics JSON reporting F1 ≥ 0.85, ROC-AUC ≥ 0.90, PR-AUC ≥ 0.80.

## Tips

- For alternate GPU counts, edit `configs/train_hdfs.yaml` and rerun the Accelerate configuration cell before training.
- To enable Deepspeed ZeRO-2, set `accelerate.zero_stage2_toggle: true` in the training YAML and rerun the notebook cell that regenerates `accelerate_config.yaml`.
- Artifact directories are reused; delete subfolders if you need a clean slate.

Questions or issues? Inspect notebook markdown callouts for context and rerun the helper cells—they are safe to execute repeatedly.
