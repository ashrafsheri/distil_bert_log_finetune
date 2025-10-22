# OpenStack Transformer Fine-tuning Results

## Training Configuration
- **Model**: Template Transformer (Next-Token Prediction)
- **Pretrained From**: HDFS checkpoint (epoch-2 / checkpoint_2M.pt)
- **Dataset**: OpenStack Logs
- **Vocabulary Size**: 159
- **Max Sequence Length**: 100
- **Model Parameters**: 4,846,239
- **Model Size**: 18.49 MB

## Architecture
- **d_model**: 256
- **Layers**: 6
- **Attention Heads**: 8
- **FFN Dimension**: 1024
- **Dropout**: 0.1

## Fine-tuning Hyperparameters
- **Optimizer**: AdamW
- **Learning Rate**: 3e-4 (lower than pretrain)
- **Betas**: (0.9, 0.98) - β2=0.98 for faster adaptation
- **Weight Decay**: 0.01
- **Scheduler**: Warmup (5%) + Cosine Decay
- **Warmup Steps**: 61
- **Early Stopping**: Patience 2 epoch(s)
- **Sample Checkpointing**: Every 250k samples

## Training Results
- **Total Epochs**: 10
- **Total Samples**: 77,480
- **Training Time**: 0.4 minutes
- **Best Validation Loss**: 0.2649
- **Best Validation Perplexity**: 1.30
- **Test Loss**: 0.6828
- **Test Perplexity**: 1.98

## Files
- `best.pt` - Best model checkpoint (lowest validation loss)
- `last.pt` - Final model checkpoint
- `checkpoint_XXXk.pt` - Sample-based checkpoints (every 250k samples)
- `training_curves.png` - Training metrics visualization
- `training_summary.png` - Comprehensive performance summary
- `training_history.csv` - Detailed epoch-by-epoch metrics
- `openstack_transformer_metrics.json` - Complete metrics in JSON format
- `checkpoint_inventory.csv` - List of all checkpoint files

## Usage
Load the best model:
```python
import torch
checkpoint = torch.load('best.pt')
model.load_state_dict(checkpoint['model_state_dict'])
```

## Training History
See `training_history.csv` for detailed epoch-by-epoch metrics.

## Notes
- Fine-tuned from HDFS pretrained checkpoint (epoch-2)
- Used aggressive early stopping (patience=2) to prevent overfitting
- Lower learning rate (3e-4) compared to pretraining for stable fine-tuning
- β2=0.98 instead of 0.999 for faster adaptation to OpenStack domain
- Sample checkpointing every 250k samples (smaller interval than HDFS 1M)
