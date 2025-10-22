# HDFS Transformer Pretraining Results

## Training Configuration
- **Model**: Template Transformer (Next-Token Prediction)
- **Dataset**: HDFS Logs
- **Vocabulary Size**: 119
- **Max Sequence Length**: 100
- **Model Parameters**: 4,825,719
- **Model Size**: 18.41 MB

## Architecture
- **d_model**: 256
- **Layers**: 6
- **Attention Heads**: 8
- **FFN Dimension**: 1024
- **Dropout**: 0.1

## Training Results
- **Total Epochs**: 5
- **Total Samples**: 2,300,595
- **Training Time**: 4.7 minutes
- **Best Validation Loss**: 0.5099
- **Best Validation Perplexity**: 1.67
- **Test Loss**: 0.4618
- **Test Perplexity**: 1.59

## Files
- `best.pt` - Best model checkpoint (lowest validation loss)
- `last.pt` - Final model checkpoint
- `checkpoint_XM.pt` - Sample-based checkpoints (every 1M samples)
- `training_curves.png` - Training metrics visualization
- `training_summary.png` - Comprehensive performance summary
- `training_history.csv` - Detailed epoch-by-epoch metrics
- `hdfs_transformer_metrics.json` - Complete metrics in JSON format
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
