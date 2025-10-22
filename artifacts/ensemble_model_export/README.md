# Ensemble Model Export

## Model Components

This directory contains the exported ensemble model for Apache log anomaly detection.

### Files:
1. **transformer_model.pt** - Apache attack fine-tuned transformer
   - Vocabulary size: 6 templates
   - Model parameters: 16,925,850
   - Architecture: 6 layers, 8 attention heads

2. **template_vocab.json** - Template vocabulary mapping
   - Total templates: 6
   - Attack-preserving normalization

3. **isolation_forest.pkl** - Statistical anomaly detector
   - Estimators: 100
   - Features: IP request count, error rate, unique paths

4. **model_config.json** - Model configuration and thresholds
   - Optimal threshold: 12.2188
   - Ensemble weights
   - Sequence parameters

## Usage

Load this model using notebook **11_ensemble_model_inference.ipynb**:

```python
# Load transformer
model = TemplateTransformer(vocab_size, ...)
checkpoint = torch.load('transformer_model.pt')
model.load_state_dict(checkpoint['model_state_dict'])

# Load vocabulary
with open('template_vocab.json', 'r') as f:
    vocab = json.load(f)

# Load Isolation Forest
with open('isolation_forest.pkl', 'rb') as f:
    iso_forest = pickle.load(f)

# Load config
with open('model_config.json', 'r') as f:
    config = json.load(f)
    optimal_threshold = config['optimal_threshold']
```

## Model Performance

Trained on: 150,000 Apache logs (85% normal, 15% attacks)
Attack types: SQL injection, XSS, path traversal, command injection, brute force, scanner, DDoS, data exfil, API abuse

Expected F1-Score: 0.50-0.75 (depends on test data domain match)

## Detection Methods

1. **Rule-Based** - Pattern matching for known attack signatures
2. **Isolation Forest** - Statistical anomaly detection
3. **Transformer** - Behavioral sequence analysis
4. **Ensemble** - Weighted voting combination

Export date: 2025-10-13 22:10:03
