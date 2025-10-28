"""
Adaptive Online Learning Ensemble Detector
Trains transformer on first N logs while using rule-based + isolation forest,
then activates transformer for full ensemble detection.
"""

import json
import math
import re
import pickle
import threading
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import deque, Counter
from urllib.parse import unquote
from datetime import datetime

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from sklearn.ensemble import IsolationForest

# Import base detector
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from models.ensemble_detector import (
    TemplateTransformer, RuleBasedDetector, ApacheLogNormalizer
)


class OnlineTrainingDataset(Dataset):
    """Dataset for online transformer training"""
    
    def __init__(self, sequences, pad_id):
        self.sequences = sequences
        self.pad_id = pad_id
    
    def __len__(self):
        return len(self.sequences)
    
    def __getitem__(self, idx):
        seq = self.sequences[idx]
        attention_mask = [1 if t != self.pad_id else 0 for t in seq]
        return {
            'input_ids': torch.tensor(seq, dtype=torch.long),
            'attention_mask': torch.tensor(attention_mask, dtype=torch.long)
        }


class AdaptiveEnsembleDetector:
    """
    Adaptive ensemble detector with online transformer training
    
    Workflow:
    1. Phase 1 (0 - warmup_logs): Use Rule-based + Isolation Forest only
    2. Background: Collect templates and train transformer
    3. Phase 2 (warmup_logs+): Activate transformer for full ensemble
    """
    
    def __init__(self, model_dir: Path, warmup_logs: int = 50000, 
                 window_size: int = 20, device: str = 'cpu'):
        self.model_dir = Path(model_dir)
        self.warmup_logs = warmup_logs
        self.window_size = window_size
        self.device = torch.device(device)
        self.normalizer = ApacheLogNormalizer()
        
        # Session windows
        self.session_windows = {}
        
        # Training data collection
        self.training_templates = []  # Collected templates for training
        self.template_to_id = {}      # Template vocabulary
        self.template_counts = Counter()
        self.logs_processed = 0
        self.transformer_ready = False
        self.training_in_progress = False
        
        # Isolation Forest online learning
        self.iso_training_features = []  # Collect features during warmup
        self.iso_forest_ready = False
        
        # Load initial models (rule-based + isolation forest)
        self._load_base_models()
        
        print(f"\n{'='*70}")
        print(f"ADAPTIVE ENSEMBLE DETECTOR - ONLINE LEARNING MODE")
        print(f"{'='*70}")
        print(f"Phase 1: Processing {warmup_logs:,} logs with Rule-based + Isolation Forest")
        print(f"Phase 2: Training Transformer in background")
        print(f"Phase 3: Full ensemble detection after training")
        print(f"{'='*70}\n")
    
    def _load_base_models(self):
        """Load rule-based detector and isolation forest"""
        print("Loading base models (Rule-based + Isolation Forest)...")
        
        # 1. Initialize Isolation Forest (will be trained during warmup)
        self.iso_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
            warm_start=True
        )
        print(f"✓ Initialized Isolation Forest (will train on first {self.warmup_logs:,} logs)")
        
        # 2. Initialize Rule-based detector
        self.rule_detector = RuleBasedDetector()
        print(f"✓ Initialized Rule-based detector")
        
        # 3. Load initial vocabulary (for template extraction)
        vocab_path = self.model_dir / 'template_vocab.json'
        with open(vocab_path, 'r') as f:
            vocab_data = json.load(f)
        
        if isinstance(vocab_data, dict) and 'template_to_id' in vocab_data:
            initial_vocab = vocab_data['template_to_id']
        else:
            initial_vocab = vocab_data
        
        # Start with empty vocabulary (will build from incoming logs)
        self.template_to_id = {}
        self.id_to_template = []
        self.pad_id = 0  # Will be set after training
        
        print(f"✓ Ready to collect templates for transformer training")
        print(f"✓ Base models loaded successfully!\n")
    
    def parse_nginx_log(self, log_line: str) -> Optional[Dict]:
        """Parse nginx access log line (Combined Log Format)
        
        Default nginx combined format:
        $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
        
        Example:
        192.168.1.1 - - [27/Oct/2025:10:00:00 +0000] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
        """
        # nginx Combined Log Format (same as Apache Combined)
        NGINX_PATTERN = re.compile(
            r'^(?P<ip>\S+) '                          # IP address
            r'\S+ \S+ '                                # remote user fields (usually - -)
            r'\[(?P<timestamp>[^\]]+)\] '             # [timestamp]
            r'"(?P<method>\S+) (?P<path>\S+)(?: (?P<protocol>\S+))?" '  # "METHOD path PROTOCOL"
            r'(?P<status>\d+) '                       # status code
            r'(?P<size>\S+)'                          # bytes sent
            r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'  # optional referer and user agent
        )
        
        match = NGINX_PATTERN.match(log_line.strip())
        if not match:
            return None
        
        d = match.groupdict()
        return {
            'ip': d['ip'],
            'method': d.get('method', 'GET'),
            'path': d.get('path', '/'),
            'protocol': d.get('protocol', 'HTTP/1.1'),
            'status': int(d.get('status', 200)),
            'referer': d.get('referer', '-'),
            'user_agent': d.get('user_agent', '-'),
            'raw_line': log_line.strip()
        }
    
    def extract_features(self, log_data: Dict, session_stats: Dict) -> np.ndarray:
        """Extract features for Isolation Forest"""
        try:
            features = [
                session_stats.get('request_count', 1),
                session_stats.get('error_rate', 0.0),
                session_stats.get('unique_paths', 1),
                session_stats.get('error_count', 0),
                1 if log_data.get('method', 'GET') == 'GET' else 0,
                1 if log_data.get('method', 'GET') == 'POST' else 0,
                1 if log_data.get('status', 200) >= 400 else 0,
                len(log_data.get('path', '/')),
                log_data.get('path', '/').count('/'),
                1 if '?' in log_data.get('path', '/') else 0,
                0  # time_hour placeholder
            ]
            
            # Validate all features are numeric
            features = [float(f) for f in features]
            
            return np.array(features, dtype=np.float64).reshape(1, -1)
        except Exception as e:
            print(f"⚠️  Feature extraction error: {e}")
            print(f"   Log data: {log_data}")
            print(f"   Session stats: {session_stats}")
            # Return default safe features
            return np.array([1, 0.0, 1, 0, 1, 0, 0, 1, 1, 0, 0], dtype=np.float64).reshape(1, -1)
    
    def get_template_id(self, log_data: Dict) -> int:
        """Convert log to template ID and collect for training"""
        message = f"{log_data['method']} {log_data['path']} {log_data['protocol']} {log_data['status']}"
        normalized = self.normalizer.normalize(message)
        
        # Add to vocabulary if new
        if normalized not in self.template_to_id:
            tid = len(self.id_to_template)
            self.template_to_id[normalized] = tid
            self.id_to_template.append(normalized)
        else:
            tid = self.template_to_id[normalized]
        
        # Track for training
        self.template_counts[tid] += 1
        
        return tid
    
    def collect_training_data(self, template_id: int, session_id: str):
        """Collect template sequences for transformer training"""
        if session_id not in self.session_windows:
            self.session_windows[session_id] = deque(maxlen=self.window_size)
        
        self.session_windows[session_id].append(template_id)
        
        # Save sequences for training
        if len(self.session_windows[session_id]) >= self.window_size:
            sequence = list(self.session_windows[session_id])
            self.training_templates.append(sequence)
    
    def train_transformer_background(self):
        """Train transformer model in background thread"""
        if self.training_in_progress:
            return
        
        self.training_in_progress = True
        
        print(f"\n{'='*70}")
        print(f"🔄 TRANSFORMER TRAINING STARTED (Background)")
        print(f"{'='*70}")
        print(f"  Templates collected: {len(self.id_to_template):,}")
        print(f"  Training sequences: {len(self.training_templates):,}")
        print(f"  Logs processed: {self.logs_processed:,}")
        print(f"{'='*70}\n")
        
        try:
            # Prepare training data
            vocab_size = len(self.id_to_template) + 1  # +1 for PAD
            self.pad_id = vocab_size - 1
            
            # Create sequences with padding
            padded_sequences = []
            for seq in self.training_templates:
                if len(seq) < self.window_size:
                    seq = seq + [self.pad_id] * (self.window_size - len(seq))
                padded_sequences.append(seq)
            
            # Initialize transformer
            self.transformer = TemplateTransformer(
                vocab_size=vocab_size,
                pad_id=self.pad_id,
                d_model=256,
                n_heads=8,
                n_layers=4,  # Lighter model for faster training
                ffn_dim=1024,
                max_length=self.window_size,
                dropout=0.1
            ).to(self.device)
            
            # Training setup
            dataset = OnlineTrainingDataset(padded_sequences, self.pad_id)
            loader = DataLoader(dataset, batch_size=64, shuffle=True)
            optimizer = torch.optim.AdamW(self.transformer.parameters(), lr=1e-4)
            
            # Quick fine-tuning (3 epochs)
            self.transformer.train()
            epochs = 3
            
            for epoch in range(epochs):
                total_loss = 0
                for batch in loader:
                    input_ids = batch['input_ids'].to(self.device)
                    attention_mask = batch['attention_mask'].to(self.device)
                    
                    # Forward pass
                    logits = self.transformer(input_ids, attention_mask)
                    
                    # Calculate loss (next token prediction)
                    targets = input_ids[:, 1:]
                    logits_shifted = logits[:, :-1, :]
                    
                    loss = F.cross_entropy(
                        logits_shifted.reshape(-1, vocab_size),
                        targets.reshape(-1),
                        ignore_index=self.pad_id
                    )
                    
                    # Backward pass
                    optimizer.zero_grad()
                    loss.backward()
                    optimizer.step()
                    
                    total_loss += loss.item()
                
                avg_loss = total_loss / len(loader)
                print(f"  Epoch {epoch+1}/{epochs} - Loss: {avg_loss:.4f}")
            
            self.transformer.eval()
            
            # Calculate adaptive threshold (95th percentile of training scores)
            self.transformer_threshold = self._calculate_adaptive_threshold(padded_sequences)
            
            # Save trained model to writable directory (/app/logs instead of read-only /app/artifacts)
            save_path = Path('/app/logs') / 'online_transformer.pt'
            torch.save({
                'model_state_dict': self.transformer.state_dict(),
                'vocab_size': vocab_size,
                'template_to_id': self.template_to_id,
                'id_to_template': self.id_to_template,
                'threshold': self.transformer_threshold,
                'logs_trained_on': self.logs_processed
            }, save_path)
            
            print(f"\n{'='*70}")
            print(f"✅ TRANSFORMER TRAINING COMPLETE")
            print(f"{'='*70}")
            print(f"  Model saved: {save_path}")
            print(f"  Vocabulary: {vocab_size:,} templates")
            print(f"  Threshold: {self.transformer_threshold:.4f}")
            print(f"  Now using FULL ENSEMBLE (Rule + Iso + Transformer)")
            print(f"{'='*70}\n")
            
            self.transformer_ready = True
            
        except Exception as e:
            print(f"❌ Transformer training failed: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.training_in_progress = False
    
    def _calculate_adaptive_threshold(self, sequences: List[List[int]]) -> float:
        """Calculate adaptive threshold from training data"""
        scores = []
        
        with torch.no_grad():
            for seq in sequences[:1000]:  # Sample 1000 sequences
                input_ids = torch.tensor([seq], dtype=torch.long).to(self.device)
                attention_mask = torch.tensor(
                    [[1 if t != self.pad_id else 0 for t in seq]], 
                    dtype=torch.long
                ).to(self.device)
                
                logits = self.transformer(input_ids, attention_mask)
                
                # Calculate NLL
                input_shifted = input_ids[:, 1:]
                logits_shifted = logits[:, :-1, :]
                log_probs = F.log_softmax(logits_shifted, dim=-1)
                nll_per_pos = -log_probs.gather(2, input_shifted.unsqueeze(-1)).squeeze(-1)
                mask = attention_mask[:, 1:] == 1
                
                if mask.sum() > 0:
                    avg_nll = nll_per_pos[mask].mean().item()
                    scores.append(avg_nll)
        
        # Use 95th percentile as threshold
        threshold = np.percentile(scores, 95) if scores else 6.5
        return float(threshold)
    
    def calculate_transformer_score(self, sequence: List[int]) -> float:
        """
        Calculate anomaly score from transformer (NLL)
        
        Improved to handle single-log sequences by:
        1. For sequences with 1 template: Score based on start-of-sequence probability
        2. For sequences with 2+ templates: Use standard sequence NLL
        """
        if not self.transformer_ready or len(sequence) < 1:
            return 0.0
        
        # Prepare sequence (pad or truncate)
        original_length = len(sequence)
        if len(sequence) < self.window_size:
            sequence = sequence + [self.pad_id] * (self.window_size - len(sequence))
        else:
            sequence = sequence[-self.window_size:]
        
        input_ids = torch.tensor([sequence], dtype=torch.long).to(self.device)
        attention_mask = torch.tensor(
            [[1 if t != self.pad_id else 0 for t in sequence]], 
            dtype=torch.long
        ).to(self.device)
        
        with torch.no_grad():
            try:
                logits = self.transformer(input_ids, attention_mask)
                
                # For single-template sequences, use the probability of that template at position 0
                if original_length == 1:
                    # Get probability distribution at position 0
                    probs = F.softmax(logits[0, 0, :], dim=-1)
                    template_id = sequence[0]
                    
                    # NLL for this template appearing at start
                    template_prob = probs[template_id].item()
                    if template_prob > 0:
                        nll = -math.log(template_prob)
                        return float(nll)
                    return self.transformer_threshold * 0.5  # Default moderate score
                
                # For multi-template sequences, use standard next-token prediction NLL
                input_shifted = input_ids[:, 1:]
                logits_shifted = logits[:, :-1, :]
                log_probs = F.log_softmax(logits_shifted, dim=-1)
                nll_per_pos = -log_probs.gather(2, input_shifted.unsqueeze(-1)).squeeze(-1)
                
                # Only average over valid (non-padding) positions
                mask = attention_mask[:, 1:] == 1
                valid_nll = nll_per_pos[mask]
                
                if valid_nll.numel() > 0:
                    return valid_nll.mean().item()
                return 0.0
                
            except Exception as e:
                print(f"⚠️  Transformer scoring error: {e}")
                print(f"   Sequence length: {original_length}, Padded: {len(sequence)}")
                return 0.0
    
    def detect(self, log_line: str, session_id: Optional[str] = None) -> Dict:
        """
        Detect anomalies with adaptive learning
        """
        # Parse nginx log
        log_data = self.parse_nginx_log(log_line)
        if not log_data:
            return {
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'phase': 'warmup' if self.logs_processed < self.warmup_logs else 'ensemble',
                'error': 'Failed to parse log'
            }
        
        self.logs_processed += 1
        
        if session_id is None:
            session_id = log_data['ip']
        
        # Initialize session stats
        if session_id not in self.session_windows:
            self.session_windows[session_id] = {
                'templates': deque(maxlen=self.window_size),
                'request_count': 0,
                'error_count': 0,
                'unique_paths': set()
            }
        
        session = self.session_windows[session_id]
        session['request_count'] += 1
        if log_data['status'] >= 400:
            session['error_count'] += 1
        session['unique_paths'].add(log_data['path'])
        
        session_stats = {
            'request_count': session['request_count'],
            'error_count': session['error_count'],
            'error_rate': session['error_count'] / session['request_count'],
            'unique_paths': len(session['unique_paths'])
        }
        
        # Extract template
        template_id = self.get_template_id(log_data)
        session['templates'].append(template_id)
        
        # Phase 1: Warmup - collect training data
        if self.logs_processed <= self.warmup_logs:
            # Collect sequences more aggressively (min 5 instead of full window_size)
            if len(session['templates']) >= 5:
                self.training_templates.append(list(session['templates']))
            
            # Collect features for Isolation Forest training
            features = self.extract_features(log_data, session_stats)
            self.iso_training_features.append(features.flatten())  # Flatten to 1D
        
        # Train models when we cross the warmup threshold (not just exactly at 50k)
        # This handles batch processing where logs_processed might skip 50,000
        if (self.logs_processed >= self.warmup_logs and 
            not self.iso_forest_ready and 
            not self.training_in_progress and
            len(self.iso_training_features) >= self.warmup_logs):
            
            # Train Isolation Forest on collected features
            print(f"\n🔄 Training Isolation Forest on {len(self.iso_training_features):,} samples...")
            self.iso_forest.fit(np.vstack(self.iso_training_features))  # Stack into 2D array
            self.iso_forest_ready = True
            print(f"✅ Isolation Forest trained successfully!\n")
            
            # Start transformer training in background thread
            if len(self.training_templates) > 0:
                print(f"🚀 Starting Transformer training with {len(self.training_templates):,} sequences...")
                training_thread = threading.Thread(target=self.train_transformer_background)
                training_thread.daemon = True
                training_thread.start()
            else:
                print(f"⚠️  WARNING: No training sequences collected!")
                print(f"    Collected templates: {len(self.template_to_id):,}")
                print(f"    Training will not start. Check session window collection.")
        
        # 1. Rule-based detection (always active)
        rule_result = self.rule_detector.detect(
            log_data['path'], 
            log_data['method'], 
            log_data['status']
        )
        
        # 2. Isolation Forest (only after warmup)
        if self.iso_forest_ready:
            try:
                features = self.extract_features(log_data, session_stats)
                
                # Validate feature shape
                if features.shape != (1, 11):
                    print(f"⚠️  Warning: Invalid feature shape {features.shape}, expected (1, 11)")
                    iso_result = {
                        'is_anomaly': 0,
                        'score': 0.0,
                        'status': 'feature_error'
                    }
                else:
                    iso_pred = self.iso_forest.predict(features)[0]
                    iso_score = -self.iso_forest.score_samples(features)[0]
                    iso_result = {
                        'is_anomaly': int(iso_pred == -1),
                        'score': float(iso_score)
                    }
            except Exception as e:
                print(f"⚠️  Isolation Forest error: {e}")
                print(f"   Features: {features if 'features' in locals() else 'not extracted'}")
                print(f"   Session stats: {session_stats}")
                print(f"   Log data: {log_data}")
                iso_result = {
                    'is_anomaly': 0,
                    'score': 0.0,
                    'status': f'error: {str(e)[:50]}'
                }
        else:
            # During warmup, don't use Isolation Forest for detection
            iso_result = {
                'is_anomaly': 0,
                'score': 0.0,
                'status': 'collecting_baseline'
            }
        
        # 3. Transformer (only if trained)
        if self.transformer_ready:
            sequence_length = len(session['templates'])
            transformer_score = self.calculate_transformer_score(list(session['templates']))
            transformer_result = {
                'is_anomaly': 1 if transformer_score > self.transformer_threshold else 0,
                'score': float(transformer_score),
                'threshold': float(self.transformer_threshold),
                'sequence_length': sequence_length,
                'context': 'single_log' if sequence_length == 1 else f'{sequence_length}_logs'
            }
        else:
            transformer_result = {
                'is_anomaly': 0,
                'score': 0.0,
                'status': 'training' if self.training_in_progress else 'collecting_data'
            }
        
        # Ensemble voting
        votes = []
        weights = []
        
        # Rule-based (always active)
        if rule_result['is_attack']:
            votes.append(1)
            weights.append(rule_result['confidence'])
        else:
            votes.append(0)
            weights.append(0.3)
        
        # Isolation Forest (only if trained)
        if self.iso_forest_ready:
            votes.append(iso_result['is_anomaly'])
            weights.append(0.6)
        
        # Transformer (only if ready)
        if self.transformer_ready:
            votes.append(transformer_result['is_anomaly'])
            weights.append(0.7)
        
        total_weight = sum(weights)
        weighted_sum = sum(v * w for v, w in zip(votes, weights))
        ensemble_score = weighted_sum / total_weight if total_weight > 0 else 0.0
        is_anomaly = ensemble_score > 0.5
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': ensemble_score,
            'phase': 'warmup' if self.logs_processed <= self.warmup_logs else (
                'training' if self.training_in_progress else 'ensemble'
            ),
            'logs_processed': self.logs_processed,
            'transformer_ready': self.transformer_ready,
            'isolation_forest_ready': self.iso_forest_ready,
            'rule_based': rule_result,
            'isolation_forest': iso_result,
            'transformer': transformer_result,
            'ensemble': {
                'score': ensemble_score,
                'votes': dict(zip(['rule', 'iso', 'transformer'], votes)),
                'weights': dict(zip(['rule', 'iso', 'transformer'], weights)),
                'active_models': sum([1, int(self.iso_forest_ready), int(self.transformer_ready)])
            },
            'log_data': log_data
        }
