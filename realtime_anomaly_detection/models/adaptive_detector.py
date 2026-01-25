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
import os
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
import logging

# Import base detector
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from models.ensemble_detector import (
    TemplateTransformer, RuleBasedDetector, ApacheLogNormalizer
)

logger = logging.getLogger(__name__)

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
        self.training_templates = []  # Collected template windows for transformer training
        self.template_to_id = {}      # Template vocabulary (log template -> integer id)
        self.template_counts = Counter()
        self.unseen_templates = Counter()  # Track templates seen after vocabulary freeze
        self.persistence_dir = self._resolve_persistence_dir()
        self.logs_processed = 0
        self.transformer_ready = False
        self.training_in_progress = False
        self.transformer_threshold = 0.0
        self.vocab_frozen = False
        self.pad_id: Optional[int] = None
        self.unknown_id: Optional[int] = None
        self.vocab_size: Optional[int] = None
        
        # Isolation Forest online learning
        self.iso_feature_store_max = max(200_000, warmup_logs * 2)
        self.iso_training_features = deque(maxlen=self.iso_feature_store_max)
        self.iso_forest_ready = False
        self.iso_retrain_interval = max(10_000, warmup_logs // 5)
        self.iso_min_samples = max(1_000, warmup_logs // 10)
        self.iso_last_retrain_log = 0
        self.iso_retraining = False
        self.iso_score_threshold: Optional[float] = None
        
        # Load initial models (rule-based + isolation forest)
        self._load_base_models()
        
        logger.info(f"\n{'='*70}")
        logger.info(f"ADAPTIVE ENSEMBLE DETECTOR - ONLINE LEARNING MODE")
        logger.info(f"{'='*70}")
        logger.info(f"Phase 1: Processing {warmup_logs:,} logs with Rule-based + Isolation Forest")
        logger.info(f"Phase 2: Training Transformer in background")
        logger.info(f"Phase 3: Full ensemble detection after training")
        logger.info(f"{'='*70}\n")
    
    def _load_base_models(self):
        """Load rule-based detector, isolation forest, and check for saved transformer"""
        logger.info("Loading base models (Rule-based + Isolation Forest)...")
        
        # 1. Initialize Isolation Forest
        self.iso_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
            warm_start=True
        )
        
        # 2. Initialize Rule-based detector
        self.rule_detector = RuleBasedDetector()
        logger.info(f"Initialized Rule-based detector")
        
        # 3. Load initial vocabulary (for template extraction)
        vocab_path = self.model_dir / 'template_vocab.json'
        with open(vocab_path, 'r') as f:
            vocab_data = json.load(f)
        
        if isinstance(vocab_data, dict) and 'template_to_id' in vocab_data:
            initial_vocab = vocab_data['template_to_id']
        else:
            initial_vocab = vocab_data
        
        # Seed vocabulary (templates will be added dynamically during warmup)
        self.template_to_id = {}
        self.id_to_template = []
        if initial_vocab:
            self._initialize_template_vocab(initial_vocab)
        
        # 4. Try to load previously trained transformer and isolation forest
        saved_state_path = self.persistence_dir / 'detector_state.pkl'
        saved_transformer_path = self.persistence_dir / 'online_transformer.pt'
        
        # Case 1: Both state and transformer exist
        if saved_state_path.exists() and saved_transformer_path.exists():
            logger.info(f"\nFound saved models, loading...")
            try:
                # Load detector state (vocabulary, counters, etc.)
                with open(saved_state_path, 'rb') as f:
                    state = pickle.load(f)
                
                self.logs_processed = state.get('logs_processed', 0)
                self.template_to_id = state.get('template_to_id', {})
                self.id_to_template = state.get('id_to_template', [])
                self.template_counts = Counter(state.get('template_counts', {}))
                self.iso_forest_ready = state.get('iso_forest_ready', False)
                self.vocab_frozen = state.get('vocab_frozen', False)
                self.pad_id = state.get('pad_id')
                self.unknown_id = state.get('unknown_id')
                self.vocab_size = state.get('vocab_size')
                self.unseen_templates = Counter(state.get('unseen_templates', {}))
                self.iso_score_threshold = state.get('iso_score_threshold')
                self.iso_last_retrain_log = state.get('iso_last_retrain_log', 0)
                
                # Load isolation forest if it was trained
                if self.iso_forest_ready and 'iso_forest_model' in state:
                    self.iso_forest = state['iso_forest_model']
                    logger.info(f"Loaded trained Isolation Forest")
                
                # Load transformer
                checkpoint = torch.load(saved_transformer_path, map_location=self.device)
                self._load_transformer_from_checkpoint(checkpoint)
                
                logger.info(f"Loaded trained Transformer")
                logger.info(f"  Logs processed: {self.logs_processed:,}")
                logger.info(f"  Vocabulary size: {len(self.id_to_template):,}")
                logger.info(f"  Transformer threshold: {self.transformer_threshold:.4f}")
                logger.info(f"  Isolation Forest ready: {self.iso_forest_ready}")
                logger.info(f"\nResumed from saved state - FULL ENSEMBLE ACTIVE!\n")
                
            except Exception as e:
                logger.warning(f"Failed to load saved models: {e}")
                logger.info(f"   Starting fresh...\n")
                self.logs_processed = 0
                self.template_to_id = {}
                self.id_to_template = []
                self.transformer_ready = False
                self.iso_forest_ready = False
        
        # Case 2: Only transformer exists (old save, no state file)
        elif saved_transformer_path.exists():
            logger.info(f"\nFound saved transformer, loading (partial restore)...")
            try:
                checkpoint = torch.load(saved_transformer_path, map_location=self.device)
                
                # Restore from checkpoint metadata
                self.template_to_id = checkpoint.get('template_to_id', {})
                self.id_to_template = checkpoint.get('id_to_template', [])
                self.logs_processed = checkpoint.get('logs_trained_on', self.warmup_logs)
                
                self._load_transformer_from_checkpoint(checkpoint)
                
                # Mark isolation forest as ready (assume it was trained)
                self.iso_forest_ready = True
                
                logger.info(f"Loaded trained Transformer (partial restore)")
                logger.info(f"  Vocabulary size: {len(self.id_to_template):,}")
                logger.info(f"  Transformer threshold: {self.transformer_threshold:.4f}")
                logger.warning(f"  Isolation Forest state not saved - will retrain if needed")
                logger.info(f"\nTransformer active! (Isolation Forest using defaults)\n")
                
            except Exception as e:
                logger.warning(f"Failed to load transformer: {e}")
                logger.info(f"   Starting fresh...\n")
                self.logs_processed = 0
                self.template_to_id = {}
                self.id_to_template = []
                self.transformer_ready = False
                self.iso_forest_ready = False
        
        # Case 3: No saved models
        else:
            logger.info(f"No saved models found, starting fresh")
            logger.info(f"Will train Isolation Forest on first {self.warmup_logs:,} logs")
            logger.info(f"Ready to collect templates for transformer training\n")
    
    def _initialize_template_vocab(self, initial_vocab):
        """Seed template vocabulary from exported metadata"""
        if not initial_vocab:
            return
        
        if isinstance(initial_vocab, dict):
            # Sort by assigned id to preserve ordering if provided
            items = sorted(initial_vocab.items(), key=lambda item: item[1])
            for template, _ in items:
                self._add_template_to_vocab(template)
        elif isinstance(initial_vocab, list):
            for template in initial_vocab:
                self._add_template_to_vocab(template)
    
    def _add_template_to_vocab(self, template: str) -> int:
        """Add template string to vocabulary if unseen"""
        if not template:
            return self.template_to_id.get(template, -1)
        
        if template in self.template_to_id:
            return self.template_to_id[template]
        
        template_id = len(self.id_to_template)
        self.template_to_id[template] = template_id
        self.id_to_template.append(template)
        return template_id
    
    def _load_transformer_from_checkpoint(self, checkpoint: Dict):
        """Restore transformer weights and metadata from checkpoint"""
        saved_state = checkpoint['model_state_dict']
        original_vocab_size = checkpoint['vocab_size']
        pad_id = checkpoint.get('pad_id', original_vocab_size - 1)
        unknown_id = checkpoint.get('unknown_id')
        threshold = checkpoint['threshold']
        
        # Expand vocabulary for unknown token if legacy checkpoint
        if unknown_id is None:
            vocab_size = original_vocab_size + 1
            unknown_id = vocab_size - 1
            logger.info("Expanding transformer vocabulary with <UNK> token (legacy checkpoint)")
        else:
            vocab_size = original_vocab_size
        
        self.vocab_size = vocab_size
        self.pad_id = pad_id
        self.unknown_id = unknown_id
        self.vocab_frozen = True
        self.transformer_threshold = threshold
        self.transformer_ready = True
        
        # Instantiate transformer with target vocab size
        transformer = TemplateTransformer(
            vocab_size=vocab_size,
            pad_id=self.pad_id,
            d_model=256,
            n_heads=8,
            n_layers=4,
            ffn_dim=1024,
            max_length=self.window_size,
            dropout=0.1
        ).to(self.device)
        
        current_state = transformer.state_dict()
        
        # Copy weights from checkpoint (handles vocab expansion gracefully)
        for name, tensor in saved_state.items():
            if name in ('embedding.weight', 'output.weight'):
                current_state[name][:tensor.size(0)] = tensor
            elif name == 'output.bias':
                current_state[name][:tensor.size(0)] = tensor
            else:
                current_state[name].copy_(tensor)
        
        transformer.load_state_dict(current_state)
        transformer.eval()
        
        self.transformer = transformer
        
        # Carry over optional calibration metadata
        if 'iso_score_threshold' in checkpoint:
            self.iso_score_threshold = checkpoint['iso_score_threshold']

    def _resolve_persistence_dir(self) -> Path:
        """
        Determine writable directory for saving detector state.
        Prefers ADAPTIVE_STATE_DIR env, then /app/logs, then local ./adaptive_state.
        """
        candidates = [
            os.getenv('ADAPTIVE_STATE_DIR'),
            '/app/logs',
            str(Path.cwd() / 'adaptive_state')
        ]
        for candidate in candidates:
            if not candidate:
                continue
            path = Path(candidate)
            try:
                path.mkdir(parents=True, exist_ok=True)
                test_file = path / '.write_test'
                with open(test_file, 'w') as f:
                    f.write('ok')
                test_file.unlink(missing_ok=True)
                return path
            except Exception:
                continue
        # Fallback to current directory
        fallback = Path.cwd()
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback

    def _record_iso_feature(self, features: Optional[np.ndarray]):
        """Store latest feature vector for Isolation Forest training/retraining"""
        if features is None:
            return
        try:
            flat = np.asarray(features, dtype=np.float64).reshape(-1)
        except Exception:
            return
        if flat.size == 0:
            return
        self.iso_training_features.append(flat)
    
    def _maybe_fit_iso_forest(self):
        """Fit or periodically refit Isolation Forest based on collected features"""
        if self.iso_retraining:
            return
        if len(self.iso_training_features) < self.iso_min_samples:
            return
        
        if not self.iso_forest_ready:
            if self.logs_processed >= self.warmup_logs:
                self._fit_iso_forest(initial=True)
        else:
            if self.logs_processed - self.iso_last_retrain_log >= self.iso_retrain_interval:
                self._fit_iso_forest(initial=False)
    
    def _fit_iso_forest(self, initial: bool):
        """Train or retrain the Isolation Forest using accumulated features"""
        if self.iso_retraining:
            return
        
        feature_matrix = np.vstack(self.iso_training_features)
        if feature_matrix.shape[0] < self.iso_min_samples:
            return
        
        self.iso_retraining = True
        phase = "initial" if initial and not self.iso_forest_ready else "incremental"
        try:
            logger.info(f"\nIsolation Forest ({phase}) training on {feature_matrix.shape[0]:,} samples...")
            self.iso_forest.fit(feature_matrix)
            self.iso_forest_ready = True
            self.iso_last_retrain_log = self.logs_processed
            
            # Derive anomaly score threshold for calibration (95th percentile)
            scores = -self.iso_forest.score_samples(feature_matrix)
            self.iso_score_threshold = float(np.percentile(scores, 95))
            
            logger.info("Isolation Forest training complete!")
            
            if initial and not self.transformer_ready:
                self._start_transformer_training()
            
            self._save_detector_state()
        except Exception as exc:
            logger.warning(f"Isolation Forest training failed: {exc}")
        finally:
            self.iso_retraining = False
    
    def _start_transformer_training(self):
        """Kick off background transformer training if data is ready"""
        if self.training_in_progress or self.transformer_ready:
            return
        
        if len(self.training_templates) == 0:
            logger.warning("WARNING: No training sequences collected!")
            logger.warning(f"    Collected templates: {len(self.template_to_id):,}")
            logger.warning(f"    Training will not start. Check session window collection.")
            return
        
        logger.info(f"Starting Transformer training with {len(self.training_templates):,} sequences...")
        training_thread = threading.Thread(target=self.train_transformer_background)
        training_thread.daemon = True
        training_thread.start()

    @staticmethod
    def _normalize_anomaly_score(score: float, threshold: Optional[float], width: float = 0.4) -> float:
        """Convert raw anomaly score into [0,1] confidence using a sigmoid around threshold"""
        if threshold is None:
            threshold = max(score, 1.0)
        margin = max(abs(threshold) * width, 1e-3)
        try:
            confidence = 1.0 / (1.0 + math.exp(-(score - threshold) / margin))
        except OverflowError:
            confidence = 1.0 if score > threshold else 0.0
        return float(confidence)
    
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
            logger.warning(f"Feature extraction error: {e}")
            logger.warning(f"   Log data: {log_data}")
            logger.warning(f"   Session stats: {session_stats}")
            # Return default safe features
            return np.array([1, 0.0, 1, 0, 1, 0, 0, 1, 1, 0, 0], dtype=np.float64).reshape(1, -1)
    
    def get_template_id(self, log_data: Dict) -> int:
        """Convert log to template ID and collect for training"""
        message = f"{log_data['method']} {log_data['path']} {log_data['protocol']} {log_data['status']}"
        normalized = self.normalizer.normalize(message)
        
        if normalized in self.template_to_id:
            tid = self.template_to_id[normalized]
        else:
            if self.vocab_frozen and self.unknown_id is not None:
                tid = self.unknown_id
                self.unseen_templates[normalized] += 1
            else:
                tid = self._add_template_to_vocab(normalized)
        
        # Track for training statistics (ignore special tokens)
        if tid not in (self.pad_id, self.unknown_id):
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
        base_vocab_size = len(self.id_to_template)
        if base_vocab_size == 0:
            logger.warning("No templates collected; skipping transformer training.")
            return
        
        self.training_in_progress = True
        
        logger.info(f"\n{'='*70}")
        logger.info(f"TRANSFORMER TRAINING STARTED (Background)")
        logger.info(f"{'='*70}")
        logger.info(f"  Templates collected: {len(self.id_to_template):,}")
        logger.info(f"  Training sequences: {len(self.training_templates):,}")
        logger.info(f"  Logs processed: {self.logs_processed:,}")
        logger.info(f"{'='*70}\n")
        
        try:
            # Freeze vocabulary and reserve special tokens
            self.vocab_frozen = True
            self.pad_id = base_vocab_size
            self.unknown_id = base_vocab_size + 1
            self.vocab_size = self.unknown_id + 1
            
            # Create sequences with padding
            padded_sequences = []
            for seq in list(self.training_templates):
                sanitized = [t if t < self.pad_id else (self.pad_id - 1) for t in seq]
                if len(sanitized) < self.window_size:
                    sanitized = sanitized + [self.pad_id] * (self.window_size - len(sanitized))
                else:
                    sanitized = sanitized[-self.window_size:]
                padded_sequences.append(sanitized)
            
            if not padded_sequences:
                logger.warning("No training sequences available; aborting transformer training.")
                return
            
            # Initialize transformer
            self.transformer = TemplateTransformer(
                vocab_size=self.vocab_size,
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
                        logits_shifted.reshape(-1, self.vocab_size),
                        targets.reshape(-1),
                        ignore_index=self.pad_id
                    )
                    
                    # Backward pass
                    optimizer.zero_grad()
                    loss.backward()
                    optimizer.step()
                    
                    total_loss += loss.item()
                
                avg_loss = total_loss / len(loader)
                logger.info(f"  Epoch {epoch+1}/{epochs} - Loss: {avg_loss:.4f}")
            
            self.transformer.eval()
            
            # Calculate adaptive threshold (95th percentile of training scores)
            self.transformer_threshold = self._calculate_adaptive_threshold(padded_sequences)
            
            # Save trained model to writable directory
            save_path = self.persistence_dir / 'online_transformer.pt'
            save_path.parent.mkdir(parents=True, exist_ok=True)
            torch.save({
                'model_state_dict': self.transformer.state_dict(),
                'vocab_size': self.vocab_size,
                'pad_id': self.pad_id,
                'unknown_id': self.unknown_id,
                'template_to_id': self.template_to_id,
                'id_to_template': self.id_to_template,
                'threshold': self.transformer_threshold,
                'logs_trained_on': self.logs_processed,
                'iso_score_threshold': self.iso_score_threshold
            }, save_path)
            
            # Save detector state (for persistence across restarts)
            self._save_detector_state()
            
            logger.info(f"\n{'='*70}")
            logger.info(f"TRANSFORMER TRAINING COMPLETE")
            logger.info(f"{'='*70}")
            logger.info(f"  Model saved: {save_path}")
            logger.info(f"  Vocabulary: {self.vocab_size:,} tokens (templates + specials)")
            logger.info(f"  Threshold: {self.transformer_threshold:.4f}")
            logger.info(f"  Now using FULL ENSEMBLE (Rule + Iso + Transformer)")
            logger.info(f"{'='*70}\n")
            
            self.transformer_ready = True
            
        except Exception as e:
            logger.error(f"Transformer training failed: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.training_in_progress = False
    
    def _save_detector_state(self):
        """Save detector state for persistence across restarts"""
        try:
            state_path = self.persistence_dir / 'detector_state.pkl'
            state_path.parent.mkdir(parents=True, exist_ok=True)
            
            state = {
                'logs_processed': self.logs_processed,
                'template_to_id': self.template_to_id,
                'id_to_template': self.id_to_template,
                'template_counts': dict(self.template_counts),
                'iso_forest_ready': self.iso_forest_ready,
                'iso_forest_model': self.iso_forest if self.iso_forest_ready else None,
                'vocab_frozen': self.vocab_frozen,
                'pad_id': self.pad_id,
                'unknown_id': self.unknown_id,
                'vocab_size': self.vocab_size,
                'unseen_templates': dict(self.unseen_templates),
                'iso_score_threshold': self.iso_score_threshold,
                'iso_last_retrain_log': self.iso_last_retrain_log,
                'saved_at': datetime.now().isoformat()
            }
            
            with open(state_path, 'wb') as f:
                pickle.dump(state, f)
            
            logger.info(f"Detector state saved to {state_path}")
            
        except Exception as e:
            logger.warning(f"Failed to save detector state: {e}")
    
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
        3. Handles unknown templates (IDs beyond training vocabulary)
        """
        if not self.transformer_ready or len(sequence) < 1 or self.vocab_size is None:
            return 0.0
        
        # Replace unknown template IDs (beyond vocab) with dedicated <UNK> token
        has_unknown = False
        unknown_count = 0
        cleaned_sequence = []
        for tid in sequence:
            if tid == self.unknown_id:
                cleaned_sequence.append(self.unknown_id)
                has_unknown = True
                unknown_count += 1
            elif tid is None:
                cleaned_sequence.append(self.unknown_id)
                has_unknown = True
                unknown_count += 1
            elif tid >= self.vocab_size:
                cleaned_sequence.append(self.unknown_id)
                has_unknown = True
                unknown_count += 1
            else:
                cleaned_sequence.append(tid)
        
        unknown_penalty = 0.0
        if has_unknown and self.transformer_threshold:
            ratio = unknown_count / max(len(cleaned_sequence), 1)
            unknown_penalty = 0.4 * self.transformer_threshold * ratio
        
        # Prepare sequence (pad or truncate)
        original_length = len(cleaned_sequence)
        if len(cleaned_sequence) < self.window_size:
            cleaned_sequence = cleaned_sequence + [self.pad_id] * (self.window_size - len(cleaned_sequence))
        else:
            cleaned_sequence = cleaned_sequence[-self.window_size:]
        
        input_ids = torch.tensor([cleaned_sequence], dtype=torch.long).to(self.device)
        attention_mask = torch.tensor(
            [[1 if t != self.pad_id else 0 for t in cleaned_sequence]], 
            dtype=torch.long
        ).to(self.device)
        
        with torch.no_grad():
            try:
                logits = self.transformer(input_ids, attention_mask)
                
                # For single-template sequences, use the probability of that template at position 0
                if original_length == 1:
                    # Get probability distribution at position 0
                    probs = F.softmax(logits[0, 0, :], dim=-1)
                    template_id = cleaned_sequence[0]
                    
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
                    base_score = valid_nll.mean().item()
                    return base_score + unknown_penalty
                return unknown_penalty
                
            except Exception as e:
                logger.warning(f"Transformer scoring error: {e}")
                logger.warning(f"   Sequence length: {original_length}, Padded: {len(cleaned_sequence)}")
                logger.warning(f"   Vocab size: {self.vocab_size}, Template IDs: {sequence[:5]}")
                return self.transformer_threshold + unknown_penalty  # Return threshold score on error (moderate anomaly)
    
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
        features = self.extract_features(log_data, session_stats)
        self._record_iso_feature(features)
        
        if self.logs_processed <= self.warmup_logs:
            # Collect sequences more aggressively (min 5 instead of full window_size)
            if len(session['templates']) >= 5:
                self.training_templates.append(list(session['templates']))
        
        # Evaluate whether Isolation Forest needs (re)training
        self._maybe_fit_iso_forest()
        
        # 1. Rule-based detection (always active)
        rule_result = self.rule_detector.detect(
            log_data['path'], 
            log_data['method'], 
            log_data['status']
        )
        
        # 2. Isolation Forest (only after warmup)
        if self.iso_forest_ready:
            try:
                if features is None or features.shape != (1, 11):
                    logger.warning(f"Warning: Invalid feature shape {features.shape if features is not None else 'None'}, expected (1, 11)")
                    iso_result = {
                        'is_anomaly': 0,
                        'score': 0.0,
                        'status': 'feature_error',
                        'threshold': self.iso_score_threshold,
                        'confidence': 0.0
                    }
                else:
                    iso_pred = self.iso_forest.predict(features)[0]
                    iso_score = -self.iso_forest.score_samples(features)[0]
                    iso_confidence = self._normalize_anomaly_score(
                        iso_score,
                        self.iso_score_threshold,
                        width=0.5
                    )
                    iso_result = {
                        'is_anomaly': int(iso_pred == -1),
                        'score': float(iso_score),
                        'threshold': self.iso_score_threshold,
                        'confidence': iso_confidence,
                        'samples_tracked': len(self.iso_training_features)
                    }
            except Exception as e:
                logger.warning(f"Isolation Forest error: {e}")
                logger.warning(f"   Features: {features if features is not None else 'not extracted'}")
                logger.warning(f"   Session stats: {session_stats}")
                logger.warning(f"   Log data: {log_data}")
                iso_result = {
                    'is_anomaly': 0,
                    'score': 0.0,
                    'status': f'error: {str(e)[:50]}',
                    'threshold': self.iso_score_threshold,
                    'confidence': 0.0
                }
        else:
            # During warmup, don't use Isolation Forest for detection
            iso_result = {
                'is_anomaly': 0,
                'score': 0.0,
                'status': 'collecting_baseline',
                'threshold': self.iso_score_threshold,
                'confidence': 0.0
            }
        
        # 3. Transformer (only if trained)
        if self.transformer_ready:
            sequence_length = len(session['templates'])
            sequence_snapshot = list(session['templates'])
            unknown_count = sum(1 for t in sequence_snapshot if t == self.unknown_id)
            transformer_score = self.calculate_transformer_score(sequence_snapshot)
            base_confidence = self._normalize_anomaly_score(
                transformer_score,
                self.transformer_threshold,
                width=0.3
            )
            if unknown_count > 0:
                ratio = unknown_count / max(sequence_length, 1)
                transformer_confidence = min(1.0, base_confidence + 0.5 * ratio)
            else:
                transformer_confidence = base_confidence
            transformer_result = {
                'is_anomaly': 1 if transformer_score > self.transformer_threshold else 0,
                'score': float(transformer_score),
                'threshold': float(self.transformer_threshold),
                'sequence_length': sequence_length,
                'context': 'single_log' if sequence_length == 1 else f'{sequence_length}_logs',
                'confidence': transformer_confidence,
                'unknown_count': unknown_count
            }
        else:
            transformer_result = {
                'is_anomaly': 0,
                'score': 0.0,
                'status': 'training' if self.training_in_progress else 'collecting_data',
                'confidence': 0.0
            }
        
        # Ensemble voting with confidence-weighted signals
        votes = {'rule': 0.0, 'iso': 0.0, 'transformer': 0.0}
        weights = {'rule': 0.0, 'iso': 0.0, 'transformer': 0.0}
        weighted_sum = 0.0
        total_weight = 0.0
        
        rule_weight = 0.2 + 0.5 * rule_result.get('confidence', 0.0)
        rule_signal = 1.0 if rule_result.get('is_attack') else 0.0
        votes['rule'] = rule_signal
        weights['rule'] = rule_weight
        weighted_sum += rule_signal * rule_weight
        total_weight += rule_weight
        
        if self.iso_forest_ready:
            iso_weight = 0.5
            iso_signal = iso_result.get('confidence', 0.0)
            votes['iso'] = iso_signal
            weights['iso'] = iso_weight
            weighted_sum += iso_signal * iso_weight
            total_weight += iso_weight
        
        if self.transformer_ready:
            transformer_weight = 0.7
            transformer_signal = transformer_result.get('confidence', 0.0)
            votes['transformer'] = transformer_signal
            weights['transformer'] = transformer_weight
            weighted_sum += transformer_signal * transformer_weight
            total_weight += transformer_weight
        
        ensemble_score = weighted_sum / total_weight if total_weight > 0 else 0.0
        is_anomaly = ensemble_score >= 0.5
        
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
                'votes': votes,
                'weights': weights,
                'active_models': sum(1 for w in weights.values() if w > 0.0),
                'total_weight': total_weight
            },
            'log_data': log_data
        }
