"""
Teacher Model Module
Main model that learns general log anomaly patterns across all projects.
The teacher model provides baseline detection during warmup and is used
to train project-specific student models via knowledge distillation.
"""

import json
import math
import pickle
import threading
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import deque, Counter
from datetime import datetime

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader

from .ensemble_detector import (
    TemplateTransformer, RuleBasedDetector, ApacheLogNormalizer
)
logger = logging.getLogger(__name__)


class TeacherTrainingDataset(Dataset):
    """Dataset for teacher model training/fine-tuning"""
    
    def __init__(self, sequences: List[List[int]], pad_id: int):
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


class TeacherModel:
    """
    Teacher Model for Log Anomaly Detection
    
    The teacher model serves two primary purposes:
    1. Provides baseline anomaly detection during project warmup phase
    2. Serves as the foundation for training project-specific student models
    
    The teacher model is periodically updated using aggregated logs from
    all active student models, making it continuously improve its understanding
    of general log anomaly patterns.
    
    Architecture:
    - Transformer: Sequence-based anomaly detection
    - Rule-based: Pattern matching for known attack signatures  
    - Isolation Forest: Statistical anomaly detection
    """
    
    def __init__(
        self,
        model_dir: Path,
        storage_dir: Path,
        window_size: int = 20,
        device: str = 'cpu',
        auto_load: bool = True
    ):
        self.model_dir = Path(model_dir)
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.window_size = window_size
        self.device = torch.device(device)
        self.normalizer = ApacheLogNormalizer()
        
        # Model components
        self.transformer: Optional[TemplateTransformer] = None
        self.iso_forest = None
        self.rule_detector = RuleBasedDetector()
        
        # Vocabulary
        self.template_to_id: Dict[str, int] = {}
        self.id_to_template: List[str] = []
        self.vocab_size: Optional[int] = None
        self.pad_id: Optional[int] = None
        self.unknown_id: Optional[int] = None
        
        # Thresholds
        self.transformer_threshold: float = 6.5
        self.iso_threshold: Optional[float] = None
        
        # State
        self.is_loaded = False
        self.is_training = False
        self.total_logs_processed = 0
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Paths
        self.teacher_model_path = self.storage_dir / 'teacher_transformer.pt'
        self.teacher_state_path = self.storage_dir / 'teacher_state.pkl'
        self.teacher_iso_path = self.storage_dir / 'teacher_iso_forest.pkl'
        
        if auto_load:
            self._load_or_initialize()
    
    def _load_or_initialize(self):
        """Load existing teacher model or initialize from base model"""
        
        # First try to load saved teacher model
        if self.teacher_model_path.exists():
            logger.info("Loading saved teacher model...")
            self._load_saved_teacher()
        else:
            logger.info("Initializing teacher from base model...")
            self._initialize_from_base()
    
    def _initialize_from_base(self):
        """Initialize teacher model from the base exported model"""
        try:
            # Load base vocabulary
            vocab_path = self.model_dir / 'template_vocab.json'
            if vocab_path.exists():
                with open(vocab_path, 'r') as f:
                    vocab_data = json.load(f)
                
                if isinstance(vocab_data, dict) and 'template_to_id' in vocab_data:
                    self.template_to_id = vocab_data['template_to_id']
                else:
                    self.template_to_id = vocab_data
                
                self.id_to_template = [''] * len(self.template_to_id)
                for template, tid in self.template_to_id.items():
                    if tid < len(self.id_to_template):
                        self.id_to_template[tid] = template
            
            base_vocab_size = len(self.id_to_template)
            self.pad_id = base_vocab_size
            self.unknown_id = base_vocab_size + 1
            self.vocab_size = self.unknown_id + 1
            
            # Load config
            config_path = self.model_dir / 'model_config.json'
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = json.load(f)
                self.transformer_threshold = config.get('optimal_threshold', 6.5)
            
            # Try to load base transformer
            base_transformer_path = self.model_dir / 'transformer_model.pt'
            if base_transformer_path.exists():
                checkpoint = torch.load(base_transformer_path, map_location=self.device)
                self._load_transformer_weights(checkpoint)
            else:
                # Initialize fresh transformer
                self._initialize_fresh_transformer()
            
            # Try to load base isolation forest
            base_iso_path = self.model_dir / 'isolation_forest.pkl'
            if base_iso_path.exists():
                with open(base_iso_path, 'rb') as f:
                    self.iso_forest = pickle.load(f)
            else:
                self._initialize_fresh_iso_forest()
            
            self.is_loaded = True
            logger.info("Teacher model initialized from base")
            logger.info(f"Vocabulary size: {self.vocab_size}")
            logger.info(f"Threshold: {self.transformer_threshold:.4f}")
            
            # Save initial state
            self.save()
            
        except Exception as e:
            logger.warning(f"Failed to initialize from base: {e}")
            self._initialize_fresh()
    
    def _initialize_fresh(self):
        """Initialize a completely fresh teacher model"""
        logger.info("Initializing fresh teacher model...")
        
        # Start with minimal vocabulary (will grow during training)
        self.template_to_id = {}
        self.id_to_template = []
        self.vocab_size = 2  # Just pad and unknown
        self.pad_id = 0
        self.unknown_id = 1
        
        self._initialize_fresh_transformer()
        self._initialize_fresh_iso_forest()
        
        self.is_loaded = True
        logger.info("Fresh teacher model initialized")
    
    def _initialize_fresh_transformer(self):
        """Initialize a fresh transformer model"""
        self.transformer = TemplateTransformer(
            vocab_size=max(self.vocab_size, 100),  # Start with reasonable vocab
            pad_id=self.pad_id,
            d_model=256,
            n_heads=8,
            n_layers=4,
            ffn_dim=1024,
            max_length=self.window_size,
            dropout=0.1
        ).to(self.device)
        self.transformer.eval()
    
    def _initialize_fresh_iso_forest(self):
        """Initialize a fresh isolation forest"""
        from sklearn.ensemble import IsolationForest
        # Note: warm_start=False to avoid sklearn warning about not increasing n_estimators
        self.iso_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
            warm_start=False
        )
    
    def _load_transformer_weights(self, checkpoint: Dict):
        """Load transformer weights from checkpoint"""
        saved_state = checkpoint.get('model_state_dict', checkpoint)
        original_vocab_size = checkpoint.get('vocab_size', self.vocab_size)
        
        # Get saved configuration
        self.transformer_threshold = checkpoint.get('threshold', self.transformer_threshold)
        
        # Ensure vocabulary is large enough
        target_vocab_size = max(original_vocab_size, self.vocab_size)
        
        # Create transformer
        self.transformer = TemplateTransformer(
            vocab_size=target_vocab_size,
            pad_id=self.pad_id,
            d_model=256,
            n_heads=8,
            n_layers=4,
            ffn_dim=1024,
            max_length=self.window_size,
            dropout=0.1
        ).to(self.device)
        
        # Load weights (handle vocabulary size mismatch)
        current_state = self.transformer.state_dict()
        for name, tensor in saved_state.items():
            if name in current_state:
                if name in ('embedding.weight', 'output.weight'):
                    # Handle embedding expansion
                    min_size = min(tensor.size(0), current_state[name].size(0))
                    current_state[name][:min_size] = tensor[:min_size]
                elif name == 'output.bias':
                    min_size = min(tensor.size(0), current_state[name].size(0))
                    current_state[name][:min_size] = tensor[:min_size]
                else:
                    current_state[name].copy_(tensor)
        
        self.transformer.load_state_dict(current_state)
        self.transformer.eval()
    
    def _load_saved_teacher(self):
        """Load previously saved teacher model"""
        try:
            # Load state
            if self.teacher_state_path.exists():
                with open(self.teacher_state_path, 'rb') as f:
                    state = pickle.load(f)
                
                self.template_to_id = state.get('template_to_id', {})
                self.id_to_template = state.get('id_to_template', [])
                self.vocab_size = state.get('vocab_size', len(self.id_to_template) + 2)
                self.pad_id = state.get('pad_id', self.vocab_size - 2)
                self.unknown_id = state.get('unknown_id', self.vocab_size - 1)
                self.transformer_threshold = state.get('transformer_threshold', 6.5)
                self.iso_threshold = state.get('iso_threshold')
                self.total_logs_processed = state.get('total_logs_processed', 0)
            
            # Load transformer
            if self.teacher_model_path.exists():
                checkpoint = torch.load(self.teacher_model_path, map_location=self.device)
                self._load_transformer_weights(checkpoint)
            else:
                self._initialize_fresh_transformer()
            
            # Load isolation forest
            if self.teacher_iso_path.exists():
                with open(self.teacher_iso_path, 'rb') as f:
                    self.iso_forest = pickle.load(f)
            else:
                self._initialize_fresh_iso_forest()
            
            self.is_loaded = True
            logger.info("Loaded saved teacher model")
            logger.info(f"Vocabulary size: {self.vocab_size}")
            logger.info(f"Total logs processed: {self.total_logs_processed:,}")
            logger.info(f"Threshold: {self.transformer_threshold:.4f}")
            
        except Exception as e:
            logger.warning(f"Failed to load saved teacher: {e}")
            self._initialize_from_base()
    
    def save(self):
        """Save teacher model state"""
        with self._lock:
            try:
                # Save transformer
                torch.save({
                    'model_state_dict': self.transformer.state_dict(),
                    'vocab_size': self.vocab_size,
                    'pad_id': self.pad_id,
                    'unknown_id': self.unknown_id,
                    'threshold': self.transformer_threshold,
                    'saved_at': datetime.now().isoformat()
                }, self.teacher_model_path)
                
                # Save state
                state = {
                    'template_to_id': self.template_to_id,
                    'id_to_template': self.id_to_template,
                    'vocab_size': self.vocab_size,
                    'pad_id': self.pad_id,
                    'unknown_id': self.unknown_id,
                    'transformer_threshold': self.transformer_threshold,
                    'iso_threshold': self.iso_threshold,
                    'total_logs_processed': self.total_logs_processed,
                    'saved_at': datetime.now().isoformat()
                }
                with open(self.teacher_state_path, 'wb') as f:
                    pickle.dump(state, f)
                
                # Save isolation forest
                if self.iso_forest is not None:
                    with open(self.teacher_iso_path, 'wb') as f:
                        pickle.dump(self.iso_forest, f)
                
                logger.info(f"Teacher model saved to {self.storage_dir}")
                
            except Exception as e:
                logger.warning(f"Failed to save teacher model: {e}")
    
    def get_template_id(self, normalized_template: str) -> int:
        """Get template ID, returning unknown ID for new templates"""
        if normalized_template in self.template_to_id:
            return self.template_to_id[normalized_template]
        return self.unknown_id
    
    def add_template(self, normalized_template: str) -> int:
        """Add a new template to vocabulary (during training only)"""
        with self._lock:
            if normalized_template in self.template_to_id:
                return self.template_to_id[normalized_template]
            
            tid = len(self.id_to_template)
            self.template_to_id[normalized_template] = tid
            self.id_to_template.append(normalized_template)
            return tid
    
    def calculate_transformer_score(self, sequence: List[int]) -> float:
        """Calculate anomaly score from transformer (NLL)"""
        if not self.is_loaded or self.transformer is None:
            return 0.0
        
        if len(sequence) < 1:
            return 0.0
        
        # Handle unknown tokens
        cleaned_sequence = []
        for tid in sequence:
            if tid is None or tid >= self.vocab_size:
                cleaned_sequence.append(self.unknown_id)
            else:
                cleaned_sequence.append(tid)
        
        # Pad or truncate
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
                
                # Calculate NLL
                input_shifted = input_ids[:, 1:]
                logits_shifted = logits[:, :-1, :]
                log_probs = F.log_softmax(logits_shifted, dim=-1)
                nll_per_pos = -log_probs.gather(2, input_shifted.unsqueeze(-1)).squeeze(-1)
                
                mask = attention_mask[:, 1:] == 1
                valid_nll = nll_per_pos[mask]
                
                if valid_nll.numel() > 0:
                    return valid_nll.mean().item()
                return 0.0
                
            except Exception as e:
                logger.warning(f"Teacher transformer error: {e}")
                return self.transformer_threshold
    
    def detect(
        self,
        log_data: Dict,
        sequence: List[int],
        session_stats: Dict,
        features: Optional[np.ndarray] = None
    ) -> Dict:
        """
        Perform anomaly detection using teacher model.
        
        Args:
            log_data: Parsed log data
            sequence: Sequence of template IDs
            session_stats: Session statistics
            features: Optional pre-extracted features for isolation forest
        
        Returns:
            Detection result dictionary
        """
        # 1. Rule-based detection
        rule_result = self.rule_detector.detect(
            log_data.get('path', '/'),
            log_data.get('method', 'GET'),
            log_data.get('status', 200)
        )
        
        # 2. Transformer detection
        transformer_score = self.calculate_transformer_score(sequence)
        transformer_result = {
            'is_anomaly': 1 if transformer_score > self.transformer_threshold else 0,
            'score': float(transformer_score),
            'threshold': float(self.transformer_threshold)
        }
        
        # 3. Isolation Forest detection
        iso_result = {'is_anomaly': 0, 'score': 0.0, 'status': 'not_available'}
        if self.iso_forest is not None and features is not None:
            try:
                iso_pred = self.iso_forest.predict(features)[0]
                iso_score = -self.iso_forest.score_samples(features)[0]
                iso_result = {
                    'is_anomaly': int(iso_pred == -1),
                    'score': float(iso_score),
                    'status': 'active'
                }
            except Exception as e:
                iso_result['status'] = f'error: {str(e)[:50]}'
        
        # 4. Ensemble voting
        votes = []
        weights = []
        
        # Rule-based
        if rule_result.get('is_attack'):
            votes.append(1)
            weights.append(rule_result.get('confidence', 0.5))
        else:
            votes.append(0)
            weights.append(0.2)
        
        # Isolation Forest
        votes.append(iso_result.get('is_anomaly', 0))
        weights.append(0.5)
        
        # Transformer
        votes.append(transformer_result['is_anomaly'])
        weights.append(0.7)
        
        total_weight = sum(weights)
        ensemble_score = sum(v * w for v, w in zip(votes, weights)) / total_weight
        is_anomaly = ensemble_score > 0.5
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': ensemble_score,
            'model_type': 'teacher',
            'rule_based': rule_result,
            'isolation_forest': iso_result,
            'transformer': transformer_result,
            'ensemble': {
                'score': ensemble_score,
                'votes': dict(zip(['rule', 'iso', 'transformer'], votes)),
                'weights': dict(zip(['rule', 'iso', 'transformer'], weights))
            }
        }
    
    def get_soft_labels(self, sequence: List[int]) -> torch.Tensor:
        """
        Get soft probability distribution from teacher for knowledge distillation.
        
        Args:
            sequence: List of template IDs
        
        Returns:
            Soft label tensor of shape (seq_len, vocab_size)
        """
        if not self.is_loaded or self.transformer is None:
            return None
        
        # Prepare sequence
        cleaned_sequence = []
        for tid in sequence:
            if tid is None or tid >= self.vocab_size:
                cleaned_sequence.append(self.unknown_id)
            else:
                cleaned_sequence.append(tid)
        
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
            logits = self.transformer(input_ids, attention_mask)
            # Return softmax probabilities (soft labels)
            soft_labels = F.softmax(logits, dim=-1)
            return soft_labels.squeeze(0)
    
    def update_from_student_logs(
        self,
        all_sequences: List[List[int]],
        all_features: Optional[np.ndarray] = None,
        epochs: int = 2,
        learning_rate: float = 1e-5
    ):
        """
        Update teacher model using aggregated logs from student models.
        
        This is the periodic update process where the teacher learns from
        the collective experience of all project-specific student models.
        
        Args:
            all_sequences: Aggregated sequences from all student projects
            all_features: Aggregated features for isolation forest
            epochs: Number of training epochs
            learning_rate: Learning rate for fine-tuning
        """
        if self.is_training:
            logger.warning("Teacher is already being trained")
            return
        
        if len(all_sequences) < 100:
            logger.warning("Not enough sequences for teacher update")
            return
        
        self.is_training = True
        logger.info("="*70)
        logger.info("UPDATING TEACHER MODEL")
        logger.info("="*70)
        logger.info(f"Sequences: {len(all_sequences):,}")
        logger.info(f"Epochs: {epochs}")
        logger.info("="*70)
        
        try:
            # Prepare training data
            padded_sequences = []
            for seq in all_sequences:
                sanitized = []
                for t in seq:
                    if t is None or t >= self.vocab_size:
                        sanitized.append(self.unknown_id)
                    elif t >= self.pad_id:
                        sanitized.append(self.pad_id - 1 if self.pad_id > 0 else 0)
                    else:
                        sanitized.append(t)
                
                if len(sanitized) < self.window_size:
                    sanitized = sanitized + [self.pad_id] * (self.window_size - len(sanitized))
                else:
                    sanitized = sanitized[-self.window_size:]
                padded_sequences.append(sanitized)
            
            # Create dataset
            dataset = TeacherTrainingDataset(padded_sequences, self.pad_id)
            loader = DataLoader(dataset, batch_size=64, shuffle=True)
            
            # Training
            self.transformer.train()
            optimizer = torch.optim.AdamW(self.transformer.parameters(), lr=learning_rate)
            
            for epoch in range(epochs):
                total_loss = 0
                for batch in loader:
                    input_ids = batch['input_ids'].to(self.device)
                    attention_mask = batch['attention_mask'].to(self.device)
                    
                    logits = self.transformer(input_ids, attention_mask)
                    
                    targets = input_ids[:, 1:]
                    logits_shifted = logits[:, :-1, :]
                    
                    loss = F.cross_entropy(
                        logits_shifted.reshape(-1, self.vocab_size),
                        targets.reshape(-1),
                        ignore_index=self.pad_id
                    )
                    
                    optimizer.zero_grad()
                    loss.backward()
                    optimizer.step()
                    
                    total_loss += loss.item()
                
                avg_loss = total_loss / len(loader)
                logger.info(f"Epoch {epoch + 1}/{epochs} - Loss: {avg_loss:.4f}")
            
            self.transformer.eval()
            
            # Update isolation forest if features provided
            if all_features is not None and len(all_features) > 100:
                logger.info("Updating isolation forest...")
                self.iso_forest.fit(all_features)
                scores = -self.iso_forest.score_samples(all_features)
                self.iso_threshold = float(np.percentile(scores, 95))
            
            # Recalculate threshold
            self._update_threshold(padded_sequences)
            
            # Save updated model
            self.save()
            
            logger.info(f"Teacher model updated successfully!")
            logger.info(f"New threshold: {self.transformer_threshold:.4f}")
            
        except Exception as e:
            logger.error(f"Teacher update failed: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.is_training = False
    
    def _update_threshold(self, sequences: List[List[int]]):
        """Update transformer threshold based on training data"""
        scores = []
        
        with torch.no_grad():
            for seq in sequences[:1000]:
                input_ids = torch.tensor([seq], dtype=torch.long).to(self.device)
                attention_mask = torch.tensor(
                    [[1 if t != self.pad_id else 0 for t in seq]],
                    dtype=torch.long
                ).to(self.device)
                
                logits = self.transformer(input_ids, attention_mask)
                input_shifted = input_ids[:, 1:]
                logits_shifted = logits[:, :-1, :]
                log_probs = F.log_softmax(logits_shifted, dim=-1)
                nll_per_pos = -log_probs.gather(2, input_shifted.unsqueeze(-1)).squeeze(-1)
                mask = attention_mask[:, 1:] == 1
                
                if mask.sum() > 0:
                    avg_nll = nll_per_pos[mask].mean().item()
                    scores.append(avg_nll)
        
        if scores:
            self.transformer_threshold = float(np.percentile(scores, 95))
    
    def get_model_info(self) -> Dict:
        """Get teacher model information"""
        return {
            'vocab_size': self.vocab_size,
            'num_templates': len(self.id_to_template),
            'transformer_threshold': self.transformer_threshold,
            'iso_threshold': self.iso_threshold,
            'total_logs_processed': self.total_logs_processed,
            'is_loaded': self.is_loaded,
            'is_training': self.is_training,
            'window_size': self.window_size,
            'device': str(self.device)
        }
