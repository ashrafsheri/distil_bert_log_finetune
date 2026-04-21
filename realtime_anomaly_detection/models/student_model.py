"""
Student Model Module
Project-specific models that are trained after warmup using knowledge distillation from teacher.
Each project gets its own student model that is fine-tuned on project-specific log patterns.
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
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError
from sklearn.utils.validation import check_is_fitted

from .ensemble_detector import (
    TemplateTransformer, RuleBasedDetector, ApacheLogNormalizer
)
from .calibrator import EnsembleCalibrator


logger = logging.getLogger(__name__)

MIN_SEQUENCE_CONTEXT = 3
MAX_UNKNOWN_TEMPLATE_RATIO = 0.5


class StudentTrainingDataset(Dataset):
    """Dataset for student model training with optional soft labels"""
    
    def __init__(
        self,
        sequences: List[List[int]],
        pad_id: int,
        soft_labels: Optional[List[torch.Tensor]] = None
    ):
        self.sequences = sequences
        self.pad_id = pad_id
        self.soft_labels = soft_labels
    
    def __len__(self):
        return len(self.sequences)
    
    def __getitem__(self, idx):
        seq = self.sequences[idx]
        attention_mask = [1 if t != self.pad_id else 0 for t in seq]
        
        item = {
            'input_ids': torch.tensor(seq, dtype=torch.long),
            'attention_mask': torch.tensor(attention_mask, dtype=torch.long)
        }
        
        if self.soft_labels is not None and idx < len(self.soft_labels):
            item['soft_labels'] = self.soft_labels[idx]
        
        return item


class StudentModel:
    """
    Student Model for Project-Specific Log Anomaly Detection
    
    The student model is trained on project-specific logs after the warmup phase.
    It uses knowledge distillation from the teacher model combined with
    the project's own log patterns to create a specialized detector.
    
    Features:
    - Smaller architecture than teacher for faster inference
    - Project-specific vocabulary and patterns
    - Online learning capability for continuous improvement
    - Knowledge distillation from teacher model
    
    Architecture:
    - Lighter Transformer (fewer layers)
    - Project-specific Isolation Forest
    - Shared Rule-based detector (from teacher)
    """
    
    def __init__(
        self,
        project_id: str,
        storage_dir: Path,
        window_size: int = 20,
        device: str = 'cpu'
    ):
        self.project_id = project_id
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.window_size = window_size
        self.device = torch.device(device)
        self.normalizer = ApacheLogNormalizer()
        
        # Model components
        self.transformer: Optional[TemplateTransformer] = None
        self.iso_forest: Optional[IsolationForest] = None
        self.rule_detector = RuleBasedDetector()

        # Calibrator (loaded if available, otherwise falls back to ensemble threshold)
        self.calibrator: Optional[EnsembleCalibrator] = None
        calibrator_path = self.storage_dir / 'calibrator.pkl'
        if calibrator_path.exists():
            try:
                self.calibrator = EnsembleCalibrator.load(calibrator_path)
                logger.info("Loaded fitted calibrator for student %s", project_id[:8])
            except Exception as e:
                logger.warning("Failed to load student calibrator: %s", e)

        # Vocabulary (project-specific)
        self.template_to_id: Dict[str, int] = {}
        self.id_to_template: List[str] = []
        self.template_counts: Counter = Counter()
        self.vocab_size: Optional[int] = None
        self.pad_id: Optional[int] = None
        self.unknown_id: Optional[int] = None
        self.vocab_frozen: bool = False
        
        # Thresholds
        self.transformer_threshold: float = 6.5
        self.iso_threshold: Optional[float] = None
        
        # Training data
        self.training_sequences: List[List[int]] = []
        self.training_features: List[np.ndarray] = []
        self.session_windows: Dict[str, deque] = {}
        self.clean_normal_reservoir: List[List[int]] = []
        self.suspicious_reservoir: List[List[int]] = []
        self.confirmed_malicious_reservoir: List[List[int]] = []
        self.clean_feature_reservoir: List[np.ndarray] = []
        
        # State
        self.is_trained = False
        self.is_training = False
        self.logs_processed = 0
        self.last_trained_at: Optional[str] = None
        self.online_update_count: int = 0
        self.logs_since_last_update: int = 0
        self.last_online_update_at: Optional[str] = None

        # Thread safety
        self._lock = threading.RLock()
        
        # Paths
        self.model_path = self.storage_dir / 'student_transformer.pt'
        self.state_path = self.storage_dir / 'student_state.pkl'
        self.iso_path = self.storage_dir / 'student_iso_forest.pkl'
        
        # Try to load existing model
        if self.model_path.exists():
            self._load()

    def _is_iso_forest_fitted(self) -> bool:
        if self.iso_forest is None:
            return False
        try:
            check_is_fitted(self.iso_forest)
            return True
        except Exception:
            return False
    
    def _load(self):
        """Load saved student model"""
        try:
            # Load state
            if self.state_path.exists():
                with open(self.state_path, 'rb') as f:
                    state = pickle.load(f)
                
                self.template_to_id = state.get('template_to_id', {})
                self.id_to_template = state.get('id_to_template', [])
                self.template_counts = Counter(state.get('template_counts', {}))
                self.vocab_size = state.get('vocab_size')
                self.pad_id = state.get('pad_id')
                self.unknown_id = state.get('unknown_id')
                self.vocab_frozen = state.get('vocab_frozen', False)
                self.transformer_threshold = state.get('transformer_threshold', 6.5)
                self.iso_threshold = state.get('iso_threshold')
                self.logs_processed = state.get('logs_processed', 0)
                self.last_trained_at = state.get('last_trained_at')
                self.online_update_count = state.get('online_update_count', 0)
                self.logs_since_last_update = state.get('logs_since_last_update', 0)
                self.last_online_update_at = state.get('last_online_update_at')
                self.clean_normal_reservoir = state.get('clean_normal_reservoir', [])
                self.suspicious_reservoir = state.get('suspicious_reservoir', [])
                self.confirmed_malicious_reservoir = state.get('confirmed_malicious_reservoir', [])
            
            # Load transformer
            if self.model_path.exists():
                checkpoint = torch.load(self.model_path, map_location=self.device)
                self._load_transformer_weights(checkpoint)
                self.is_trained = True
            
            # Load isolation forest
            if self.iso_path.exists():
                with open(self.iso_path, 'rb') as f:
                    self.iso_forest = pickle.load(f)
            
            logger.info(f"Loaded student model for project {self.project_id[:8]}...")
            logger.info(f"  Vocabulary size: {self.vocab_size}")
            logger.info(f"  Logs processed: {self.logs_processed:,}")
            
        except Exception as e:
            logger.warning(f"Failed to load student model: {e}")
            self.is_trained = False
    
    def _load_transformer_weights(self, checkpoint: Dict):
        """Load transformer weights from checkpoint"""
        saved_state = checkpoint.get('model_state_dict', checkpoint)
        
        self.transformer = TemplateTransformer(
            vocab_size=self.vocab_size,
            pad_id=self.pad_id,
            d_model=128,  # Smaller than teacher
            n_heads=4,
            n_layers=2,   # Fewer layers
            ffn_dim=512,
            max_length=self.window_size,
            dropout=0.1
        ).to(self.device)
        
        current_state = self.transformer.state_dict()
        for name, tensor in saved_state.items():
            if name in current_state:
                if current_state[name].shape == tensor.shape:
                    current_state[name].copy_(tensor)
        
        self.transformer.load_state_dict(current_state)
        self.transformer.eval()
    
    def save(self):
        """Save student model state"""
        with self._lock:
            try:
                # Save transformer
                if self.transformer is not None:
                    torch.save({
                        'model_state_dict': self.transformer.state_dict(),
                        'vocab_size': self.vocab_size,
                        'pad_id': self.pad_id,
                        'unknown_id': self.unknown_id,
                        'threshold': self.transformer_threshold,
                        'saved_at': datetime.now().isoformat()
                    }, self.model_path)
                
                # Save state
                state = {
                    'project_id': self.project_id,
                    'template_to_id': self.template_to_id,
                    'id_to_template': self.id_to_template,
                    'template_counts': dict(self.template_counts),
                    'vocab_size': self.vocab_size,
                    'pad_id': self.pad_id,
                    'unknown_id': self.unknown_id,
                    'vocab_frozen': self.vocab_frozen,
                    'transformer_threshold': self.transformer_threshold,
                    'iso_threshold': self.iso_threshold,
                    'logs_processed': self.logs_processed,
                    'last_trained_at': self.last_trained_at,
                    'online_update_count': self.online_update_count,
                    'logs_since_last_update': self.logs_since_last_update,
                    'last_online_update_at': self.last_online_update_at,
                    'clean_normal_reservoir': self.clean_normal_reservoir[-512:],
                    'suspicious_reservoir': self.suspicious_reservoir[-512:],
                    'confirmed_malicious_reservoir': self.confirmed_malicious_reservoir[-512:],
                    'saved_at': datetime.now().isoformat()
                }
                with open(self.state_path, 'wb') as f:
                    pickle.dump(state, f)
                
                # Save isolation forest
                if self.iso_forest is not None:
                    with open(self.iso_path, 'wb') as f:
                        pickle.dump(self.iso_forest, f)
                
            except Exception as e:
                logger.warning(f"Failed to save student model: {e}")
    
    def add_template(self, normalized_template: str) -> int:
        """Add a new template to vocabulary"""
        with self._lock:
            if normalized_template in self.template_to_id:
                tid = self.template_to_id[normalized_template]
                self.template_counts[tid] += 1
                return tid
            
            if self.vocab_frozen:
                return self.unknown_id
            
            tid = len(self.id_to_template)
            self.template_to_id[normalized_template] = tid
            self.id_to_template.append(normalized_template)
            self.template_counts[tid] = 1
            return tid
    
    def get_template_id(self, normalized_template: str) -> int:
        """Get template ID, returning unknown ID for new templates"""
        if normalized_template in self.template_to_id:
            return self.template_to_id[normalized_template]
        return self.unknown_id if self.unknown_id is not None else -1
    
    def collect_training_data(
        self,
        template_id: int,
        session_id: str,
        features: Optional[np.ndarray] = None,
        collect_for_training: bool = True,
    ):
        """Collect data for training during warmup"""
        with self._lock:
            # Manage session window
            if session_id not in self.session_windows:
                self.session_windows[session_id] = deque(maxlen=self.window_size)
            
            self.session_windows[session_id].append(template_id)
            
            # Collect sequences for training
            if collect_for_training and len(self.session_windows[session_id]) >= 5:  # Min sequence length
                sequence = list(self.session_windows[session_id])
                self.training_sequences.append(sequence)
                self.clean_normal_reservoir.append(sequence)
                self.clean_normal_reservoir = self.clean_normal_reservoir[-2048:]
            
            # Collect features for isolation forest
            if collect_for_training and features is not None:
                self.training_features.append(features.flatten())
                self.clean_feature_reservoir.append(features.flatten())
                self.clean_feature_reservoir = self.clean_feature_reservoir[-2048:]

    def record_reservoir_observation(
        self,
        *,
        sequence: List[int],
        is_anomaly: bool,
        is_known_attack: bool,
    ) -> None:
        with self._lock:
            if not sequence:
                return
            clipped_sequence = list(sequence[-self.window_size:])
            if is_known_attack:
                self.confirmed_malicious_reservoir.append(clipped_sequence)
                self.confirmed_malicious_reservoir = self.confirmed_malicious_reservoir[-1024:]
            elif is_anomaly:
                self.suspicious_reservoir.append(clipped_sequence)
                self.suspicious_reservoir = self.suspicious_reservoir[-1024:]
            else:
                self.clean_normal_reservoir.append(clipped_sequence)
                self.clean_normal_reservoir = self.clean_normal_reservoir[-2048:]
    
    def train_from_teacher(
        self,
        teacher_model,
        epochs: int = 5,
        learning_rate: float = 1e-4,
        distillation_alpha: float = 0.5,
        temperature: float = 3.0,
        min_training_sequences: int = 100,
        min_if_feature_rows: int = 100,
    ):
        """
        Train student model using knowledge distillation from teacher.
        
        Args:
            teacher_model: The teacher model for soft labels
            epochs: Number of training epochs
            learning_rate: Learning rate
            distillation_alpha: Weight for distillation loss vs hard label loss
            temperature: Temperature for softening probability distributions
        """
        if self.is_training:
            logger.warning("Student is already being trained")
            return False
        
        if len(self.training_sequences) < min_training_sequences:
            logger.warning(f"Not enough training sequences: {len(self.training_sequences)}")
            return False
        
        self.is_training = True
        logger.info(f"\n{'='*70}")
        logger.info(f"TRAINING STUDENT MODEL - Project: {self.project_id[:8]}...")
        logger.info(f"{'='*70}")
        logger.info(f"  Training sequences: {len(self.training_sequences):,}")
        logger.info(f"  Vocabulary size: {len(self.id_to_template)}")
        logger.info(f"  Distillation alpha: {distillation_alpha}")
        logger.info(f"  Temperature: {temperature}")
        logger.info(f"{'='*70}\n")
        
        try:
            # Freeze vocabulary
            self.vocab_frozen = True
            base_vocab_size = len(self.id_to_template)
            self.pad_id = base_vocab_size
            self.unknown_id = base_vocab_size + 1
            self.vocab_size = self.unknown_id + 1

            def _pad_sequences(sequences: List[List[int]]) -> List[List[int]]:
                padded_sequences: List[List[int]] = []
                for seq in sequences:
                    sanitized = []
                    for token in seq:
                        if token is None or token >= self.pad_id:
                            sanitized.append(min(token, self.pad_id - 1) if token is not None else 0)
                        else:
                            sanitized.append(token)

                    if len(sanitized) < self.window_size:
                        sanitized = sanitized + [self.pad_id] * (self.window_size - len(sanitized))
                    else:
                        sanitized = sanitized[-self.window_size:]
                    padded_sequences.append(sanitized)
                return padded_sequences

            total_sequences = len(self.training_sequences)
            train_cutoff = max(1, int(total_sequences * 0.70))
            calibration_cutoff = max(train_cutoff + 1, int(total_sequences * 0.85))

            raw_train = list(self.training_sequences[:train_cutoff])

            # Sequence augmentation for small training sets.
            # Only applied to the training split (not calibration/holdout) so
            # evaluation scores stay unbiased.
            # Two cheap techniques that preserve the distribution:
            #   1. Sub-sequence windows: slide a shorter window over longer sequences
            #   2. Reversal: reversed order is unnatural and helps the model learn
            #      positional sensitivity without injecting false patterns
            if len(raw_train) < 60:
                augmented = []
                for seq in raw_train:
                    # Sub-sequence: take the last half if sequence is long enough
                    if len(seq) >= 6:
                        mid = len(seq) // 2
                        augmented.append(seq[mid:])
                    # Reversal (only for sequences of length ≥ 4)
                    if len(seq) >= 4:
                        augmented.append(list(reversed(seq)))
                raw_train = raw_train + augmented
                logger.info("  Augmented training set: %d → %d sequences", train_cutoff, len(raw_train))

            train_sequences = _pad_sequences(raw_train)
            calibration_sequences = _pad_sequences(self.training_sequences[train_cutoff:calibration_cutoff])
            holdout_sequences = _pad_sequences(self.training_sequences[calibration_cutoff:])

            if not calibration_sequences:
                calibration_sequences = train_sequences[-min(16, len(train_sequences)):]
            if not holdout_sequences:
                holdout_sequences = calibration_sequences[-min(16, len(calibration_sequences)):]

            soft_labels = None
            if teacher_model is not None and distillation_alpha > 0:
                logger.info("  Getting soft labels from teacher...")
                soft_labels = []
                for seq in train_sequences:
                    teacher_soft = teacher_model.get_soft_labels(seq)
                    if teacher_soft is not None:
                        soft_labels.append(teacher_soft.cpu())
                    else:
                        soft_labels.append(
                            torch.ones(self.window_size, teacher_model.vocab_size) / teacher_model.vocab_size
                        )

            # Initialize student transformer
            self.transformer = TemplateTransformer(
                vocab_size=self.vocab_size,
                pad_id=self.pad_id,
                d_model=128,  # Smaller than teacher (256)
                n_heads=4,    # Fewer heads (8)
                n_layers=2,   # Fewer layers (4)
                ffn_dim=512,  # Smaller FFN (1024)
                max_length=self.window_size,
                dropout=0.1
            ).to(self.device)
            
            # Create dataset
            dataset = StudentTrainingDataset(
                train_sequences,
                self.pad_id,
                soft_labels
            )
            # Scale batch size to dataset size so small datasets still get gradient signal.
            effective_batch = min(32, max(4, len(train_sequences) // 4))
            loader = DataLoader(dataset, batch_size=effective_batch, shuffle=True, drop_last=False)
            
            # Training
            self.transformer.train()
            optimizer = torch.optim.AdamW(self.transformer.parameters(), lr=learning_rate)
            
            for epoch in range(epochs):
                total_loss = 0
                total_hard_loss = 0
                total_distill_loss = 0
                
                for batch in loader:
                    input_ids = batch['input_ids'].to(self.device)
                    attention_mask = batch['attention_mask'].to(self.device)
                    
                    # Forward pass
                    logits = self.transformer(input_ids, attention_mask)
                    
                    # Hard label loss (standard cross-entropy)
                    targets = input_ids[:, 1:]
                    logits_shifted = logits[:, :-1, :]
                    
                    hard_loss = F.cross_entropy(
                        logits_shifted.reshape(-1, self.vocab_size),
                        targets.reshape(-1),
                        ignore_index=self.pad_id
                    )
                    
                    # Distillation loss (if soft labels available)
                    distill_loss = torch.tensor(0.0).to(self.device)
                    if 'soft_labels' in batch and distillation_alpha > 0:
                        teacher_soft = batch['soft_labels'].to(self.device)
                        
                        # Ensure dimensions match
                        if teacher_soft.size(-1) != self.vocab_size:
                            # Pad or truncate teacher soft labels to match student vocab
                            if teacher_soft.size(-1) > self.vocab_size:
                                teacher_soft = teacher_soft[..., :self.vocab_size]
                            else:
                                padding = torch.zeros(
                                    *teacher_soft.shape[:-1],
                                    self.vocab_size - teacher_soft.size(-1)
                                ).to(self.device)
                                teacher_soft = torch.cat([teacher_soft, padding], dim=-1)
                        
                        # KL divergence with temperature
                        student_log_prob = F.log_softmax(logits / temperature, dim=-1)
                        teacher_prob = F.softmax(teacher_soft / temperature, dim=-1)
                        
                        distill_loss = F.kl_div(
                            student_log_prob[:, :-1].reshape(-1, self.vocab_size),
                            teacher_prob[:, :-1].reshape(-1, self.vocab_size),
                            reduction='batchmean'
                        ) * (temperature ** 2)
                    
                    # Combined loss
                    loss = (1 - distillation_alpha) * hard_loss + distillation_alpha * distill_loss
                    
                    optimizer.zero_grad()
                    loss.backward()
                    optimizer.step()
                    
                    total_loss += loss.item()
                    total_hard_loss += hard_loss.item()
                    total_distill_loss += distill_loss.item()
                
                avg_loss = total_loss / len(loader)
                avg_hard = total_hard_loss / len(loader)
                avg_distill = total_distill_loss / len(loader)
                logger.info(f"  Epoch {epoch + 1}/{epochs} - Loss: {avg_loss:.4f} (Hard: {avg_hard:.4f}, Distill: {avg_distill:.4f})")
            
            self.transformer.eval()
            
            # Train isolation forest
            if len(self.training_features) >= min_if_feature_rows:
                logger.info("  Training isolation forest...")
                total_features = len(self.training_features)
                train_feature_cutoff = max(1, int(total_features * 0.70))
                calibration_feature_cutoff = max(train_feature_cutoff + 1, int(total_features * 0.85))
                train_matrix = np.vstack(self.training_features[:train_feature_cutoff])
                calibration_features = self.training_features[train_feature_cutoff:calibration_feature_cutoff]
                if not calibration_features:
                    calibration_features = self.training_features[-min(16, len(self.training_features)):]
                calibration_matrix = np.vstack(calibration_features)
                # Training features are warmup-collected clean baseline by design,
                # so assuming 10% contamination systematically mislabels normal traffic.
                # Use 'auto' (scikit-learn ≥1.3) or a low fixed value as fallback.
                try:
                    self.iso_forest = IsolationForest(
                        n_estimators=100,
                        contamination='auto',
                        random_state=42,
                        warm_start=False
                    )
                except (TypeError, ValueError):
                    # scikit-learn < 1.3 does not support contamination='auto'
                    self.iso_forest = IsolationForest(
                        n_estimators=100,
                        contamination=0.05,
                        random_state=42,
                        warm_start=False
                    )
                self.iso_forest.fit(train_matrix)
                scores = -self.iso_forest.score_samples(calibration_matrix)
                self.iso_threshold = float(np.percentile(scores, 95))
            
            # Calculate thresholds from held-out calibration windows
            self._update_threshold(calibration_sequences or holdout_sequences or train_sequences)
            
            # Mark as trained
            self.is_trained = True
            self.last_trained_at = datetime.now().isoformat()
            
            # Save
            self.save()
            
            # Clear training data
            self.training_sequences = []
            self.training_features = []
            
            logger.info(f"\nStudent model trained successfully!")
            logger.info(f"   Vocabulary: {self.vocab_size} tokens")
            logger.info(f"   Threshold: {self.transformer_threshold:.4f}")
            
            return True
            
        except Exception as e:
            logger.error(f"Student training failed: {e}")
            import traceback
            traceback.print_exc()
            return False
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
                    if math.isfinite(avg_nll):
                        scores.append(float(avg_nll))
                    else:
                        logger.warning("Student %s produced non-finite NLL during threshold update; skipping sample", self.project_id[:8])
        
        if scores:
            candidate_threshold = float(np.percentile(scores, 95))
            if math.isfinite(candidate_threshold) and candidate_threshold > 0:
                self.transformer_threshold = candidate_threshold
            else:
                logger.warning(
                    "Student %s produced non-finite threshold candidate (%s); retaining previous threshold=%s",
                    self.project_id[:8],
                    candidate_threshold,
                    self.transformer_threshold,
                )

    def _safe_transformer_threshold(self) -> float:
        """Return a finite positive transformer threshold for runtime decisions."""
        try:
            threshold = float(self.transformer_threshold)
        except (TypeError, ValueError):
            threshold = 6.5
        if not math.isfinite(threshold) or threshold <= 0:
            return 6.5
        return threshold
    
    def _score_transformer_sequence(self, sequence: List[int]) -> Tuple[float, Optional[str]]:
        """Calculate anomaly score from transformer (NLL) with error details."""
        if not self.is_trained or self.transformer is None:
            return 0.0, "transformer_not_trained"
        
        if len(sequence) < 1:
            return 0.0, None
        
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
                if not torch.isfinite(logits).all():
                    return 0.0, "non_finite_logits"
                
                input_shifted = input_ids[:, 1:]
                logits_shifted = logits[:, :-1, :]
                log_probs = F.log_softmax(logits_shifted, dim=-1)
                nll_per_pos = -log_probs.gather(2, input_shifted.unsqueeze(-1)).squeeze(-1)
                
                mask = attention_mask[:, 1:] == 1
                valid_nll = nll_per_pos[mask]
                
                if valid_nll.numel() > 0:
                    if not torch.isfinite(valid_nll).all():
                        return 0.0, "non_finite_nll"
                    score = valid_nll.mean().item()
                    if not math.isfinite(score):
                        return 0.0, "non_finite_nll_mean"
                    return float(score), None
                return 0.0, None
                
            except Exception as e:
                logger.warning(f"Student transformer error: {e}")
                return 0.0, str(e)

    def calculate_transformer_score(self, sequence: List[int]) -> float:
        """Calculate anomaly score from transformer (NLL)."""
        score, error = self._score_transformer_sequence(sequence)
        if error:
            return self._safe_transformer_threshold()
        return score
    
    def detect(
        self,
        log_data: Dict,
        sequence: List[int],
        session_stats: Dict,
        features: Optional[np.ndarray] = None,
        known_template_mask: Optional[List[bool]] = None,
    ) -> Dict:
        """
        Perform anomaly detection using student model.
        
        Args:
            log_data: Parsed log data
            sequence: Sequence of template IDs
            session_stats: Session statistics
            features: Optional pre-extracted features for isolation forest
        
        Returns:
            Detection result dictionary
        """
        self.logs_processed += 1
        self.logs_since_last_update += 1

        # 1. Rule-based detection
        rule_result = self.rule_detector.detect(
            log_data.get('path', '/'),
            log_data.get('method', 'GET'),
            log_data.get('status', 200)
        )
        
        # 2. Transformer detection
        transformer_threshold = self._safe_transformer_threshold()
        if sequence and self.unknown_id is not None:
            protected_mask = list(known_template_mask or [])
            if len(protected_mask) < len(sequence):
                protected_mask.extend([False] * (len(sequence) - len(protected_mask)))
            unknown_template_ratio = (
                sum(
                    1
                    for idx, tid in enumerate(sequence)
                    if tid == self.unknown_id and not protected_mask[idx]
                )
                / len(sequence)
            )
        else:
            unknown_template_ratio = 0.0
        transformer_context = 'single_log' if len(sequence) <= 1 else f'{len(sequence)}_logs'
        transformer_result = {
            'is_anomaly': 0,
            'score': 0.0,
            'threshold': transformer_threshold,
            'status': 'insufficient_context',
            'sequence_length': len(sequence),
            'context': transformer_context,
        }
        if len(sequence) >= MIN_SEQUENCE_CONTEXT:
            if unknown_template_ratio >= MAX_UNKNOWN_TEMPLATE_RATIO:
                # High unknown-template ratio signals novel endpoints, NOT necessarily malicious.
                # Emit novel_score separately; malicious_score stays 0.
                novel_penalty = unknown_template_ratio * transformer_threshold
                transformer_result = {
                    'is_anomaly': 0,
                    'score': novel_penalty,
                    'novel_score': novel_penalty,
                    'malicious_score': 0.0,
                    'threshold': transformer_threshold,
                    'status': 'novel_penalty',
                    'sequence_length': len(sequence),
                    'context': transformer_context,
                }
            else:
                transformer_score, transformer_error = self._score_transformer_sequence(sequence)
                if transformer_error:
                    transformer_result = {
                        'is_anomaly': 0,
                        'score': None,
                        'threshold': transformer_threshold,
                        'status': 'error',
                        'error': transformer_error[:160],
                        'sequence_length': len(sequence),
                        'context': transformer_context,
                    }
                else:
                    transformer_result = {
                        'is_anomaly': 1 if transformer_score > transformer_threshold else 0,
                        'score': float(transformer_score),
                        'threshold': transformer_threshold,
                        'status': 'active',
                        'sequence_length': len(sequence),
                        'context': transformer_context,
                    }
        
        # 3. Isolation Forest detection
        iso_result = {'is_anomaly': 0, 'score': 0.0, 'status': 'not_available'}
        if self.iso_forest is not None and features is not None:
            if not self._is_iso_forest_fitted():
                iso_result['status'] = 'not_fitted'
            else:
                try:
                    iso_score = -self.iso_forest.score_samples(features)[0]
                    iso_threshold = self.iso_threshold
                    iso_result = {
                        'is_anomaly': int(iso_score > iso_threshold) if iso_threshold is not None else int(self.iso_forest.predict(features)[0] == -1),
                        'score': float(iso_score),
                        'threshold': iso_threshold,
                        'status': 'active'
                    }
                except NotFittedError:
                    iso_result['status'] = 'not_fitted'
                except Exception as e:
                    iso_result['status'] = f'error: {str(e)[:50]}'
        
        # 4. Ensemble voting
        ablation = getattr(self, '_ablation_mode', 'none')
        votes = []
        weights = []
        vote_names = []

        if rule_result.get('is_attack') and ablation not in ('iso_only', 'transformer_only'):
            confidence = float(rule_result.get('confidence', 0.5))
            votes.append(1)
            weights.append(confidence)  # severity-tiered weight; no floor
            vote_names.append('rule')

        if iso_result.get('status') == 'active' and ablation not in ('rule_only', 'transformer_only'):
            votes.append(iso_result.get('is_anomaly', 0))
            weights.append(0.5)
            vote_names.append('iso')

        if transformer_result.get('status') in ('active', 'novel_penalty') and ablation not in ('rule_only', 'iso_only'):
            votes.append(transformer_result['is_anomaly'])
            weights.append(0.7)
            vote_names.append('transformer')

        total_weight = sum(weights)
        ensemble_score = (
            sum(v * w for v, w in zip(votes, weights)) / total_weight
            if total_weight > 0
            else 0.0
        )
        is_anomaly = ensemble_score > 0.5

        # Calibrated score (overrides ensemble threshold when calibrator is fitted)
        calibrated_score = None
        if self.calibrator is not None and self.calibrator.is_fitted:
            try:
                feat_vec = EnsembleCalibrator.build_feature_vector(
                    {
                        'transformer': transformer_result,
                        'isolation_forest': iso_result,
                        'rule_based': rule_result,
                        'unknown_template_ratio': unknown_template_ratio,
                        'ensemble': {'active_models': len(weights)},
                    },
                    session_stats,
                )
                calibrated_score = self.calibrator.predict_proba(feat_vec)
                if calibrated_score is not None:
                    is_anomaly = calibrated_score > 0.5
                    ensemble_score = calibrated_score
            except Exception as e:
                logger.warning("Calibrator failed, falling back to ensemble: %s", e)

        novel_score = float(transformer_result.get('novel_score', 0.0) or 0.0)

        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': ensemble_score,
            'novel_score': novel_score,
            'calibrated_score': calibrated_score,
            'model_type': 'student',
            'project_id': self.project_id,
            'rule_based': rule_result,
            'isolation_forest': iso_result,
            'transformer': transformer_result,
            'ensemble': {
                'score': ensemble_score,
                'votes': dict(zip(vote_names, votes)),
                'weights': dict(zip(vote_names, weights)),
                'active_models': len(weights),
            },
            'unknown_template_ratio': float(unknown_template_ratio),
        }

    def online_update(
        self,
        min_reservoir_size: int = 500,
        epochs: int = 2,
        learning_rate: float = 5e-5,
        max_kl_divergence: float = 2.0,
    ) -> bool:
        """
        Update student model online using clean_normal_reservoir.

        Performs a short fine-tuning pass on recent clean data. A KL divergence
        guard rolls back the update if the model drifts too far from the prior
        checkpoint.

        Returns True if the update was applied, False if skipped or rolled back.
        """
        if not self.is_trained or self.transformer is None:
            return False
        if len(self.clean_normal_reservoir) < min_reservoir_size:
            logger.info(
                "Online update skipped: reservoir %d < %d",
                len(self.clean_normal_reservoir),
                min_reservoir_size,
            )
            return False
        if self.is_training:
            return False

        self.is_training = True
        try:
            # Snapshot current weights for rollback
            prior_state = {k: v.clone() for k, v in self.transformer.state_dict().items()}

            # Prepare data from reservoir
            sequences = list(self.clean_normal_reservoir[-min_reservoir_size:])
            padded: List[List[int]] = []
            for seq in sequences:
                sanitized = []
                for t in seq:
                    if t is None or t >= self.vocab_size:
                        sanitized.append(self.unknown_id)
                    elif t >= self.pad_id:
                        sanitized.append(self.pad_id - 1 if self.pad_id > 0 else 0)
                    else:
                        sanitized.append(t)
                if len(sanitized) < self.window_size:
                    sanitized += [self.pad_id] * (self.window_size - len(sanitized))
                else:
                    sanitized = sanitized[-self.window_size:]
                padded.append(sanitized)

            # Compute reference logits for KL check
            ref_sample = padded[:64]
            ref_input = torch.tensor(ref_sample, dtype=torch.long).to(self.device)
            ref_mask = torch.tensor(
                [[1 if t != self.pad_id else 0 for t in s] for s in ref_sample],
                dtype=torch.long,
            ).to(self.device)
            with torch.no_grad():
                ref_logits = self.transformer(ref_input, ref_mask)
                ref_probs = F.softmax(ref_logits, dim=-1)

            # Fine-tune
            dataset = StudentTrainingDataset(padded, self.pad_id)
            batch_size = min(32, max(4, len(padded) // 4))
            loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, drop_last=False)

            self.transformer.train()
            optimizer = torch.optim.AdamW(self.transformer.parameters(), lr=learning_rate)

            for epoch in range(epochs):
                total_loss = 0.0
                for batch in loader:
                    input_ids = batch["input_ids"].to(self.device)
                    attention_mask = batch["attention_mask"].to(self.device)
                    logits = self.transformer(input_ids, attention_mask)
                    targets = input_ids[:, 1:]
                    logits_shifted = logits[:, :-1, :]
                    loss = F.cross_entropy(
                        logits_shifted.reshape(-1, self.vocab_size),
                        targets.reshape(-1),
                        ignore_index=self.pad_id,
                    )
                    optimizer.zero_grad()
                    loss.backward()
                    optimizer.step()
                    total_loss += loss.item()
                logger.info(
                    "  Online update epoch %d/%d loss: %.4f",
                    epoch + 1,
                    epochs,
                    total_loss / max(len(loader), 1),
                )

            self.transformer.eval()

            # KL divergence check
            with torch.no_grad():
                new_logits = self.transformer(ref_input, ref_mask)
                new_probs = F.softmax(new_logits, dim=-1)
                kl = F.kl_div(
                    new_probs.log().reshape(-1, self.vocab_size),
                    ref_probs.reshape(-1, self.vocab_size),
                    reduction="batchmean",
                ).item()

            if kl > max_kl_divergence:
                logger.warning(
                    "Online update rolled back: KL=%.4f > max=%.4f",
                    kl,
                    max_kl_divergence,
                )
                self.transformer.load_state_dict(prior_state)
                self.transformer.eval()
                return False

            # Update threshold from new model
            self._update_threshold(padded)
            self.last_trained_at = datetime.now().isoformat()
            self.last_online_update_at = datetime.now().isoformat()
            self.online_update_count += 1
            self.logs_since_last_update = 0
            self.save()
            logger.info(
                "Online student update #%d applied (KL=%.4f, reservoir=%d)",
                self.online_update_count, kl, len(self.clean_normal_reservoir),
            )
            return True

        except Exception as e:
            logger.error("Online student update failed: %s", e)
            return False
        finally:
            self.is_training = False

    def get_training_data_for_teacher(self) -> Tuple[List[List[int]], Optional[np.ndarray]]:
        """
        Get accumulated training data for teacher model updates.
        
        Returns:
            Tuple of (sequences, features) for teacher training
        """
        with self._lock:
            sequences = list(self.clean_normal_reservoir)
            features = None
            if self.clean_feature_reservoir:
                features = np.vstack(self.clean_feature_reservoir)
            return sequences, features
    
    def get_model_info(self) -> Dict:
        """Get student model information"""
        return {
            'project_id': self.project_id,
            'vocab_size': self.vocab_size,
            'num_templates': len(self.id_to_template),
            'transformer_threshold': self._safe_transformer_threshold(),
            'iso_threshold': self.iso_threshold,
            'logs_processed': self.logs_processed,
            'is_trained': self.is_trained,
            'is_training': self.is_training,
            'last_trained_at': self.last_trained_at,
            'window_size': self.window_size,
            'training_sequences_pending': len(self.training_sequences),
            'clean_normal_reservoir_count': len(self.clean_normal_reservoir),
            'suspicious_reservoir_count': len(self.suspicious_reservoir),
            'confirmed_malicious_reservoir_count': len(self.confirmed_malicious_reservoir),
            'online_update_count': self.online_update_count,
            'logs_since_last_update': self.logs_since_last_update,
            'last_online_update_at': self.last_online_update_at,
        }
