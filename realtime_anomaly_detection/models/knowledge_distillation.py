"""
Knowledge Distillation Module
Utilities for training student models from teacher and for periodic
teacher model updates using aggregated student logs.
"""

import math
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable
from datetime import datetime
import time

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader


class DistillationConfig:
    """Configuration for knowledge distillation training"""
    
    def __init__(
        self,
        # Training parameters
        epochs: int = 5,
        batch_size: int = 32,
        learning_rate: float = 1e-4,
        weight_decay: float = 0.01,
        
        # Distillation parameters
        alpha: float = 0.5,          # Weight for distillation loss (vs hard label)
        temperature: float = 3.0,     # Temperature for softening distributions
        
        # Regularization
        label_smoothing: float = 0.1,
        dropout_rate: float = 0.1,
        
        # Early stopping
        patience: int = 3,
        min_delta: float = 0.001,
        
        # Checkpointing
        save_best: bool = True,
        checkpoint_dir: Optional[Path] = None
    ):
        self.epochs = epochs
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self.weight_decay = weight_decay
        self.alpha = alpha
        self.temperature = temperature
        self.label_smoothing = label_smoothing
        self.dropout_rate = dropout_rate
        self.patience = patience
        self.min_delta = min_delta
        self.save_best = save_best
        self.checkpoint_dir = checkpoint_dir


class DistillationDataset(Dataset):
    """Dataset for knowledge distillation with teacher soft labels"""
    
    def __init__(
        self,
        sequences: List[List[int]],
        soft_labels: Optional[List[torch.Tensor]],
        pad_id: int
    ):
        self.sequences = sequences
        self.soft_labels = soft_labels
        self.pad_id = pad_id
    
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


class DistillationLoss(nn.Module):
    """
    Combined loss for knowledge distillation.
    
    Combines:
    - Hard label loss (cross-entropy with actual targets)
    - Soft label loss (KL divergence with teacher predictions)
    
    The temperature parameter softens both student and teacher distributions,
    making it easier for the student to learn from the teacher's dark knowledge.
    """
    
    def __init__(
        self,
        alpha: float = 0.5,
        temperature: float = 3.0,
        label_smoothing: float = 0.0,
        ignore_index: int = -100
    ):
        super().__init__()
        self.alpha = alpha
        self.temperature = temperature
        self.ignore_index = ignore_index
        self.ce_loss = nn.CrossEntropyLoss(
            ignore_index=ignore_index,
            label_smoothing=label_smoothing
        )
    
    def forward(
        self,
        student_logits: torch.Tensor,
        targets: torch.Tensor,
        teacher_soft_labels: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, Dict[str, float]]:
        """
        Compute combined distillation loss.
        
        Args:
            student_logits: Student model output logits [batch, seq, vocab]
            targets: Hard label targets [batch, seq]
            teacher_soft_labels: Optional teacher soft labels [batch, seq, vocab]
        
        Returns:
            Tuple of (combined_loss, loss_dict)
        """
        # Flatten for loss computation
        batch_size, seq_len, vocab_size = student_logits.shape
        student_flat = student_logits.view(-1, vocab_size)
        targets_flat = targets.view(-1)
        
        # Hard label loss
        hard_loss = self.ce_loss(student_flat, targets_flat)
        
        # Soft label loss (if teacher labels provided)
        soft_loss = torch.tensor(0.0, device=student_logits.device)
        
        if teacher_soft_labels is not None and self.alpha > 0:
            # Handle vocab size mismatch
            teacher_vocab = teacher_soft_labels.size(-1)
            if teacher_vocab != vocab_size:
                if teacher_vocab > vocab_size:
                    teacher_soft_labels = teacher_soft_labels[..., :vocab_size]
                else:
                    padding = torch.zeros(
                        batch_size, seq_len, vocab_size - teacher_vocab,
                        device=teacher_soft_labels.device
                    )
                    teacher_soft_labels = torch.cat([teacher_soft_labels, padding], dim=-1)
            
            # Apply temperature
            student_log_probs = F.log_softmax(
                student_logits / self.temperature, dim=-1
            )
            teacher_probs = F.softmax(
                teacher_soft_labels / self.temperature, dim=-1
            )
            
            # KL divergence
            soft_loss = F.kl_div(
                student_log_probs.view(-1, vocab_size),
                teacher_probs.view(-1, vocab_size),
                reduction='batchmean'
            ) * (self.temperature ** 2)
        
        # Combine losses
        combined_loss = (1 - self.alpha) * hard_loss + self.alpha * soft_loss
        
        loss_dict = {
            'combined': combined_loss.item(),
            'hard': hard_loss.item(),
            'soft': soft_loss.item()
        }
        
        return combined_loss, loss_dict


class KnowledgeDistillationTrainer:
    """
    Trainer for knowledge distillation from teacher to student model.
    
    Handles:
    - Soft label generation from teacher
    - Student training with combined loss
    - Progress tracking and callbacks
    - Early stopping and checkpointing
    """
    
    def __init__(
        self,
        teacher_model,
        student_model,
        config: DistillationConfig,
        device: str = 'cpu'
    ):
        self.teacher = teacher_model
        self.student = student_model
        self.config = config
        self.device = torch.device(device)
        
        # Training state
        self.current_epoch = 0
        self.best_loss = float('inf')
        self.patience_counter = 0
        self.training_history: List[Dict] = []
        
        # Loss function
        self.loss_fn = DistillationLoss(
            alpha=config.alpha,
            temperature=config.temperature,
            label_smoothing=config.label_smoothing,
            ignore_index=student_model.pad_id if hasattr(student_model, 'pad_id') else -100
        )
    
    def generate_soft_labels(
        self,
        sequences: List[List[int]],
        batch_size: int = 64
    ) -> List[torch.Tensor]:
        """
        Generate soft labels from teacher for a list of sequences.
        
        Args:
            sequences: List of token sequences
            batch_size: Batch size for processing
        
        Returns:
            List of soft label tensors
        """
        soft_labels = []
        
        if self.teacher is None:
            return soft_labels
        
        print("  Generating soft labels from teacher...")
        
        for i in range(0, len(sequences), batch_size):
            batch_seqs = sequences[i:i + batch_size]
            
            for seq in batch_seqs:
                teacher_soft = self.teacher.get_soft_labels(seq)
                if teacher_soft is not None:
                    soft_labels.append(teacher_soft.cpu())
                else:
                    # Uniform distribution fallback
                    soft_labels.append(
                        torch.ones(len(seq), self.teacher.vocab_size) / self.teacher.vocab_size
                    )
        
        return soft_labels
    
    def train(
        self,
        sequences: List[List[int]],
        soft_labels: Optional[List[torch.Tensor]] = None,
        progress_callback: Optional[Callable[[int, Dict], None]] = None
    ) -> Dict:
        """
        Train student model with knowledge distillation.
        
        Args:
            sequences: Padded training sequences
            soft_labels: Optional pre-computed soft labels from teacher
            progress_callback: Optional callback for progress updates
        
        Returns:
            Training summary dictionary
        """
        if soft_labels is None and self.teacher is not None:
            soft_labels = self.generate_soft_labels(sequences)
        
        # Create dataset and loader
        dataset = DistillationDataset(
            sequences=sequences,
            soft_labels=soft_labels,
            pad_id=self.student.pad_id
        )
        loader = DataLoader(
            dataset,
            batch_size=self.config.batch_size,
            shuffle=True
        )
        
        # Optimizer
        optimizer = torch.optim.AdamW(
            self.student.transformer.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay
        )
        
        # Learning rate scheduler
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer,
            T_max=self.config.epochs * len(loader)
        )
        
        # Training loop
        self.student.transformer.train()
        
        for epoch in range(self.config.epochs):
            self.current_epoch = epoch
            epoch_losses = {'combined': 0, 'hard': 0, 'soft': 0}
            
            for batch in loader:
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                teacher_soft = batch.get('soft_labels')
                if teacher_soft is not None:
                    teacher_soft = teacher_soft.to(self.device)
                
                # Forward pass
                logits = self.student.transformer(input_ids, attention_mask)
                
                # Prepare targets (shifted for next token prediction)
                targets = input_ids[:, 1:]
                logits_shifted = logits[:, :-1, :]
                
                if teacher_soft is not None:
                    teacher_soft = teacher_soft[:, :-1, :]
                
                # Compute loss
                loss, loss_dict = self.loss_fn(
                    logits_shifted,
                    targets,
                    teacher_soft
                )
                
                # Backward pass
                optimizer.zero_grad()
                loss.backward()
                
                # Gradient clipping
                torch.nn.utils.clip_grad_norm_(
                    self.student.transformer.parameters(),
                    max_norm=1.0
                )
                
                optimizer.step()
                scheduler.step()
                
                # Accumulate losses
                for k, v in loss_dict.items():
                    epoch_losses[k] += v
            
            # Average losses
            for k in epoch_losses:
                epoch_losses[k] /= len(loader)
            
            # Record history
            epoch_record = {
                'epoch': epoch + 1,
                'losses': epoch_losses,
                'lr': scheduler.get_last_lr()[0]
            }
            self.training_history.append(epoch_record)
            
            print(f"  Epoch {epoch + 1}/{self.config.epochs} - "
                  f"Loss: {epoch_losses['combined']:.4f} "
                  f"(Hard: {epoch_losses['hard']:.4f}, Soft: {epoch_losses['soft']:.4f})")
            
            # Progress callback
            if progress_callback:
                progress_callback(epoch, epoch_losses)
            
            # Early stopping check
            if epoch_losses['combined'] < self.best_loss - self.config.min_delta:
                self.best_loss = epoch_losses['combined']
                self.patience_counter = 0
                
                # Save best model
                if self.config.save_best and self.config.checkpoint_dir:
                    self._save_checkpoint()
            else:
                self.patience_counter += 1
                if self.patience_counter >= self.config.patience:
                    print(f"  Early stopping at epoch {epoch + 1}")
                    break
        
        self.student.transformer.eval()
        
        return {
            'final_loss': epoch_losses['combined'],
            'best_loss': self.best_loss,
            'epochs_trained': self.current_epoch + 1,
            'history': self.training_history
        }
    
    def _save_checkpoint(self):
        """Save training checkpoint"""
        if self.config.checkpoint_dir:
            checkpoint_path = Path(self.config.checkpoint_dir) / 'best_student.pt'
            checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            torch.save({
                'epoch': self.current_epoch,
                'model_state_dict': self.student.transformer.state_dict(),
                'best_loss': self.best_loss,
                'config': vars(self.config)
            }, checkpoint_path)


class TeacherUpdateScheduler:
    """
    Scheduler for periodic teacher model updates from student logs.
    
    Manages:
    - Collection of training data from students
    - Scheduling of teacher updates
    - Logging and monitoring
    """
    
    def __init__(
        self,
        multi_tenant_detector,
        update_interval_hours: int = 168,  # Weekly by default
        min_new_samples: int = 10000,
        max_samples_per_project: int = 50000
    ):
        self.detector = multi_tenant_detector
        self.update_interval_hours = update_interval_hours
        self.min_new_samples = min_new_samples
        self.max_samples_per_project = max_samples_per_project
        
        # State
        self.last_update: Optional[datetime] = None
        self.update_history: List[Dict] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
    
    def should_update(self) -> bool:
        """Check if teacher update is due"""
        if self.last_update is None:
            return True
        
        hours_since = (datetime.now() - self.last_update).total_seconds() / 3600
        return hours_since >= self.update_interval_hours
    
    def collect_training_data(self) -> Tuple[List[List[int]], Optional[np.ndarray]]:
        """
        Collect training data from all active student models.
        
        Returns:
            Tuple of (sequences, features)
        """
        all_sequences = []
        all_features = []
        
        projects = self.detector.project_manager.get_projects_for_teacher_update()
        
        for project in projects:
            student = self.detector.students.get(project.project_id)
            if student and student.is_trained:
                sequences, features = student.get_training_data_for_teacher()
                
                # Limit samples per project
                if len(sequences) > self.max_samples_per_project:
                    indices = np.random.choice(
                        len(sequences),
                        self.max_samples_per_project,
                        replace=False
                    )
                    sequences = [sequences[i] for i in indices]
                    if features is not None:
                        features = features[indices]
                
                all_sequences.extend(sequences)
                if features is not None:
                    all_features.append(features)
        
        combined_features = None
        if all_features:
            combined_features = np.vstack(all_features)
        
        return all_sequences, combined_features
    
    def perform_update(self) -> Dict:
        """
        Perform teacher model update.
        
        Returns:
            Update summary dictionary
        """
        print(f"\n{'='*70}")
        print(f"🎓 SCHEDULED TEACHER UPDATE")
        print(f"{'='*70}\n")
        
        start_time = time.time()
        
        # Collect data
        sequences, features = self.collect_training_data()
        
        if len(sequences) < self.min_new_samples:
            print(f"⚠️ Not enough new samples: {len(sequences)} < {self.min_new_samples}")
            return {
                'success': False,
                'reason': 'insufficient_samples',
                'samples_collected': len(sequences)
            }
        
        print(f"  Collected {len(sequences):,} sequences from students")
        
        # Update teacher
        self.detector.teacher.update_from_student_logs(
            all_sequences=sequences,
            all_features=features,
            epochs=2,
            learning_rate=1e-5
        )
        
        # Record update
        self.last_update = datetime.now()
        duration = time.time() - start_time
        
        update_record = {
            'timestamp': self.last_update.isoformat(),
            'samples_used': len(sequences),
            'duration_seconds': duration,
            'success': True
        }
        self.update_history.append(update_record)
        
        # Update detector's project manager
        self.detector.project_manager.mark_teacher_updated()
        
        print(f"\n✅ Teacher update complete in {duration:.1f}s")
        
        return update_record
    
    def start_background_scheduler(self):
        """Start background thread for automatic updates"""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self._thread.start()
        print(f"📅 Teacher update scheduler started (interval: {self.update_interval_hours}h)")
    
    def stop_background_scheduler(self):
        """Stop background scheduler"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _scheduler_loop(self):
        """Background scheduler loop"""
        while self._running:
            try:
                if self.should_update():
                    self.perform_update()
            except Exception as e:
                print(f"⚠️ Teacher update failed: {e}")
            
            # Sleep for 1 hour between checks
            for _ in range(3600):
                if not self._running:
                    break
                time.sleep(1)


def distill_student_from_teacher(
    teacher_model,
    student_model,
    training_sequences: List[List[int]],
    config: Optional[DistillationConfig] = None,
    device: str = 'cpu'
) -> Dict:
    """
    Convenience function to train a student model from a teacher.
    
    Args:
        teacher_model: Trained teacher model
        student_model: Student model to train
        training_sequences: Padded training sequences
        config: Optional distillation configuration
        device: Device to use
    
    Returns:
        Training result dictionary
    """
    if config is None:
        config = DistillationConfig()
    
    trainer = KnowledgeDistillationTrainer(
        teacher_model=teacher_model,
        student_model=student_model,
        config=config,
        device=device
    )
    
    return trainer.train(training_sequences)


def calculate_distillation_metrics(
    teacher_model,
    student_model,
    test_sequences: List[List[int]],
    device: str = 'cpu'
) -> Dict:
    """
    Calculate metrics comparing teacher and student predictions.
    
    Args:
        teacher_model: Teacher model
        student_model: Student model
        test_sequences: Test sequences
        device: Device to use
    
    Returns:
        Metrics dictionary
    """
    device = torch.device(device)
    
    teacher_scores = []
    student_scores = []
    agreement_count = 0
    
    for seq in test_sequences[:1000]:  # Sample for efficiency
        # Teacher score
        t_score = teacher_model.calculate_transformer_score(seq)
        teacher_scores.append(t_score)
        
        # Student score
        s_score = student_model.calculate_transformer_score(seq)
        student_scores.append(s_score)
        
        # Check agreement on anomaly classification
        t_anomaly = t_score > teacher_model.transformer_threshold
        s_anomaly = s_score > student_model.transformer_threshold
        if t_anomaly == s_anomaly:
            agreement_count += 1
    
    # Calculate correlation
    correlation = np.corrcoef(teacher_scores, student_scores)[0, 1]
    
    return {
        'agreement_rate': agreement_count / len(test_sequences[:1000]),
        'score_correlation': float(correlation),
        'teacher_mean_score': float(np.mean(teacher_scores)),
        'student_mean_score': float(np.mean(student_scores)),
        'teacher_std_score': float(np.std(teacher_scores)),
        'student_std_score': float(np.std(student_scores))
    }
