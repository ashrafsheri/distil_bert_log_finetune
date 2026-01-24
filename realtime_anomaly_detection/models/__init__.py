"""Models package for real-time anomaly detection"""

# Original single-tenant detectors
from .ensemble_detector import EnsembleAnomalyDetector, RuleBasedDetector, ApacheLogNormalizer, TemplateTransformer
from .adaptive_detector import AdaptiveEnsembleDetector

# Multi-tenant student-teacher architecture
from .project_manager import ProjectManager, ProjectConfig, ProjectPhase
from .teacher_model import TeacherModel
from .student_model import StudentModel
from .multi_tenant_detector import MultiTenantDetector
from .knowledge_distillation import (
    KnowledgeDistillationTrainer,
    TeacherUpdateScheduler,
    DistillationConfig,
    DistillationLoss,
    distill_student_from_teacher,
    calculate_distillation_metrics
)

__all__ = [
    # Original detectors
    'EnsembleAnomalyDetector',
    'RuleBasedDetector',
    'AdaptiveEnsembleDetector',
    'ApacheLogNormalizer',
    'TemplateTransformer',
    
    # Multi-tenant architecture
    'ProjectManager',
    'ProjectConfig',
    'ProjectPhase',
    'TeacherModel',
    'StudentModel',
    'MultiTenantDetector',
    
    # Knowledge distillation
    'KnowledgeDistillationTrainer',
    'TeacherUpdateScheduler',
    'DistillationConfig',
    'DistillationLoss',
    'distill_student_from_teacher',
    'calculate_distillation_metrics',
]
