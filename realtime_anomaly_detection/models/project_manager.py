"""
Project Manager Module
Manages multi-tenant projects with API keys, warmup tracking, and project-specific configurations.
"""

import json
import os
import uuid
import hashlib
import secrets
import threading
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import pickle
import logging


logger = logging.getLogger(__name__)


class ProjectPhase(Enum):
    """Phases of project lifecycle"""
    WARMUP = "warmup"           # Using teacher model, collecting logs
    TRAINING = "training"       # Student model is being trained
    ACTIVE = "active"           # Using project-specific student model
    SUSPENDED = "suspended"     # Project temporarily suspended
    ERROR = "error"             # Project in error state


@dataclass
class ProjectConfig:
    """Configuration for a single project"""
    project_id: str
    project_name: str
    api_key: str
    api_key_hash: str
    
    # Warmup configuration
    warmup_threshold: int = 10000  # Number of logs before student training
    traffic_profile: str = "standard"
    current_log_count: int = 0
    phase: str = ProjectPhase.WARMUP.value
    baseline_eligible_count: int = 0
    clean_baseline_count: int = 0
    dirty_excluded_count: int = 0
    probe_skipped_count: int = 0
    total_received_count: int = 0
    parse_failure_count: int = 0
    recent_total_received_count: int = 0
    recent_parse_failure_count: int = 0
    observed_hours: List[int] = field(default_factory=list)
    data_quality_incident_open: bool = False
    student_training_blockers: List[str] = field(default_factory=list)
    calibration_threshold: float = 0.5
    threshold_source: str = "bootstrap"
    threshold_fitted_at: Optional[str] = None
    calibration_sample_count: int = 0
    score_normalization_version: str = "hybrid-v1"
    feature_schema_version: str = "access-log-v2"
    
    # Timestamps
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_activity: str = field(default_factory=lambda: datetime.now().isoformat())
    student_trained_at: Optional[str] = None
    
    # Model paths
    student_model_path: Optional[str] = None
    student_state_path: Optional[str] = None
    
    # Training metrics
    training_sequences_collected: int = 0
    unique_templates_seen: int = 0
    distinct_template_count: int = 0
    teacher_last_updated_at: Optional[str] = None
    teacher_freshness: Optional[str] = None
    clean_normal_reservoir_count: int = 0
    suspicious_reservoir_count: int = 0
    confirmed_malicious_reservoir_count: int = 0
    
    # Elasticsearch index configuration
    es_index_pattern: Optional[str] = None
    
    # Metadata
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'project_id': self.project_id,
            'project_name': self.project_name,
            'api_key': self.api_key,
            'api_key_hash': self.api_key_hash,
            'warmup_threshold': self.warmup_threshold,
            'traffic_profile': self.traffic_profile,
            'current_log_count': self.current_log_count,
            'phase': self.phase,
            'baseline_eligible_count': self.baseline_eligible_count,
            'clean_baseline_count': self.clean_baseline_count,
            'dirty_excluded_count': self.dirty_excluded_count,
            'probe_skipped_count': self.probe_skipped_count,
            'total_received_count': self.total_received_count,
            'parse_failure_count': self.parse_failure_count,
            'recent_total_received_count': self.recent_total_received_count,
            'recent_parse_failure_count': self.recent_parse_failure_count,
            'observed_hours': self.observed_hours,
            'data_quality_incident_open': self.data_quality_incident_open,
            'student_training_blockers': self.student_training_blockers,
            'calibration_threshold': self.calibration_threshold,
            'threshold_source': self.threshold_source,
            'threshold_fitted_at': self.threshold_fitted_at,
            'calibration_sample_count': self.calibration_sample_count,
            'score_normalization_version': self.score_normalization_version,
            'feature_schema_version': self.feature_schema_version,
            'created_at': self.created_at,
            'last_activity': self.last_activity,
            'student_trained_at': self.student_trained_at,
            'student_model_path': self.student_model_path,
            'student_state_path': self.student_state_path,
            'training_sequences_collected': self.training_sequences_collected,
            'unique_templates_seen': self.unique_templates_seen,
            'distinct_template_count': self.distinct_template_count,
            'teacher_last_updated_at': self.teacher_last_updated_at,
            'teacher_freshness': self.teacher_freshness,
            'clean_normal_reservoir_count': self.clean_normal_reservoir_count,
            'suspicious_reservoir_count': self.suspicious_reservoir_count,
            'confirmed_malicious_reservoir_count': self.confirmed_malicious_reservoir_count,
            'es_index_pattern': self.es_index_pattern,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ProjectConfig':
        """Create from dictionary"""
        return cls(
            project_id=data['project_id'],
            project_name=data['project_name'],
            api_key=data['api_key'],
            api_key_hash=data['api_key_hash'],
            warmup_threshold=data.get('warmup_threshold', 10000),
            traffic_profile=data.get('traffic_profile', data.get('metadata', {}).get('traffic_profile', 'standard')),
            current_log_count=data.get('current_log_count', 0),
            phase=data.get('phase', ProjectPhase.WARMUP.value),
            baseline_eligible_count=data.get('baseline_eligible_count', 0),
            clean_baseline_count=data.get('clean_baseline_count', data.get('baseline_eligible_count', 0)),
            dirty_excluded_count=data.get('dirty_excluded_count', 0),
            probe_skipped_count=data.get('probe_skipped_count', 0),
            total_received_count=data.get('total_received_count', 0),
            parse_failure_count=data.get('parse_failure_count', 0),
            recent_total_received_count=data.get('recent_total_received_count', 0),
            recent_parse_failure_count=data.get('recent_parse_failure_count', 0),
            observed_hours=data.get('observed_hours', []),
            data_quality_incident_open=data.get('data_quality_incident_open', False),
            student_training_blockers=data.get('student_training_blockers', []),
            calibration_threshold=data.get('calibration_threshold', 0.5),
            threshold_source=data.get('threshold_source', 'bootstrap'),
            threshold_fitted_at=data.get('threshold_fitted_at'),
            calibration_sample_count=data.get('calibration_sample_count', 0),
            score_normalization_version=data.get('score_normalization_version', 'hybrid-v1'),
            feature_schema_version=data.get('feature_schema_version', 'access-log-v2'),
            created_at=data.get('created_at', datetime.now().isoformat()),
            last_activity=data.get('last_activity', datetime.now().isoformat()),
            student_trained_at=data.get('student_trained_at'),
            student_model_path=data.get('student_model_path'),
            student_state_path=data.get('student_state_path'),
            training_sequences_collected=data.get('training_sequences_collected', 0),
            unique_templates_seen=data.get('unique_templates_seen', 0),
            distinct_template_count=data.get('distinct_template_count', data.get('unique_templates_seen', 0)),
            teacher_last_updated_at=data.get('teacher_last_updated_at'),
            teacher_freshness=data.get('teacher_freshness'),
            clean_normal_reservoir_count=data.get('clean_normal_reservoir_count', 0),
            suspicious_reservoir_count=data.get('suspicious_reservoir_count', 0),
            confirmed_malicious_reservoir_count=data.get('confirmed_malicious_reservoir_count', 0),
            es_index_pattern=data.get('es_index_pattern'),
            metadata=data.get('metadata', {})
        )


class ProjectManager:
    """
    Manages multiple tenant projects for the anomaly detection SaaS.
    
    Responsibilities:
    - Create and manage projects with unique API keys
    - Track warmup progress for each project
    - Manage project lifecycle (warmup -> training -> active)
    - Persist project state across restarts
    - Coordinate with teacher and student models
    """
    
    def __init__(self, storage_dir: Path, teacher_update_interval_days: int = 7):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.parse_failure_window = int(os.getenv("MULTI_TENANT_PARSE_FAILURE_WINDOW", "2000"))
        
        # Project storage
        self.projects: Dict[str, ProjectConfig] = {}
        self.api_key_to_project: Dict[str, str] = {}  # api_key_hash -> project_id
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Teacher model update configuration
        self.teacher_update_interval_days = teacher_update_interval_days
        self.last_teacher_update: Optional[datetime] = None
        
        # Paths
        self.projects_file = self.storage_dir / 'projects.json'
        self.manager_state_file = self.storage_dir / 'manager_state.pkl'

        # Debounced-save infrastructure (item 7)
        # Hot-path calls mark dirty; a background thread flushes every 30 s.
        # Critical mutations (create, delete, phase transitions, key ops) still
        # call _save_projects() directly so they are durable immediately.
        self._dirty: bool = False
        self._save_interval: float = float(os.getenv('PM_SAVE_INTERVAL', '30'))
        self._flush_stop: threading.Event = threading.Event()
        self._flush_thread: Optional[threading.Thread] = None

        # Load existing projects
        self._load_projects()
        
        logger.info(f"\n{'='*70}")
        logger.info(f"PROJECT MANAGER INITIALIZED")
        logger.info(f"{'='*70}")
        logger.info(f"  Storage directory: {self.storage_dir}")
        logger.info(f"  Active projects: {len(self.projects)}")
        logger.info(f"  Teacher update interval: {teacher_update_interval_days} days")
        logger.info(f"{'='*70}\n")
    
    def _generate_api_key(self) -> Tuple[str, str]:
        """Generate a secure API key and its hash"""
        # Generate a secure random API key
        api_key = f"sk-{secrets.token_urlsafe(32)}"
        # Hash for storage and lookup
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        return api_key, api_key_hash
    
    def _hash_api_key(self, api_key: str) -> str:
        """Hash an API key for comparison"""
        return hashlib.sha256(api_key.encode()).hexdigest()

    def ensure_project(
        self,
        project_id: str,
        project_name: str,
        warmup_threshold: int = 10000,
        metadata: Optional[Dict] = None,
        traffic_profile: str = "standard",
    ) -> ProjectConfig:
        """Ensure a backend-owned project exists in detector storage."""
        with self._lock:
            project = self.projects.get(project_id)
            if project is None:
                api_key = f"internal-{project_id}"
                api_key_hash = self._hash_api_key(api_key)
                project_dir = self.storage_dir / project_id
                project_dir.mkdir(parents=True, exist_ok=True)
                project = ProjectConfig(
                    project_id=project_id,
                    project_name=project_name,
                    api_key=api_key,
                    api_key_hash=api_key_hash,
                    warmup_threshold=warmup_threshold,
                    traffic_profile=(metadata or {}).get("traffic_profile", traffic_profile),
                    es_index_pattern=f"logs-{project_id}",
                    metadata=metadata or {},
                )
                self.projects[project_id] = project
                self.api_key_to_project[api_key_hash] = project_id
                logger.info("Registered backend project in detector: %s", project_id)
            else:
                project.project_name = project_name
                project.warmup_threshold = warmup_threshold
                project.traffic_profile = (metadata or {}).get("traffic_profile", traffic_profile)
                if metadata:
                    project.metadata.update(metadata)
                project.last_activity = datetime.now().isoformat()

            self._save_projects()
            return project
    
    def create_project(
        self,
        project_name: str,
        warmup_threshold: int = 10000,
        metadata: Optional[Dict] = None,
        traffic_profile: str = "standard",
    ) -> Tuple[str, str]:
        """
        Create a new project with a unique API key.
        
        Args:
            project_name: Human-readable name for the project
            warmup_threshold: Number of logs before student training (default 10k)
            metadata: Optional metadata dictionary
        
        Returns:
            Tuple of (project_id, api_key)
        """
        with self._lock:
            # Generate unique IDs
            project_id = str(uuid.uuid4())
            api_key, api_key_hash = self._generate_api_key()
            
            # Create project directory
            project_dir = self.storage_dir / project_id
            project_dir.mkdir(parents=True, exist_ok=True)
            
            # Create project config
            project = ProjectConfig(
                project_id=project_id,
                project_name=project_name,
                api_key=api_key,  # Store for initial return only
                api_key_hash=api_key_hash,
                warmup_threshold=warmup_threshold,
                traffic_profile=(metadata or {}).get("traffic_profile", traffic_profile),
                es_index_pattern=f"logs-{project_id}",
                metadata=metadata or {}
            )
            
            # Store project
            self.projects[project_id] = project
            self.api_key_to_project[api_key_hash] = project_id
            
            # Persist
            self._save_projects()
            
            logger.info(f"Created project: {project_name} (ID: {project_id[:8]}...)")
            logger.info(f"  Warmup threshold: {warmup_threshold:,} logs")
            logger.info(f"  ES index pattern: logs-{project_id}")
            
            return project_id, api_key
    
    def validate_api_key(self, api_key: str) -> Optional[str]:
        """
        Validate an API key and return the associated project ID.
        
        Args:
            api_key: The API key to validate
        
        Returns:
            project_id if valid, None otherwise
        """
        api_key_hash = self._hash_api_key(api_key)
        return self.api_key_to_project.get(api_key_hash)
    
    def get_project(self, project_id: str) -> Optional[ProjectConfig]:
        """Get project configuration by ID"""
        return self.projects.get(project_id)
    
    def get_project_by_api_key(self, api_key: str) -> Optional[ProjectConfig]:
        """Get project configuration by API key"""
        project_id = self.validate_api_key(api_key)
        if project_id:
            return self.projects.get(project_id)
        return None
    
    def increment_log_count(self, project_id: str, count: int = 1) -> ProjectConfig:
        """
        Increment the log count for a project.
        
        Args:
            project_id: The project ID
            count: Number of logs to add
        
        Returns:
            Updated project config
        """
        with self._lock:
            project = self.projects.get(project_id)
            if not project:
                raise ValueError(f"Project not found: {project_id}")
            
            project.current_log_count += count
            project.last_activity = datetime.now().isoformat()
            self._mark_dirty()   # hot path — deferred flush
            return project

    def record_ingest_stats(
        self,
        project_id: str,
        total_records: int,
        parse_failures: int = 0,
        baseline_eligible: int = 0,
        clean_baseline_count: Optional[int] = None,
        dirty_excluded_count: int = 0,
        probe_skipped_count: int = 0,
        distinct_template_count: int = 0,
        observed_hours: Optional[List[int]] = None,
        data_quality_incident_open: Optional[bool] = None,
        traffic_profile: Optional[str] = None,
    ) -> Optional[ProjectConfig]:
        """Record ingest quality metrics used for student promotion gates."""
        with self._lock:
            project = self.projects.get(project_id)
            if not project:
                return None

            clean_count = baseline_eligible if clean_baseline_count is None else clean_baseline_count
            total_records = max(total_records, 0)
            parse_failures = max(parse_failures, 0)
            project.total_received_count += total_records
            project.parse_failure_count += parse_failures
            retained_total = project.recent_total_received_count
            retained_failures = project.recent_parse_failure_count
            if self.parse_failure_window > 0:
                retained_total_budget = max(self.parse_failure_window - total_records, 0)
                if retained_total > retained_total_budget and retained_total > 0:
                    retention_ratio = retained_total_budget / retained_total
                    retained_failures = int(round(retained_failures * retention_ratio))
                    retained_total = retained_total_budget
            project.recent_total_received_count = retained_total + total_records
            project.recent_parse_failure_count = retained_failures + parse_failures
            project.baseline_eligible_count += max(clean_count, 0)
            project.clean_baseline_count += max(clean_count, 0)
            project.dirty_excluded_count += max(dirty_excluded_count, 0)
            project.probe_skipped_count += max(probe_skipped_count, 0)
            project.distinct_template_count = max(project.distinct_template_count, distinct_template_count)
            if observed_hours:
                merged_hours = set(project.observed_hours)
                merged_hours.update(int(hour) for hour in observed_hours if hour is not None)
                project.observed_hours = sorted(hour for hour in merged_hours if 0 <= hour <= 23)
            if data_quality_incident_open is not None:
                project.data_quality_incident_open = data_quality_incident_open
            if traffic_profile:
                project.traffic_profile = traffic_profile
            project.last_activity = datetime.now().isoformat()
            self._mark_dirty()   # hot path — deferred flush
            return project

    def update_calibration_threshold(self, project_id: str, threshold: float) -> Optional[ProjectConfig]:
        with self._lock:
            project = self.projects.get(project_id)
            if not project:
                return None
            project.calibration_threshold = threshold
            self._mark_dirty()   # deferred — threshold recalculated per-batch
            return project

    def update_threshold_metadata(
        self,
        project_id: str,
        *,
        threshold: float,
        threshold_source: str,
        calibration_sample_count: int,
        score_normalization_version: str,
        feature_schema_version: str,
    ) -> Optional[ProjectConfig]:
        with self._lock:
            project = self.projects.get(project_id)
            if not project:
                return None
            project.calibration_threshold = threshold
            project.threshold_source = threshold_source
            project.threshold_fitted_at = datetime.now().isoformat()
            project.calibration_sample_count = calibration_sample_count
            project.score_normalization_version = score_normalization_version
            project.feature_schema_version = feature_schema_version
            self._mark_dirty()   # deferred — updated per-training, not per-log
            return project

    def set_student_training_blockers(self, project_id: str, blockers: List[str]) -> Optional[ProjectConfig]:
        with self._lock:
            project = self.projects.get(project_id)
            if not project:
                return None
            project.student_training_blockers = blockers
            if blockers and project.phase == ProjectPhase.TRAINING.value:
                # Phase reversion is critical — save immediately so a crash
                # doesn't leave the project stuck in the TRAINING phase.
                project.phase = ProjectPhase.WARMUP.value
                self._save_projects()
            else:
                self._mark_dirty()   # blocker list update — deferred is fine
            return project
    
    def update_training_stats(
        self,
        project_id: str,
        sequences_collected: int,
        unique_templates: int
    ):
        """Update training statistics for a project"""
        with self._lock:
            project = self.projects.get(project_id)
            if project:
                project.training_sequences_collected = sequences_collected
                project.unique_templates_seen = unique_templates
                project.distinct_template_count = max(project.distinct_template_count, unique_templates)

    def update_reservoir_counts(
        self,
        project_id: str,
        *,
        clean_normal_reservoir_count: int,
        suspicious_reservoir_count: int,
        confirmed_malicious_reservoir_count: int,
    ) -> None:
        with self._lock:
            project = self.projects.get(project_id)
            if not project:
                return
            project.clean_normal_reservoir_count = clean_normal_reservoir_count
            project.suspicious_reservoir_count = suspicious_reservoir_count
            project.confirmed_malicious_reservoir_count = confirmed_malicious_reservoir_count
            self._mark_dirty()   # hot path — deferred flush
    
    def _trigger_student_training(self, project_id: str):
        """Mark project for student model training"""
        project = self.projects.get(project_id)
        if project and project.phase == ProjectPhase.WARMUP.value:
            project.phase = ProjectPhase.TRAINING.value
            logger.info(f"\nProject {project.project_name} reached warmup threshold!")
            logger.info(f"   Logs collected: {project.current_log_count:,}")
            logger.info(f"   Initiating student model training...\n")
            self._save_projects()
    
    def mark_student_trained(
        self,
        project_id: str,
        student_model_path: str,
        student_state_path: str
    ):
        """Mark a project's student model as trained and ready"""
        with self._lock:
            project = self.projects.get(project_id)
            if project:
                project.phase = ProjectPhase.ACTIVE.value
                project.student_model_path = student_model_path
                project.student_state_path = student_state_path
                project.student_trained_at = datetime.now().isoformat()
                self._save_projects()
                
                logger.info(f"\nStudent model trained for project: {project.project_name}")
                logger.info(f"   Model path: {student_model_path}")
                logger.info(f"   Now using project-specific model for inference.\n")
    
    def get_projects_for_teacher_update(self) -> List[ProjectConfig]:
        """
        Get list of active projects whose logs should be used
        to update the teacher model.
        
        Returns projects that:
        - Have active student models
        - Have accumulated significant new logs since last teacher update
        """
        with self._lock:
            eligible = []
            for project in self.projects.values():
                if project.phase == ProjectPhase.ACTIVE.value:
                    # Check if project has new logs since student was trained
                    if project.student_trained_at:
                        trained_count = project.warmup_threshold
                        new_logs = project.current_log_count - trained_count
                        # Require at least 10% new logs for teacher update
                        if new_logs >= trained_count * 0.1:
                            eligible.append(project)
            return eligible
    
    def should_update_teacher(self) -> bool:
        """Check if teacher model should be updated based on schedule"""
        if self.last_teacher_update is None:
            return True
        
        days_since_update = (datetime.now() - self.last_teacher_update).days
        return days_since_update >= self.teacher_update_interval_days
    
    def mark_teacher_updated(self):
        """Record that teacher model was updated"""
        with self._lock:
            self.last_teacher_update = datetime.now()
            freshness = self.last_teacher_update.isoformat()
            for project in self.projects.values():
                project.teacher_last_updated_at = freshness
                project.teacher_freshness = "fresh"
            self._save_state()
            self._save_projects()
    
    def list_projects(self) -> List[Dict]:
        """List all projects with their status"""
        with self._lock:
            return [
                {
                    'project_id': p.project_id,
                    'project_name': p.project_name,
                    'phase': p.phase,
                    'log_count': p.current_log_count,
                    'warmup_threshold': p.warmup_threshold,
                    'traffic_profile': p.traffic_profile,
                    'warmup_progress': min(100, (p.current_log_count / p.warmup_threshold) * 100),
                    'created_at': p.created_at,
                    'last_activity': p.last_activity,
                    'has_student_model': p.student_model_path is not None,
                    'baseline_eligible_count': p.baseline_eligible_count,
                    'clean_baseline_count': p.clean_baseline_count,
                    'dirty_excluded_count': p.dirty_excluded_count,
                    'probe_skipped_count': p.probe_skipped_count,
                    'parse_failure_rate': (
                        p.parse_failure_count / p.total_received_count
                        if p.total_received_count else 0.0
                    ),
                    'observed_hours': p.observed_hours,
                    'student_training_blockers': p.student_training_blockers,
                    'calibration_threshold': p.calibration_threshold,
                    'threshold_source': p.threshold_source,
                    'threshold_fitted_at': p.threshold_fitted_at,
                    'calibration_sample_count': p.calibration_sample_count,
                    'score_normalization_version': p.score_normalization_version,
                    'distinct_template_count': p.distinct_template_count,
                    'teacher_last_updated_at': p.teacher_last_updated_at,
                    'teacher_freshness': p.teacher_freshness,
                    'reservoir_counts': {
                        'clean_normal': p.clean_normal_reservoir_count,
                        'suspicious': p.suspicious_reservoir_count,
                        'confirmed_malicious': p.confirmed_malicious_reservoir_count,
                    },
                }
                for p in self.projects.values()
            ]
    
    def delete_project(self, project_id: str) -> bool:
        """Delete a project and its associated data"""
        with self._lock:
            project = self.projects.get(project_id)
            if not project:
                return False
            
            # Remove from lookup
            if project.api_key_hash in self.api_key_to_project:
                del self.api_key_to_project[project.api_key_hash]
            
            # Remove project directory
            project_dir = self.storage_dir / project_id
            if project_dir.exists():
                import shutil
                shutil.rmtree(project_dir)
            
            # Remove from projects dict
            del self.projects[project_id]
            
            self._save_projects()
            logger.info(f"Deleted project: {project.project_name} (ID: {project_id[:8]}...)")
            return True
    
    def suspend_project(self, project_id: str) -> bool:
        """Suspend a project (stop processing)"""
        with self._lock:
            project = self.projects.get(project_id)
            if project:
                project.phase = ProjectPhase.SUSPENDED.value
                self._save_projects()
                return True
            return False
    
    def resume_project(self, project_id: str) -> bool:
        """Resume a suspended project"""
        with self._lock:
            project = self.projects.get(project_id)
            if project and project.phase == ProjectPhase.SUSPENDED.value:
                # Resume to appropriate phase
                if project.student_model_path:
                    project.phase = ProjectPhase.ACTIVE.value
                elif project.current_log_count >= project.warmup_threshold:
                    project.phase = ProjectPhase.TRAINING.value
                else:
                    project.phase = ProjectPhase.WARMUP.value
                self._save_projects()
                return True
            return False
    
    def regenerate_api_key(self, project_id: str) -> Optional[str]:
        """Regenerate API key for a project (invalidates old key)"""
        with self._lock:
            project = self.projects.get(project_id)
            if not project:
                return None
            
            # Remove old key mapping
            if project.api_key_hash in self.api_key_to_project:
                del self.api_key_to_project[project.api_key_hash]
            
            # Generate new key
            new_api_key, new_api_key_hash = self._generate_api_key()
            project.api_key = new_api_key
            project.api_key_hash = new_api_key_hash
            
            # Update mapping
            self.api_key_to_project[new_api_key_hash] = project_id
            
            self._save_projects()
            return new_api_key
    
    def _save_projects(self):
        """Write all projects to disk immediately.

        Call directly for critical mutations (create, delete, phase transitions,
        API key operations).  Hot-path callers should call _mark_dirty() instead
        so the write is deferred to the background flush thread.

        Must be called while self._lock is held (or before the lock is released,
        if the caller holds it for the entire critical section).
        """
        try:
            data = {
                'projects': {pid: p.to_dict() for pid, p in self.projects.items()},
                'api_key_mapping': self.api_key_to_project,
                'saved_at': datetime.now().isoformat()
            }
            with open(self.projects_file, 'w') as f:
                json.dump(data, f, indent=2)
            self._dirty = False
        except Exception as e:
            logger.warning(f"Failed to save projects: {e}")

    def _mark_dirty(self) -> None:
        """Mark in-memory project state as needing a flush.

        Used by hot-path callers (per-batch stat updates) to avoid a synchronous
        JSON write on every incoming log batch.  The background flush thread
        (started by start_background_flush) drains this flag every _save_interval
        seconds.  If the flush thread is not running the flag is ignored; a
        synchronous save still happens on shutdown via stop_background_flush().
        """
        self._dirty = True

    # ------------------------------------------------------------------
    # Background flush thread (item 7 — debounced _save_projects)
    # ------------------------------------------------------------------

    def start_background_flush(self) -> None:
        """Start the background thread that periodically flushes dirty state."""
        self._flush_stop.clear()
        self._flush_thread = threading.Thread(
            target=self._background_flush_loop,
            name='pm-flush',
            daemon=True,
        )
        self._flush_thread.start()
        logger.info(f"ProjectManager: background flush started (interval={self._save_interval}s)")

    def stop_background_flush(self) -> None:
        """Stop the flush thread and do a final synchronous save if dirty."""
        self._flush_stop.set()
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=5.0)
        # Synchronous save on graceful shutdown so no data is lost.
        with self._lock:
            if self._dirty:
                logger.info("ProjectManager: flushing dirty state on shutdown")
                self._save_projects()

    def _background_flush_loop(self) -> None:
        """Run by the flush daemon thread.  Sleeps _save_interval seconds between
        checks and writes to disk only when the dirty flag is set."""
        while not self._flush_stop.wait(timeout=self._save_interval):
            with self._lock:
                if self._dirty:
                    self._save_projects()
    
    def _load_projects(self):
        """Load projects from disk"""
        if self.projects_file.exists():
            try:
                with open(self.projects_file, 'r') as f:
                    data = json.load(f)
                
                self.projects = {
                    pid: ProjectConfig.from_dict(pdata)
                    for pid, pdata in data.get('projects', {}).items()
                }
                self.api_key_to_project = data.get('api_key_mapping', {})
                
                logger.info(f"Loaded {len(self.projects)} projects from storage")
                
            except Exception as e:
                logger.warning(f"Failed to load projects: {e}")
                self.projects = {}
                self.api_key_to_project = {}
        
        # Load manager state
        self._load_state()
    
    def _save_state(self):
        """Save manager state"""
        try:
            state = {
                'last_teacher_update': self.last_teacher_update,
                'saved_at': datetime.now()
            }
            with open(self.manager_state_file, 'wb') as f:
                pickle.dump(state, f)
        except Exception as e:
            logger.warning(f"Failed to save manager state: {e}")
    
    def _load_state(self):
        """Load manager state"""
        if self.manager_state_file.exists():
            try:
                with open(self.manager_state_file, 'rb') as f:
                    state = pickle.load(f)
                self.last_teacher_update = state.get('last_teacher_update')
            except Exception as e:
                logger.warning(f"Failed to load manager state: {e}")
    
    def get_project_storage_path(self, project_id: str) -> Path:
        """Get the storage path for a specific project"""
        return self.storage_dir / project_id
