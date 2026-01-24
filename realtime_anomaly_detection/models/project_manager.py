"""
Project Manager Module
Manages multi-tenant projects with API keys, warmup tracking, and project-specific configurations.
"""

import json
import uuid
import hashlib
import secrets
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import pickle


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
    current_log_count: int = 0
    phase: str = ProjectPhase.WARMUP.value
    
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
            'current_log_count': self.current_log_count,
            'phase': self.phase,
            'created_at': self.created_at,
            'last_activity': self.last_activity,
            'student_trained_at': self.student_trained_at,
            'student_model_path': self.student_model_path,
            'student_state_path': self.student_state_path,
            'training_sequences_collected': self.training_sequences_collected,
            'unique_templates_seen': self.unique_templates_seen,
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
            current_log_count=data.get('current_log_count', 0),
            phase=data.get('phase', ProjectPhase.WARMUP.value),
            created_at=data.get('created_at', datetime.now().isoformat()),
            last_activity=data.get('last_activity', datetime.now().isoformat()),
            student_trained_at=data.get('student_trained_at'),
            student_model_path=data.get('student_model_path'),
            student_state_path=data.get('student_state_path'),
            training_sequences_collected=data.get('training_sequences_collected', 0),
            unique_templates_seen=data.get('unique_templates_seen', 0),
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
        
        # Load existing projects
        self._load_projects()
        
        print(f"\n{'='*70}")
        print(f"PROJECT MANAGER INITIALIZED")
        print(f"{'='*70}")
        print(f"  Storage directory: {self.storage_dir}")
        print(f"  Active projects: {len(self.projects)}")
        print(f"  Teacher update interval: {teacher_update_interval_days} days")
        print(f"{'='*70}\n")
    
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
    
    def create_project(
        self,
        project_name: str,
        warmup_threshold: int = 10000,
        metadata: Optional[Dict] = None
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
            project_dir = self.storage_dir / 'projects' / project_id
            project_dir.mkdir(parents=True, exist_ok=True)
            
            # Create project config
            project = ProjectConfig(
                project_id=project_id,
                project_name=project_name,
                api_key=api_key,  # Store for initial return only
                api_key_hash=api_key_hash,
                warmup_threshold=warmup_threshold,
                es_index_pattern=f"logs-{project_id}",
                metadata=metadata or {}
            )
            
            # Store project
            self.projects[project_id] = project
            self.api_key_to_project[api_key_hash] = project_id
            
            # Persist
            self._save_projects()
            
            print(f"✓ Created project: {project_name} (ID: {project_id[:8]}...)")
            print(f"  Warmup threshold: {warmup_threshold:,} logs")
            print(f"  ES index pattern: logs-{project_id}")
            
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
            
            # Check if warmup threshold reached
            if (project.phase == ProjectPhase.WARMUP.value and 
                project.current_log_count >= project.warmup_threshold):
                self._trigger_student_training(project_id)
            
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
    
    def _trigger_student_training(self, project_id: str):
        """Mark project for student model training"""
        project = self.projects.get(project_id)
        if project and project.phase == ProjectPhase.WARMUP.value:
            project.phase = ProjectPhase.TRAINING.value
            print(f"\n🎓 Project {project.project_name} reached warmup threshold!")
            print(f"   Logs collected: {project.current_log_count:,}")
            print(f"   Initiating student model training...\n")
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
                
                print(f"\n✅ Student model trained for project: {project.project_name}")
                print(f"   Model path: {student_model_path}")
                print(f"   Now using project-specific model for inference.\n")
    
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
            self._save_state()
    
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
                    'warmup_progress': min(100, (p.current_log_count / p.warmup_threshold) * 100),
                    'created_at': p.created_at,
                    'last_activity': p.last_activity,
                    'has_student_model': p.student_model_path is not None
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
            project_dir = self.storage_dir / 'projects' / project_id
            if project_dir.exists():
                import shutil
                shutil.rmtree(project_dir)
            
            # Remove from projects dict
            del self.projects[project_id]
            
            self._save_projects()
            print(f"✓ Deleted project: {project.project_name} (ID: {project_id[:8]}...)")
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
        """Save all projects to disk"""
        try:
            data = {
                'projects': {pid: p.to_dict() for pid, p in self.projects.items()},
                'api_key_mapping': self.api_key_to_project,
                'saved_at': datetime.now().isoformat()
            }
            with open(self.projects_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"⚠️ Failed to save projects: {e}")
    
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
                
                print(f"✓ Loaded {len(self.projects)} projects from storage")
                
            except Exception as e:
                print(f"⚠️ Failed to load projects: {e}")
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
            print(f"⚠️ Failed to save manager state: {e}")
    
    def _load_state(self):
        """Load manager state"""
        if self.manager_state_file.exists():
            try:
                with open(self.manager_state_file, 'rb') as f:
                    state = pickle.load(f)
                self.last_teacher_update = state.get('last_teacher_update')
            except Exception as e:
                print(f"⚠️ Failed to load manager state: {e}")
    
    def get_project_storage_path(self, project_id: str) -> Path:
        """Get the storage path for a specific project"""
        return self.storage_dir / 'projects' / project_id
