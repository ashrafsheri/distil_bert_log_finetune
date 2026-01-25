"""
Multi-Tenant Detector Module
Main orchestrator for the student-teacher architecture.
Handles API key routing, model lifecycle management, and coordinates
between teacher and project-specific student models.
"""

import re
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import deque
from datetime import datetime

import numpy as np

from .project_manager import ProjectManager, ProjectConfig, ProjectPhase
from .teacher_model import TeacherModel
from .student_model import StudentModel
from .ensemble_detector import ApacheLogNormalizer


class MultiTenantDetector:
    """
    Multi-Tenant Anomaly Detector with Student-Teacher Architecture
    
    This is the main orchestrator that manages:
    - Project lifecycle (warmup -> training -> active)
    - API key validation and routing
    - Teacher model for baseline detection
    - Student models for project-specific detection
    - Periodic teacher model updates from student logs
    
    Workflow:
    1. New project created with unique API key
    2. During warmup: Teacher model handles detection, logs collected
    3. After warmup threshold: Student model trained via knowledge distillation
    4. Active phase: Student model handles project-specific detection
    5. Periodically: Teacher model updated with aggregated student logs
    """
    
    def __init__(
        self,
        base_model_dir: Path,
        storage_dir: Path,
        default_warmup_threshold: int = 10000,
        window_size: int = 20,
        device: str = 'cpu',
        teacher_update_interval_days: int = 7
    ):
        self.base_model_dir = Path(base_model_dir)
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.default_warmup_threshold = default_warmup_threshold
        self.window_size = window_size
        self.device = device
        
        # Normalizer
        self.normalizer = ApacheLogNormalizer()
        
        # Initialize project manager
        self.project_manager = ProjectManager(
            storage_dir=self.storage_dir / 'projects',
            teacher_update_interval_days=teacher_update_interval_days
        )
        
        # Initialize teacher model
        self.teacher = TeacherModel(
            model_dir=self.base_model_dir,
            storage_dir=self.storage_dir / 'teacher',
            window_size=window_size,
            device=device
        )
        
        # Student models cache (project_id -> StudentModel)
        self.students: Dict[str, StudentModel] = {}
        
        # Session windows per project (project_id -> {session_id -> deque})
        self.project_sessions: Dict[str, Dict[str, Dict]] = {}
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Background training queue
        self._training_queue: List[str] = []
        self._training_thread: Optional[threading.Thread] = None
        
        # Load existing student models
        self._load_existing_students()
        
        logger.info(f"\n{'='*70}")
        logger.info(f"MULTI-TENANT DETECTOR INITIALIZED")
        logger.info(f"{'='*70}")
        logger.info(f"  Base model directory: {self.base_model_dir}")
        logger.info(f"  Storage directory: {self.storage_dir}")
        logger.info(f"  Default warmup: {default_warmup_threshold:,} logs")
        logger.info(f"  Active projects: {len(self.project_manager.projects)}")
        logger.info(f"  Loaded student models: {len(self.students)}")
        logger.info(f"{'='*70}\n")
    
    def _load_existing_students(self):
        """Load existing student models for active projects"""
        for project_id, project in self.project_manager.projects.items():
            if project.phase == ProjectPhase.ACTIVE.value and project.student_model_path:
                try:
                    student_dir = self.project_manager.get_project_storage_path(project_id)
                    student = StudentModel(
                        project_id=project_id,
                        storage_dir=student_dir,
                        window_size=self.window_size,
                        device=self.device
                    )
                    if student.is_trained:
                        self.students[project_id] = student
                        logger.info(f"  Loaded student: {project.project_name[:20]}")
                except Exception as e:
                    logger.warning(f"  Failed to load student for {project_id[:8]}: {e}")
    
    # ========================================================================
    # PROJECT MANAGEMENT
    # ========================================================================
    
    def create_project(
        self,
        project_name: str,
        warmup_threshold: Optional[int] = None,
        metadata: Optional[Dict] = None
    ) -> Tuple[str, str]:
        """
        Create a new project with a unique API key.
        
        Args:
            project_name: Human-readable name
            warmup_threshold: Number of logs before student training (optional)
            metadata: Optional metadata
        
        Returns:
            Tuple of (project_id, api_key)
        """
        threshold = warmup_threshold or self.default_warmup_threshold
        project_id, api_key = self.project_manager.create_project(
            project_name=project_name,
            warmup_threshold=threshold,
            metadata=metadata
        )
        
        # Initialize project sessions
        self.project_sessions[project_id] = {}
        
        return project_id, api_key
    
    def validate_api_key(self, api_key: str) -> Optional[str]:
        """Validate API key and return project ID"""
        return self.project_manager.validate_api_key(api_key)
    
    def get_project_status(self, project_id: str) -> Optional[Dict]:
        """Get detailed status for a project"""
        project = self.project_manager.get_project(project_id)
        if not project:
            return None
        
        student = self.students.get(project_id)
        student_info = student.get_model_info() if student else None
        
        return {
            'project_id': project.project_id,
            'project_name': project.project_name,
            'phase': project.phase,
            'log_count': project.current_log_count,
            'warmup_threshold': project.warmup_threshold,
            'warmup_progress': min(100, (project.current_log_count / project.warmup_threshold) * 100),
            'has_student_model': student is not None and student.is_trained,
            'student_info': student_info,
            'created_at': project.created_at,
            'last_activity': project.last_activity
        }
    
    def list_projects(self) -> List[Dict]:
        """List all projects with status"""
        return self.project_manager.list_projects()
    
    def delete_project(self, project_id: str) -> bool:
        """Delete a project and its student model"""
        # Remove from cache
        if project_id in self.students:
            del self.students[project_id]
        if project_id in self.project_sessions:
            del self.project_sessions[project_id]
        
        return self.project_manager.delete_project(project_id)
    
    # ========================================================================
    # LOG PARSING
    # ========================================================================
    
    def parse_log(self, log_line: str) -> Optional[Dict]:
        """Parse nginx/apache log line"""
        # nginx/Apache Combined Log Format
        LOG_PATTERN = re.compile(
            r'^(?P<ip>\S+) '
            r'\S+ \S+ '
            r'\[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\S+) (?P<path>\S+)(?: (?P<protocol>\S+))?" '
            r'(?P<status>\d+) '
            r'(?P<size>\S+)'
            r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
        )
        
        match = LOG_PATTERN.match(log_line.strip())
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
        return np.array(features, dtype=np.float64).reshape(1, -1)
    
    def normalize_template(self, log_data: Dict) -> str:
        """Normalize log to template"""
        message = f"{log_data['method']} {log_data['path']} {log_data['protocol']} {log_data['status']}"
        return self.normalizer.normalize(message)
    
    # ========================================================================
    # DETECTION
    # ========================================================================
    
    def detect(
        self,
        api_key: str,
        log_line: str,
        session_id: Optional[str] = None
    ) -> Dict:
        """
        Perform anomaly detection for a specific project.
        
        This is the main entry point for detection. It:
        1. Validates the API key
        2. Routes to appropriate model (teacher or student)
        3. Collects training data during warmup
        4. Triggers student training when warmup complete
        
        Args:
            api_key: Project API key
            log_line: Raw log line to analyze
            session_id: Optional session identifier (defaults to IP)
        
        Returns:
            Detection result dictionary
        """
        # Validate API key
        project_id = self.validate_api_key(api_key)
        if not project_id:
            return {
                'error': 'Invalid API key',
                'is_anomaly': False,
                'anomaly_score': 0.0
            }
        
        # Get project
        project = self.project_manager.get_project(project_id)
        if not project:
            return {
                'error': 'Project not found',
                'is_anomaly': False,
                'anomaly_score': 0.0
            }
        
        # Check if suspended
        if project.phase == ProjectPhase.SUSPENDED.value:
            return {
                'error': 'Project is suspended',
                'is_anomaly': False,
                'anomaly_score': 0.0
            }
        
        # Parse log
        log_data = self.parse_log(log_line)
        if not log_data:
            return {
                'error': 'Failed to parse log',
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'project_id': project_id
            }
        
        # Use IP as session ID if not provided
        if session_id is None:
            session_id = log_data['ip']
        
        # Get or create session for this project
        session, session_stats = self._get_or_create_session(
            project_id, session_id, log_data
        )
        
        # Extract template and features
        normalized_template = self.normalize_template(log_data)
        features = self.extract_features(log_data, session_stats)
        
        # Increment log count
        self.project_manager.increment_log_count(project_id)
        
        # Route to appropriate model based on phase
        if project.phase == ProjectPhase.ACTIVE.value and project_id in self.students:
            # Use student model
            result = self._detect_with_student(
                project_id, log_data, normalized_template,
                session, session_stats, features
            )
        else:
            # Use teacher model (warmup or training phase)
            result = self._detect_with_teacher(
                project_id, log_data, normalized_template,
                session, session_stats, features
            )
            
            # Collect training data during warmup
            if project.phase == ProjectPhase.WARMUP.value:
                self._collect_training_data(
                    project_id, normalized_template, session_id, features
                )
            
            # Check if we should start student training
            if project.phase == ProjectPhase.TRAINING.value:
                self._maybe_trigger_student_training(project_id)
        
        # Add project info to result
        result['project_id'] = project_id
        result['project_name'] = project.project_name
        result['phase'] = project.phase
        result['log_count'] = project.current_log_count
        result['warmup_progress'] = min(100, (project.current_log_count / project.warmup_threshold) * 100)
        
        return result
    
    def _get_or_create_session(
        self,
        project_id: str,
        session_id: str,
        log_data: Dict
    ) -> Tuple[Dict, Dict]:
        """Get or create session tracking for a project/session"""
        with self._lock:
            if project_id not in self.project_sessions:
                self.project_sessions[project_id] = {}
            
            if session_id not in self.project_sessions[project_id]:
                self.project_sessions[project_id][session_id] = {
                    'templates': deque(maxlen=self.window_size),
                    'request_count': 0,
                    'error_count': 0,
                    'unique_paths': set()
                }
            
            session = self.project_sessions[project_id][session_id]
            
            # Update session
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
            
            return session, session_stats
    
    def _detect_with_teacher(
        self,
        project_id: str,
        log_data: Dict,
        normalized_template: str,
        session: Dict,
        session_stats: Dict,
        features: np.ndarray
    ) -> Dict:
        """Perform detection using teacher model"""
        # Get template ID from teacher vocabulary
        template_id = self.teacher.get_template_id(normalized_template)
        
        # Update session templates
        session['templates'].append(template_id)
        sequence = list(session['templates'])
        
        # Perform detection
        result = self.teacher.detect(log_data, sequence, session_stats, features)
        result['using_model'] = 'teacher'
        result['log_data'] = log_data
        
        return result
    
    def _detect_with_student(
        self,
        project_id: str,
        log_data: Dict,
        normalized_template: str,
        session: Dict,
        session_stats: Dict,
        features: np.ndarray
    ) -> Dict:
        """Perform detection using student model"""
        student = self.students[project_id]
        
        # Get template ID from student vocabulary
        template_id = student.get_template_id(normalized_template)
        
        # Update session templates
        session['templates'].append(template_id)
        sequence = list(session['templates'])
        
        # Perform detection
        result = student.detect(log_data, sequence, session_stats, features)
        result['using_model'] = 'student'
        result['log_data'] = log_data
        
        return result
    
    def _collect_training_data(
        self,
        project_id: str,
        normalized_template: str,
        session_id: str,
        features: np.ndarray
    ):
        """Collect training data for student model during warmup"""
        with self._lock:
            # Get or create student model for data collection
            if project_id not in self.students:
                project_dir = self.project_manager.get_project_storage_path(project_id)
                self.students[project_id] = StudentModel(
                    project_id=project_id,
                    storage_dir=project_dir,
                    window_size=self.window_size,
                    device=self.device
                )
            
            student = self.students[project_id]
            
            # Add template to vocabulary
            template_id = student.add_template(normalized_template)
            
            # Collect training data
            student.collect_training_data(template_id, session_id, features)
            
            # Update project stats
            project = self.project_manager.get_project(project_id)
            if project:
                self.project_manager.update_training_stats(
                    project_id,
                    len(student.training_sequences),
                    len(student.id_to_template)
                )
    
    def _maybe_trigger_student_training(self, project_id: str):
        """Check and trigger student training if needed"""
        with self._lock:
            if project_id in self._training_queue:
                return  # Already queued
            
            student = self.students.get(project_id)
            if not student or student.is_trained or student.is_training:
                return
            
            # Add to training queue
            self._training_queue.append(project_id)
            
            # Start training thread if not running
            if self._training_thread is None or not self._training_thread.is_alive():
                self._training_thread = threading.Thread(
                    target=self._process_training_queue,
                    daemon=True
                )
                self._training_thread.start()
    
    def _process_training_queue(self):
        """Process the training queue in background"""
        while True:
            with self._lock:
                if not self._training_queue:
                    return
                project_id = self._training_queue.pop(0)
            
            student = self.students.get(project_id)
            if student and not student.is_trained:
                logger.info(f"\nStarting training for project: {project_id[:8]}...")
                success = student.train_from_teacher(
                    teacher_model=self.teacher,
                    epochs=5,
                    learning_rate=1e-4,
                    distillation_alpha=0.5,
                    temperature=3.0
                )
                
                if success:
                    # Update project manager
                    self.project_manager.mark_student_trained(
                        project_id,
                        str(student.model_path),
                        str(student.state_path)
                    )
    
    # ========================================================================
    # TEACHER UPDATES
    # ========================================================================
    
    def update_teacher_from_students(self, force: bool = False) -> bool:
        """
        Update teacher model using aggregated logs from student models.
        
        This should be called periodically (e.g., weekly) to improve the
        teacher model based on collective learning from all projects.
        
        Args:
            force: Force update even if interval hasn't passed
        
        Returns:
            True if update was performed
        """
        if not force and not self.project_manager.should_update_teacher():
            return False
        
        # Collect data from all active student models
        all_sequences = []
        all_features = []
        
        projects = self.project_manager.get_projects_for_teacher_update()
        if not projects:
            logger.warning("No eligible projects for teacher update")
            return False
        
        logger.info(f"\nCollecting data from {len(projects)} projects for teacher update...")
        
        for project in projects:
            student = self.students.get(project.project_id)
            if student:
                sequences, features = student.get_training_data_for_teacher()
                all_sequences.extend(sequences)
                if features is not None:
                    all_features.append(features)
        
        if len(all_sequences) < 1000:
            logger.warning(f"Not enough data for teacher update: {len(all_sequences)} sequences")
            return False
        
        # Combine features
        combined_features = None
        if all_features:
            combined_features = np.vstack(all_features)
        
        # Update teacher
        self.teacher.update_from_student_logs(
            all_sequences=all_sequences,
            all_features=combined_features,
            epochs=2,
            learning_rate=1e-5
        )
        
        # Mark update complete
        self.project_manager.mark_teacher_updated()
        
        return True
    
    # ========================================================================
    # BATCH DETECTION
    # ========================================================================
    
    def detect_batch(
        self,
        api_key: str,
        log_lines: List[str],
        session_id: Optional[str] = None
    ) -> Dict:
        """
        Perform anomaly detection on a batch of logs.
        
        Args:
            api_key: Project API key
            log_lines: List of log lines
            session_id: Optional session identifier
        
        Returns:
            Batch detection results
        """
        results = []
        anomaly_count = 0
        
        for log_line in log_lines:
            result = self.detect(api_key, log_line, session_id)
            results.append(result)
            if result.get('is_anomaly', False):
                anomaly_count += 1
        
        return {
            'results': results,
            'total_logs': len(results),
            'anomalies_detected': anomaly_count
        }
    
    # ========================================================================
    # HEALTH & STATUS
    # ========================================================================
    
    def get_health(self) -> Dict:
        """Get system health status"""
        active_students = sum(
            1 for s in self.students.values() if s.is_trained
        )
        training_students = sum(
            1 for s in self.students.values() if s.is_training
        )
        
        return {
            'status': 'healthy',
            'teacher_loaded': self.teacher.is_loaded,
            'teacher_training': self.teacher.is_training,
            'total_projects': len(self.project_manager.projects),
            'active_student_models': active_students,
            'training_in_progress': training_students,
            'pending_training': len(self._training_queue),
            'teacher_info': self.teacher.get_model_info()
        }
    
    def reset_project_session(self, project_id: str, session_id: str):
        """Reset a specific session for a project"""
        with self._lock:
            if project_id in self.project_sessions:
                if session_id in self.project_sessions[project_id]:
                    del self.project_sessions[project_id][session_id]
    
    def reset_all_project_sessions(self, project_id: str):
        """Reset all sessions for a project"""
        with self._lock:
            if project_id in self.project_sessions:
                self.project_sessions[project_id] = {}
