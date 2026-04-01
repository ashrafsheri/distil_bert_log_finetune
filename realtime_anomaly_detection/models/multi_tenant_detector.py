"""
Multi-Tenant Detector Module
Main orchestrator for the student-teacher architecture.
Handles API key routing, model lifecycle management, and coordinates
between teacher and project-specific student models.
"""

import os
import re
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from collections import deque
from datetime import datetime, timezone
import logging

import numpy as np

from .project_manager import ProjectManager, ProjectConfig, ProjectPhase
from .teacher_model import TeacherModel
from .student_model import StudentModel
from .ensemble_detector import ApacheLogNormalizer
from .runtime_metrics import runtime_metrics


logger = logging.getLogger(__name__)


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
        self.project_score_windows: Dict[str, deque] = {}
        self.incident_cache: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self.session_ttl_seconds = int(os.getenv("MULTI_TENANT_SESSION_TTL_SECONDS", "1800"))
        self.max_sessions_per_project = int(os.getenv("MULTI_TENANT_MAX_SESSIONS_PER_PROJECT", "50000"))
        self.max_unique_paths = int(os.getenv("MULTI_TENANT_MAX_UNIQUE_PATHS", "1000"))
        self.score_window_size = int(os.getenv("MULTI_TENANT_SCORE_WINDOW", "512"))
        self.min_observed_hours = int(os.getenv("MULTI_TENANT_MIN_OBSERVED_HOURS", "6"))
        self.max_parse_failure_rate = float(os.getenv("MULTI_TENANT_MAX_PARSE_FAILURE_RATE", "0.05"))
        self.model_version = os.getenv("MULTI_TENANT_MODEL_VERSION", "student-teacher-v1")
        
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
            'baseline_eligible_count': project.baseline_eligible_count,
            'parse_failure_rate': (
                project.parse_failure_count / project.total_received_count
                if project.total_received_count else 0.0
            ),
            'observed_hours': project.observed_hours,
            'student_training_blockers': project.student_training_blockers,
            'calibration_threshold': project.calibration_threshold,
            'created_at': project.created_at,
            'last_activity': project.last_activity
        }
    
    def list_projects(self) -> List[Dict]:
        """List all projects with status"""
        return self.project_manager.list_projects()

    def ensure_project(
        self,
        project_id: str,
        project_name: str,
        warmup_threshold: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        threshold = warmup_threshold or self.default_warmup_threshold
        project = self.project_manager.ensure_project(
            project_id=project_id,
            project_name=project_name,
            warmup_threshold=threshold,
            metadata=metadata or {},
        )
        self.project_sessions.setdefault(project_id, {})
        self.project_score_windows.setdefault(project_id, deque(maxlen=self.score_window_size))
        self.incident_cache.setdefault(project_id, {})
        return self.get_project_status(project_id) or {
            "project_id": project.project_id,
            "project_name": project.project_name,
            "phase": project.phase,
        }

    def record_project_ingest_stats(
        self,
        project_id: str,
        *,
        total_records: int,
        parse_failures: int,
        baseline_eligible: int,
        observed_hours: Optional[List[int]] = None,
        data_quality_incident_open: Optional[bool] = None,
    ) -> Optional[Dict[str, Any]]:
        project = self.project_manager.record_ingest_stats(
            project_id,
            total_records=total_records,
            parse_failures=parse_failures,
            baseline_eligible=baseline_eligible,
            observed_hours=observed_hours,
            data_quality_incident_open=data_quality_incident_open,
        )
        if not project:
            return None
        blockers = self._student_training_blockers(project)
        self.project_manager.set_student_training_blockers(project_id, blockers)
        return self.get_project_status(project_id)
    
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
            'raw_line': log_line.strip(),
            'event_time': datetime.now(timezone.utc).isoformat(),
        }
    
    def extract_features(self, log_data: Dict, session_stats: Dict) -> np.ndarray:
        """Extract features for Isolation Forest"""
        event_hour = 0
        event_time = log_data.get("event_time")
        if isinstance(event_time, str) and event_time:
            try:
                event_hour = datetime.fromisoformat(event_time.replace("Z", "+00:00")).hour
            except ValueError:
                event_hour = 0

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
            event_hour
        ]
        return np.array(features, dtype=np.float64).reshape(1, -1)
    
    def normalize_template(self, log_data: Dict) -> str:
        """Normalize log to template"""
        message = f"{log_data['method']} {log_data['path']} {log_data['protocol']} {log_data['status']}"
        return self.normalizer.normalize(message)

    def _student_training_blockers(self, project: ProjectConfig) -> List[str]:
        blockers: List[str] = []
        if project.baseline_eligible_count < project.warmup_threshold:
            blockers.append("insufficient_clean_baseline_volume")
        if len(project.observed_hours) < self.min_observed_hours:
            blockers.append("insufficient_time_coverage")
        parse_failure_rate = (
            project.parse_failure_count / project.total_received_count
            if project.total_received_count else 0.0
        )
        if parse_failure_rate > self.max_parse_failure_rate:
            blockers.append("parse_failure_rate_too_high")
        if project.data_quality_incident_open:
            blockers.append("active_data_quality_incident")
        return blockers

    def _maybe_promote_project(self, project_id: str) -> None:
        project = self.project_manager.get_project(project_id)
        if not project:
            return
        blockers = self._student_training_blockers(project)
        self.project_manager.set_student_training_blockers(project_id, blockers)
        if blockers:
            return
        if project.phase == ProjectPhase.WARMUP.value and project.current_log_count >= project.warmup_threshold:
            self.project_manager._trigger_student_training(project_id)

    def _update_project_calibration(
        self,
        project_id: str,
        ensemble_score: float,
        *,
        baseline_eligible: bool,
    ) -> float:
        window = self.project_score_windows.setdefault(
            project_id,
            deque(maxlen=self.score_window_size),
        )
        if baseline_eligible:
            window.append(float(ensemble_score))

        project = self.project_manager.get_project(project_id)
        if not project:
            return 0.5
        if len(window) < 50:
            return project.calibration_threshold

        threshold = float(np.percentile(list(window), 97.5))
        threshold = min(max(threshold, 0.45), 0.9)
        self.project_manager.update_calibration_threshold(project_id, threshold)
        return threshold

    def _build_incident(
        self,
        project_id: str,
        log_data: Dict[str, Any],
        normalized_template: str,
        *,
        is_anomaly: bool,
    ) -> Optional[Dict[str, Any]]:
        if not is_anomaly:
            return None

        event_time = log_data.get("event_time") or datetime.now(timezone.utc).isoformat()
        try:
            parsed_time = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
        except ValueError:
            parsed_time = datetime.now(timezone.utc)

        bucket_time = parsed_time.replace(
            minute=(parsed_time.minute // 15) * 15,
            second=0,
            microsecond=0,
        )
        entity = log_data.get("session_key_hash") or log_data.get("ip") or "unknown"
        incident_id = f"{project_id}:{normalized_template}:{entity}:{bucket_time.isoformat()}"
        incident = {
            "incident_id": incident_id,
            "incident_type": "anomaly",
            "incident_bucket_start": bucket_time.isoformat(),
            "normalized_template": normalized_template,
        }
        self.incident_cache.setdefault(project_id, {})[incident_id] = incident
        return incident
    
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

        calibrated_threshold = self._update_project_calibration(
            project_id,
            result.get('anomaly_score', 0.0),
            baseline_eligible=True,
        )
        result['raw_anomaly_score'] = result.get('anomaly_score', 0.0)
        result['is_anomaly'] = result.get('anomaly_score', 0.0) >= calibrated_threshold
        result['calibration'] = {'project_threshold': calibrated_threshold, 'baseline_eligible': True}
        incident = self._build_incident(project_id, log_data, normalized_template, is_anomaly=result['is_anomaly'])
        if incident:
            result.update(incident)

        self._maybe_promote_project(project_id)
        project = self.project_manager.get_project(project_id) or project

        # Add project info to result
        result['project_id'] = project_id
        result['project_name'] = project.project_name
        result['phase'] = project.phase
        result['log_count'] = project.current_log_count
        result['warmup_progress'] = min(100, (project.current_log_count / project.warmup_threshold) * 100)
        result['model_version'] = self.model_version
        result['feature_schema_version'] = 'access-log-v2'
        result['student_training_blockers'] = project.student_training_blockers

        return result

    def detect_structured(
        self,
        *,
        project_id: str,
        project_name: str,
        warmup_threshold: Optional[int],
        session_key: str,
        event_time: Optional[str],
        normalized_event: Optional[str],
        raw_log: str,
        parsed_fields: Dict[str, Any],
        flags: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict:
        """Detect anomalies for a backend-owned project using structured events."""
        self.ensure_project(
            project_id=project_id,
            project_name=project_name,
            warmup_threshold=warmup_threshold,
            metadata=metadata,
        )
        project = self.project_manager.get_project(project_id)
        if not project:
            return {'error': 'Project not found', 'is_anomaly': False, 'anomaly_score': 0.0}
        if project.phase == ProjectPhase.SUSPENDED.value:
            return {'error': 'Project is suspended', 'is_anomaly': False, 'anomaly_score': 0.0}

        method = parsed_fields.get('method', 'GET')
        path = parsed_fields.get('path', '/')
        protocol = parsed_fields.get('protocol', 'HTTP/1.1')
        status = int(parsed_fields.get('status_code', 0))
        log_data = {
            'ip': parsed_fields.get('ip_address', ''),
            'method': method,
            'path': path,
            'protocol': protocol,
            'status': status,
            'referer': parsed_fields.get('referer', '-'),
            'user_agent': parsed_fields.get('user_agent', '-'),
            'auth_user': parsed_fields.get('auth_user', ''),
            'raw_line': raw_log,
            'event_time': event_time or datetime.now(timezone.utc).isoformat(),
            'session_key_hash': parsed_fields.get('session_key_hash'),
        }

        baseline_eligible = not any(
            bool((flags or {}).get(flag_name))
            for flag_name in ('synthetic_attack', 'manual_malicious_override', 'rule_hit', 'parse_failed')
        )
        session, session_stats = self._get_or_create_session(project_id, session_key, log_data)
        normalized_template = normalized_event or self.normalize_template(log_data)
        features = self.extract_features(log_data, session_stats)
        self.project_manager.increment_log_count(project_id)

        if project.phase == ProjectPhase.ACTIVE.value and project_id in self.students:
            result = self._detect_with_student(project_id, log_data, normalized_template, session, session_stats, features)
        else:
            result = self._detect_with_teacher(project_id, log_data, normalized_template, session, session_stats, features)
            if project.phase == ProjectPhase.WARMUP.value and baseline_eligible:
                self._collect_training_data(project_id, normalized_template, session_key, features)
            if project.phase == ProjectPhase.TRAINING.value:
                self._maybe_trigger_student_training(project_id)

        calibrated_threshold = self._update_project_calibration(
            project_id,
            result.get('anomaly_score', 0.0),
            baseline_eligible=baseline_eligible,
        )
        result['raw_anomaly_score'] = result.get('anomaly_score', 0.0)
        result['is_anomaly'] = result.get('anomaly_score', 0.0) >= calibrated_threshold
        result['calibration'] = {
            'project_threshold': calibrated_threshold,
            'baseline_eligible': baseline_eligible,
        }
        incident = self._build_incident(project_id, log_data, normalized_template, is_anomaly=result['is_anomaly'])
        if incident:
            result.update(incident)

        self._maybe_promote_project(project_id)
        project = self.project_manager.get_project(project_id) or project
        runtime_metrics.increment('structured_detections_total')
        result['project_id'] = project_id
        result['project_name'] = project.project_name
        result['phase'] = project.phase
        result['log_count'] = project.current_log_count
        result['warmup_progress'] = min(100, (project.current_log_count / project.warmup_threshold) * 100)
        result['model_version'] = self.model_version
        result['feature_schema_version'] = 'access-log-v2'
        result['student_training_blockers'] = project.student_training_blockers
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
            now = time.time()
            expired_sessions = [
                existing_session_id
                for existing_session_id, existing_session in self.project_sessions[project_id].items()
                if now - existing_session.get('last_seen', now) > self.session_ttl_seconds
            ]
            for expired_session_id in expired_sessions:
                del self.project_sessions[project_id][expired_session_id]
                runtime_metrics.increment("session_cache_evictions_total")
            
            if session_id not in self.project_sessions[project_id]:
                self.project_sessions[project_id][session_id] = {
                    'templates': deque(maxlen=self.window_size),
                    'request_count': 0,
                    'error_count': 0,
                    'unique_paths': set(),
                    'last_seen': now,
                }

            if len(self.project_sessions[project_id]) > self.max_sessions_per_project:
                oldest_sessions = sorted(
                    self.project_sessions[project_id].items(),
                    key=lambda item: item[1].get('last_seen', 0.0),
                )[: len(self.project_sessions[project_id]) - self.max_sessions_per_project]
                for oldest_session_id, _ in oldest_sessions:
                    del self.project_sessions[project_id][oldest_session_id]
                    runtime_metrics.increment("session_cache_evictions_total")
            
            session = self.project_sessions[project_id][session_id]
            
            # Update session
            session['request_count'] += 1
            if log_data['status'] >= 400:
                session['error_count'] += 1
            session['unique_paths'].add(log_data['path'])
            if len(session['unique_paths']) > self.max_unique_paths:
                session['unique_paths'] = set(list(session['unique_paths'])[-self.max_unique_paths:])
            session['last_seen'] = now
            
            session_stats = {
                'request_count': session['request_count'],
                'error_count': session['error_count'],
                'error_rate': session['error_count'] / session['request_count'],
                'unique_paths': len(session['unique_paths'])
            }
            runtime_metrics.observe("session_cache_size", len(self.project_sessions[project_id]))
            
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
        result['model_version'] = self.model_version
        
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
        result['model_version'] = self.model_version
        
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
