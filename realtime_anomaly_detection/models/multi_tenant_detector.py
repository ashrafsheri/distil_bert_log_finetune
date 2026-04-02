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
UUID_SEGMENT_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
LONG_HEX_SEGMENT_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
MANIFEST_INVALID_MARKERS = ("${",)
TRANSPORT_NOISE_PREFIXES = ("/socket.io/",)
SIGNED_ASSET_PREFIXES = ("/storage/v1/object/sign/",)
VOLATILE_QUERY_KEYS = {
    "token",
    "expires",
    "signature",
    "sig",
    "x-amz-signature",
    "x-amz-credential",
    "x-amz-date",
    "x-amz-security-token",
    "sid",
    "t",
    "transport",
    "eio",
}


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
        self.project_score_buffers: Dict[str, Dict[str, deque]] = {}
        self.incident_cache: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self.session_ttl_seconds = int(os.getenv("MULTI_TENANT_SESSION_TTL_SECONDS", "1800"))
        self.max_sessions_per_project = int(os.getenv("MULTI_TENANT_MAX_SESSIONS_PER_PROJECT", "50000"))
        self.max_unique_paths = int(os.getenv("MULTI_TENANT_MAX_UNIQUE_PATHS", "1000"))
        self.score_window_size = int(os.getenv("MULTI_TENANT_SCORE_WINDOW", "512"))
        self.min_observed_hours = int(os.getenv("MULTI_TENANT_MIN_OBSERVED_HOURS", "6"))
        self.max_parse_failure_rate = float(os.getenv("MULTI_TENANT_MAX_PARSE_FAILURE_RATE", "0.05"))
        self.model_version = os.getenv("MULTI_TENANT_MODEL_VERSION", "student-teacher-v1")
        self.feature_schema_version = os.getenv("MULTI_TENANT_FEATURE_SCHEMA_VERSION", "access-log-v2")
        self.score_normalization_version = "hybrid-v1"
        self.max_daily_threshold_delta = float(os.getenv("MULTI_TENANT_MAX_DAILY_THRESHOLD_DELTA", "0.1"))
        self.profile_settings = {
            "standard": {
                "warmup_threshold": default_warmup_threshold,
                "min_training_sequences": 100,
                "min_if_feature_rows": 100,
                "min_observed_hours": self.min_observed_hours,
                "min_calibration_samples": int(os.getenv("MULTI_TENANT_STANDARD_MIN_CALIBRATION_SAMPLES", "50")),
                "min_distinct_templates": 10,
                "max_single_template_ratio": 0.85,
            },
            "low_traffic": {
                "warmup_threshold": int(os.getenv("MULTI_TENANT_LOW_TRAFFIC_WARMUP_THRESHOLD", "1000")),
                "min_training_sequences": 30,
                "min_if_feature_rows": 50,
                "min_observed_hours": int(os.getenv("MULTI_TENANT_LOW_TRAFFIC_MIN_OBSERVED_HOURS", "3")),
                "min_calibration_samples": int(os.getenv("MULTI_TENANT_LOW_TRAFFIC_MIN_CALIBRATION_SAMPLES", "20")),
                "min_distinct_templates": 5,
                "max_single_template_ratio": 0.9,
            },
        }
        
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
        traffic_profile = (metadata or {}).get("traffic_profile", "standard")
        threshold = warmup_threshold or self.profile_settings.get(traffic_profile, self.profile_settings["standard"])["warmup_threshold"]
        project_id, api_key = self.project_manager.create_project(
            project_name=project_name,
            warmup_threshold=threshold,
            metadata=metadata,
            traffic_profile=traffic_profile,
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
        
        standard_calibration_floor = self.profile_settings["standard"]["min_calibration_samples"] * 2
        low_sample_calibration = (
            project.threshold_source == "holdout_calibration"
            and project.traffic_profile == "low_traffic"
            and project.calibration_sample_count < standard_calibration_floor
        )

        return {
            'project_id': project.project_id,
            'project_name': project.project_name,
            'phase': project.phase,
            'log_count': project.current_log_count,
            'warmup_threshold': project.warmup_threshold,
            'warmup_progress': min(100, (project.current_log_count / project.warmup_threshold) * 100),
            'has_student_model': student is not None and student.is_trained,
            'student_info': student_info,
            'traffic_profile': project.traffic_profile,
            'baseline_eligible_count': project.baseline_eligible_count,
            'clean_baseline_count': project.clean_baseline_count,
            'dirty_excluded_count': project.dirty_excluded_count,
            'probe_skipped_count': project.probe_skipped_count,
            'parse_failure_rate': (
                project.parse_failure_count / project.total_received_count
                if project.total_received_count else 0.0
            ),
            'observed_hours': project.observed_hours,
            'student_training_blockers': project.student_training_blockers,
            'distinct_template_count': project.distinct_template_count,
            'calibration_threshold': project.calibration_threshold,
            'threshold_source': project.threshold_source,
            'threshold_fitted_at': project.threshold_fitted_at,
            'calibration_sample_count': project.calibration_sample_count,
            'low_sample_calibration': low_sample_calibration,
            'score_normalization_version': project.score_normalization_version,
            'teacher_last_updated_at': project.teacher_last_updated_at,
            'teacher_freshness': project.teacher_freshness,
            'reservoir_counts': {
                'clean_normal': project.clean_normal_reservoir_count,
                'suspicious': project.suspicious_reservoir_count,
                'confirmed_malicious': project.confirmed_malicious_reservoir_count,
            },
            'created_at': project.created_at,
            'last_activity': project.last_activity
        }
    
    def list_projects(self) -> List[Dict]:
        """List all projects with status"""
        projects = self.project_manager.list_projects()
        standard_calibration_floor = self.profile_settings["standard"]["min_calibration_samples"] * 2
        for project in projects:
            project["low_sample_calibration"] = (
                project.get("threshold_source") == "holdout_calibration"
                and project.get("traffic_profile") == "low_traffic"
                and int(project.get("calibration_sample_count") or 0) < standard_calibration_floor
            )
        return projects

    def ensure_project(
        self,
        project_id: str,
        project_name: str,
        warmup_threshold: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        traffic_profile = (metadata or {}).get("traffic_profile", "standard")
        profile_settings = self.profile_settings.get(traffic_profile, self.profile_settings["standard"])
        threshold = warmup_threshold or profile_settings["warmup_threshold"]
        project = self.project_manager.ensure_project(
            project_id=project_id,
            project_name=project_name,
            warmup_threshold=threshold,
            metadata=metadata or {},
            traffic_profile=traffic_profile,
        )
        self.project_sessions.setdefault(project_id, {})
        self.project_score_windows.setdefault(project_id, deque(maxlen=self.score_window_size))
        self._project_score_buffers_for(project_id)
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
        clean_baseline_count: Optional[int] = None,
        dirty_excluded_count: int = 0,
        probe_skipped_count: int = 0,
        distinct_template_count: int = 0,
        observed_hours: Optional[List[int]] = None,
        data_quality_incident_open: Optional[bool] = None,
        traffic_profile: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        project = self.project_manager.record_ingest_stats(
            project_id,
            total_records=total_records,
            parse_failures=parse_failures,
            baseline_eligible=baseline_eligible,
            clean_baseline_count=clean_baseline_count,
            dirty_excluded_count=dirty_excluded_count,
            probe_skipped_count=probe_skipped_count,
            distinct_template_count=distinct_template_count,
            observed_hours=observed_hours,
            data_quality_incident_open=data_quality_incident_open,
            traffic_profile=traffic_profile,
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
        event_weekday = 0
        event_time = log_data.get("event_time")
        if isinstance(event_time, str) and event_time:
            try:
                parsed_time = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                event_hour = parsed_time.hour
                event_weekday = parsed_time.weekday()
            except ValueError:
                event_hour = 0
                event_weekday = 0

        path = log_data.get('path', '/')
        method = log_data.get('method', 'GET')
        status = log_data.get('status', 200)
        user_agent = log_data.get('user_agent', '-') or '-'
        referer = log_data.get('referer', '-') or '-'

        if self.feature_schema_version == "access-log-v3":
            suspicious_token_count = sum(
                token in path.lower()
                for token in ("..", "%2e", "%2f", "cmd", "union", "select", "<script", "wget", "curl")
            )
            features = [
                session_stats.get('request_count', 1),
                session_stats.get('error_rate', 0.0),
                session_stats.get('unique_paths', 1),
                session_stats.get('error_count', 0),
                1 if method == 'GET' else 0,
                1 if method == 'POST' else 0,
                1 if status >= 400 else 0,
                len(path),
                path.count('/'),
                1 if '?' in path else 0,
                event_hour,
                event_weekday,
                suspicious_token_count,
                1 if status in {401, 403} else 0,
                len(user_agent.split("/")[0]) if user_agent != '-' else 0,
                0 if referer == '-' else 1,
            ]
        else:
            features = [
                session_stats.get('request_count', 1),
                session_stats.get('error_rate', 0.0),
                session_stats.get('unique_paths', 1),
                session_stats.get('error_count', 0),
                1 if method == 'GET' else 0,
                1 if method == 'POST' else 0,
                1 if status >= 400 else 0,
                len(path),
                path.count('/'),
                1 if '?' in path else 0,
                event_hour
            ]
        return np.array(features, dtype=np.float64).reshape(1, -1)
    
    def normalize_template(self, log_data: Dict) -> str:
        """Normalize log to template"""
        canonical_path = self._canonicalize_path(log_data.get("path", "/"))
        message = f"{log_data['method']} {canonical_path} {log_data['protocol']} {log_data['status']}"
        return self.normalizer.normalize(message)

    @staticmethod
    def _path_without_query(path: str) -> str:
        return (path or "/").split("?", 1)[0] or "/"

    @staticmethod
    def _strip_query_value(query: str) -> str:
        if not query:
            return ""
        kept_parts: List[str] = []
        for raw_part in query.split("&"):
            key, sep, value = raw_part.partition("=")
            key_name = key.strip().lower()
            if not key_name:
                continue
            if key_name in VOLATILE_QUERY_KEYS:
                kept_parts.append(f"{key}=<FILTERED>" if sep else f"{key}=<FILTERED>")
                continue
            if len(value) > 64:
                kept_parts.append(f"{key}=<LONG>")
                continue
            kept_parts.append(raw_part)
        return "&".join(kept_parts)

    @staticmethod
    def _canonicalize_path(path: str) -> str:
        raw_path = (path or "/").strip() or "/"
        base_path, sep, query = raw_path.partition("?")
        normalized_segments: List[str] = []
        for segment in base_path.split("/"):
            if not segment:
                normalized_segments.append("")
                continue
            lowered = segment.lower()
            if UUID_SEGMENT_RE.match(segment):
                normalized_segments.append("<UUID>")
            elif LONG_HEX_SEGMENT_RE.match(segment):
                normalized_segments.append("<HEX>")
            elif len(segment) > 96:
                normalized_segments.append("<LONG>")
            else:
                normalized_segments.append(lowered if lowered in {"socket.io"} else segment)
        normalized_path = "/".join(normalized_segments) or "/"
        normalized_path = normalized_path if normalized_path.startswith("/") else f"/{normalized_path}"
        cleaned_query = MultiTenantDetector._strip_query_value(query) if sep else ""
        return f"{normalized_path}?{cleaned_query}" if cleaned_query else normalized_path

    @staticmethod
    def _classify_path_policy(path: str) -> Optional[Dict[str, Any]]:
        normalized_path = (path or "/").strip().lower()
        if normalized_path.startswith(TRANSPORT_NOISE_PREFIXES):
            return {
                "traffic_class": "transport_noise",
                "baseline_eligible": False,
                "decision_reason": "transport_noise_skipped",
            }
        if normalized_path.startswith(SIGNED_ASSET_PREFIXES):
            return {
                "traffic_class": "signed_asset_access",
                "baseline_eligible": False,
                "decision_reason": "signed_asset_skipped",
            }
        return None

    @staticmethod
    def _path_template_to_regex(path_template: str) -> re.Pattern[str]:
        normalized = path_template if path_template.startswith("/") else f"/{path_template}"
        if normalized == "/":
            return re.compile(r"^/$")

        pattern_parts: List[str] = []
        for segment in normalized.strip("/").split("/"):
            if segment in {"*", "**"}:
                pattern_parts.append(".*")
                break
            if (
                segment.startswith(":")
                or (segment.startswith("{") and segment.endswith("}"))
                or (segment.startswith("<") and segment.endswith(">"))
            ):
                pattern_parts.append(r"[^/]+")
            else:
                pattern_parts.append(re.escape(segment))
        return re.compile(r"^/" + "/".join(pattern_parts) + r"$")

    def _endpoint_manifest_entries(self, project: ProjectConfig) -> List[Dict[str, Any]]:
        manifest = (project.metadata or {}).get("endpoint_manifest") or {}
        if not isinstance(manifest, dict):
            return []
        endpoints = manifest.get("endpoints", [])
        if not isinstance(endpoints, list):
            return []
        filtered_entries: List[Dict[str, Any]] = []
        for entry in endpoints:
            if not isinstance(entry, dict):
                continue
            path_template = str(entry.get("path_template") or "").strip()
            if not path_template or any(marker in path_template for marker in MANIFEST_INVALID_MARKERS):
                continue
            filtered_entries.append(entry)
        return filtered_entries

    def _match_endpoint_manifest(
        self,
        project: ProjectConfig,
        method: str,
        path: str,
    ) -> Optional[Dict[str, Any]]:
        request_method = (method or "GET").upper()
        request_path = self._path_without_query(path)
        for entry in self._endpoint_manifest_entries(project):
            entry_method = str(entry.get("method", "ANY")).upper()
            if entry_method not in {"ANY", "*", request_method}:
                continue
            template = str(entry.get("path_template"))
            if self._path_template_to_regex(template).match(request_path):
                classification = entry.get("classification") or (
                    "internal_probe" if entry.get("baseline_eligible") is False else "user_traffic"
                )
                return {
                    "path_template": template if template.startswith("/") else f"/{template}",
                    "classification": classification,
                    "baseline_eligible": bool(entry.get("baseline_eligible", classification == "user_traffic")),
                    "entry": entry,
                }
        return None

    def _normalize_template_with_manifest(
        self,
        log_data: Dict[str, Any],
        manifest_match: Optional[Dict[str, Any]],
    ) -> str:
        if not manifest_match:
            return self.normalize_template(log_data)
        message = (
            f"{log_data.get('method', 'GET')} "
            f"{self._canonicalize_path(manifest_match['path_template'])} "
            f"{log_data.get('protocol', 'HTTP/1.1')} "
            f"{log_data.get('status', 0)}"
        )
        return self.normalizer.normalize(message)

    def _profile_settings_for_project(self, project: ProjectConfig) -> Dict[str, Any]:
        profile = project.traffic_profile if project.traffic_profile in self.profile_settings else "standard"
        settings = dict(self.profile_settings[profile])
        settings["profile"] = profile
        return settings

    def _split_name_for_position(self, position: int, warmup_threshold: int) -> str:
        if warmup_threshold <= 0:
            return "train"
        train_end = max(1, int(warmup_threshold * 0.70))
        calibration_end = max(train_end + 1, int(warmup_threshold * 0.85))
        if position <= train_end:
            return "train"
        if position <= calibration_end:
            return "calibration"
        return "holdout"

    def _normalize_component_score(self, component_name: str, component: Dict[str, Any]) -> Optional[float]:
        if component.get("status") != "active":
            return None
        if component_name == "transformer":
            threshold = float(component.get("threshold") or 1.0)
            score = float(component.get("score") or 0.0)
            return float(min(max(score / max(threshold, 1e-6), 0.0), 2.0) / 2.0)
        if component_name == "isolation_forest":
            threshold = float(component.get("threshold") or 1.0)
            score = float(component.get("score") or 0.0)
            if threshold <= 0:
                return float(component.get("is_anomaly", 0))
            return float(min(max(score / threshold, 0.0), 2.0) / 2.0)
        return None

    def _project_score_buffers_for(self, project_id: str) -> Dict[str, deque]:
        return self.project_score_buffers.setdefault(
            project_id,
            {
                "train": deque(maxlen=self.score_window_size),
                "calibration": deque(maxlen=self.score_window_size),
                "holdout": deque(maxlen=self.score_window_size),
            },
        )

    def _compose_final_decision(
        self,
        *,
        project: ProjectConfig,
        traffic_class: str,
        baseline_eligible: bool,
        raw_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        rule_result = raw_result.get("rule_based", {}) or {}
        iso_result = raw_result.get("isolation_forest", {}) or {}
        transformer_result = raw_result.get("transformer", {}) or {}
        component_status = {
            "rule_based": "active",
            "isolation_forest": iso_result.get("status", "not_available"),
            "transformer": transformer_result.get("status", "not_available"),
        }

        policy_score = 0.0
        if rule_result.get("is_attack"):
            policy_score = max(float(rule_result.get("confidence", 1.0)), 0.95)

        normalized_scores = {
            "transformer": self._normalize_component_score("transformer", transformer_result),
            "isolation_forest": self._normalize_component_score("isolation_forest", iso_result),
        }
        active_scores = [score for score in normalized_scores.values() if score is not None]
        anomaly_score = float(sum(active_scores) / len(active_scores)) if active_scores else 0.0

        final_decision = "not_flagged"
        decision_reason = "behavioral_normal"
        is_anomaly = False

        if traffic_class in {"internal_probe", "data_quality_late_event", "transport_noise", "signed_asset_access"}:
            final_decision = "skipped"
            if traffic_class == "internal_probe":
                decision_reason = "internal_probe_skipped"
            elif traffic_class == "data_quality_late_event":
                decision_reason = "late_event_skipped"
            elif traffic_class == "transport_noise":
                decision_reason = "transport_noise_skipped"
            else:
                decision_reason = "signed_asset_skipped"
        elif policy_score > 0:
            final_decision = "threat_detected"
            decision_reason = "known_attack_policy"
            anomaly_score = max(anomaly_score, policy_score)
            is_anomaly = True
        else:
            threshold = project.calibration_threshold
            if anomaly_score >= threshold:
                final_decision = "threat_detected"
                decision_reason = "behavioral_anomaly"
                is_anomaly = True
            elif not active_scores:
                decision_reason = "insufficient_signal"

        return {
            "policy_score": float(policy_score),
            "anomaly_score": float(anomaly_score),
            "final_decision": final_decision,
            "decision_reason": decision_reason,
            "component_status": component_status,
            "is_anomaly": is_anomaly,
            "raw_anomaly_score": float(raw_result.get("anomaly_score", anomaly_score)),
            "unknown_template_ratio": float(raw_result.get("unknown_template_ratio", 0.0)),
            "threshold_source": project.threshold_source,
            "threshold_fitted_at": project.threshold_fitted_at,
            "calibration_sample_count": project.calibration_sample_count,
            "score_normalization_version": project.score_normalization_version,
            "traffic_class": traffic_class,
            "baseline_eligible": baseline_eligible,
        }

    def _student_training_blockers(self, project: ProjectConfig) -> List[str]:
        blockers: List[str] = []
        profile_settings = self._profile_settings_for_project(project)
        if project.clean_baseline_count < project.warmup_threshold:
            blockers.append("insufficient_clean_baseline_volume")
        if len(project.observed_hours) < profile_settings["min_observed_hours"]:
            blockers.append("insufficient_time_coverage")
        if project.distinct_template_count < profile_settings["min_distinct_templates"]:
            blockers.append("insufficient_distinct_templates")
        parse_failure_rate = (
            project.parse_failure_count / project.total_received_count
            if project.total_received_count else 0.0
        )
        if parse_failure_rate > self.max_parse_failure_rate:
            blockers.append("parse_failure_rate_too_high")
        if project.data_quality_incident_open:
            blockers.append("active_data_quality_incident")
        total_non_probe = project.clean_baseline_count + project.dirty_excluded_count
        if project.probe_skipped_count > total_non_probe and project.probe_skipped_count > 0:
            blockers.append("probe_traffic_dominant")
        student = self.students.get(project.project_id)
        training_sequence_count = len(student.training_sequences) if student else 0
        training_feature_count = len(student.training_features) if student else 0
        if training_sequence_count < profile_settings["min_training_sequences"]:
            blockers.append("insufficient_training_sequences")
        if training_feature_count < profile_settings["min_if_feature_rows"]:
            blockers.append("insufficient_if_features")
        if student and student.template_counts:
            total_templates = sum(student.template_counts.values())
            if total_templates > 0:
                dominant_ratio = max(student.template_counts.values()) / total_templates
                if dominant_ratio > profile_settings["max_single_template_ratio"]:
                    blockers.append("dominant_single_endpoint")
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
        split_name: str,
    ) -> float:
        window = self.project_score_windows.setdefault(project_id, deque(maxlen=self.score_window_size))
        score_buffers = self._project_score_buffers_for(project_id)
        if baseline_eligible:
            window.append(float(ensemble_score))
            score_buffers[split_name].append(float(ensemble_score))

        project = self.project_manager.get_project(project_id)
        if not project:
            return 0.5
        profile_settings = self._profile_settings_for_project(project)
        min_calibration_samples = profile_settings["min_calibration_samples"]
        calibration_scores = list(score_buffers["calibration"])
        holdout_scores = list(score_buffers["holdout"])
        if len(calibration_scores) < min_calibration_samples or len(holdout_scores) < min_calibration_samples:
            return project.calibration_threshold

        calibration_threshold = float(np.percentile(calibration_scores, 95))
        holdout_threshold = float(np.percentile(holdout_scores, 97.5))
        threshold = max(calibration_threshold, holdout_threshold)
        threshold = min(max(threshold, 0.45), 0.9)
        current_threshold = project.calibration_threshold
        threshold = min(
            max(threshold, current_threshold - self.max_daily_threshold_delta),
            current_threshold + self.max_daily_threshold_delta,
        )
        self.project_manager.update_threshold_metadata(
            project_id,
            threshold=threshold,
            threshold_source="holdout_calibration",
            calibration_sample_count=len(calibration_scores) + len(holdout_scores),
            score_normalization_version=self.score_normalization_version,
            feature_schema_version=self.feature_schema_version,
        )
        return threshold

    def _build_incident(
        self,
        project_id: str,
        log_data: Dict[str, Any],
        normalized_template: str,
        *,
        is_anomaly: bool,
        decision_reason: Optional[str] = None,
        raw_result: Optional[Dict[str, Any]] = None,
        component_status: Optional[Dict[str, Any]] = None,
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
        rule_result = (raw_result or {}).get("rule_based", {}) or {}
        transformer_result = (raw_result or {}).get("transformer", {}) or {}
        iso_result = (raw_result or {}).get("isolation_forest", {}) or {}
        top_contributing_signals: List[str] = []

        for attack_type in rule_result.get("attack_types", []) or []:
            top_contributing_signals.append(f"rule:{attack_type}")
        if transformer_result.get("status") == "active" and transformer_result.get("is_anomaly"):
            top_contributing_signals.append("transformer:sequence_novelty")
        if iso_result.get("status") == "active" and iso_result.get("is_anomaly"):
            top_contributing_signals.append("iforest:feature_outlier")
        if float((raw_result or {}).get("unknown_template_ratio", 0.0) or 0.0) >= 0.25:
            top_contributing_signals.append("template:unknown_ratio")
        if not top_contributing_signals and component_status:
            for component_name, status in component_status.items():
                if status == "active":
                    top_contributing_signals.append(f"{component_name}:active")

        top_contributing_signals = list(dict.fromkeys(top_contributing_signals))[:5]
        incident_type = "known_exploit" if decision_reason == "known_attack_policy" else "behavioral_anomaly"
        existing_incident = self.incident_cache.setdefault(project_id, {}).get(incident_id)
        if existing_incident is None:
            incident = {
                "incident_id": incident_id,
                "incident_type": incident_type,
                "incident_bucket_start": bucket_time.isoformat(),
                "incident_reason": decision_reason or "behavioral_anomaly",
                "normalized_template": normalized_template,
                "incident_grouped_event_count": 1,
                "incident_first_seen_at": parsed_time.isoformat(),
                "incident_last_seen_at": parsed_time.isoformat(),
                "top_contributing_signals": top_contributing_signals,
            }
        else:
            merged_signals = list(
                dict.fromkeys(
                    [*existing_incident.get("top_contributing_signals", []), *top_contributing_signals]
                )
            )[:5]
            incident = {
                **existing_incident,
                "incident_type": existing_incident.get("incident_type") or incident_type,
                "incident_reason": existing_incident.get("incident_reason") or decision_reason or "behavioral_anomaly",
                "incident_grouped_event_count": int(existing_incident.get("incident_grouped_event_count", 0)) + 1,
                "incident_last_seen_at": parsed_time.isoformat(),
                "top_contributing_signals": merged_signals,
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
        
        manifest_match = self._match_endpoint_manifest(project, log_data.get('method', 'GET'), log_data.get('path', '/'))
        path_policy = self._classify_path_policy(log_data.get("path", "/"))
        traffic_class = path_policy["traffic_class"] if path_policy else "user_traffic"
        baseline_eligible = bool(path_policy["baseline_eligible"]) if path_policy else True
        if not path_policy and manifest_match and manifest_match.get("classification") == "internal_probe":
            traffic_class = "internal_probe"
            baseline_eligible = False
        elif not path_policy and manifest_match and manifest_match.get("baseline_eligible") is False:
            baseline_eligible = False

        # Extract template and features
        normalized_template = self._normalize_template_with_manifest(log_data, manifest_match)
        features = self.extract_features(log_data, session_stats)
        
        # Increment log count
        self.project_manager.increment_log_count(project_id)
        
        split_name = self._split_name_for_position(project.clean_baseline_count + 1, project.warmup_threshold)

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
            if project.phase == ProjectPhase.WARMUP.value and baseline_eligible and split_name == "train":
                self._collect_training_data(
                    project_id, normalized_template, session_id, features
                )
            
            # Check if we should start student training
            if project.phase == ProjectPhase.TRAINING.value:
                self._maybe_trigger_student_training(project_id)
        decision = self._compose_final_decision(
            project=project,
            traffic_class=traffic_class,
            baseline_eligible=baseline_eligible,
            raw_result=result,
        )
        calibrated_threshold = self._update_project_calibration(
            project_id,
            decision.get('anomaly_score', 0.0),
            baseline_eligible=baseline_eligible,
            split_name=split_name,
        )
        decision['raw_anomaly_score'] = decision.get('anomaly_score', 0.0)
        decision['anomaly_score'] = max(decision.get('anomaly_score', 0.0), decision.get('policy_score', 0.0))
        if decision['final_decision'] not in {'threat_detected', 'skipped'}:
            decision['is_anomaly'] = decision['anomaly_score'] >= calibrated_threshold
            decision['final_decision'] = "threat_detected" if decision['is_anomaly'] else "not_flagged"
            if decision['is_anomaly']:
                decision['decision_reason'] = "behavioral_anomaly"
        result.update(decision)
        result['calibration'] = {'project_threshold': calibrated_threshold, 'baseline_eligible': baseline_eligible}
        incident = self._build_incident(
            project_id,
            log_data,
            normalized_template,
            is_anomaly=result['is_anomaly'],
            decision_reason=result.get('decision_reason'),
            raw_result=result,
            component_status=result.get('component_status'),
        )
        if incident:
            result.update(incident)

        student = self.students.get(project_id)
        if student is not None:
            student.record_reservoir_observation(
                sequence=list(session['templates']),
                is_anomaly=result['is_anomaly'],
                is_known_attack=bool(result.get('rule_based', {}).get('is_attack')),
            )
            self.project_manager.update_reservoir_counts(
                project_id,
                clean_normal_reservoir_count=len(student.clean_normal_reservoir),
                suspicious_reservoir_count=len(student.suspicious_reservoir),
                confirmed_malicious_reservoir_count=len(student.confirmed_malicious_reservoir),
            )

        self._maybe_promote_project(project_id)
        project = self.project_manager.get_project(project_id) or project

        # Add project info to result
        result['project_id'] = project_id
        result['project_name'] = project.project_name
        result['phase'] = project.phase
        result['log_count'] = project.current_log_count
        result['warmup_progress'] = min(100, (project.current_log_count / project.warmup_threshold) * 100)
        result['model_version'] = self.model_version
        result['feature_schema_version'] = self.feature_schema_version
        result['student_training_blockers'] = project.student_training_blockers
        result['traffic_class'] = traffic_class
        result['baseline_eligible'] = baseline_eligible
        result['threshold_source'] = project.threshold_source
        result['threshold_fitted_at'] = project.threshold_fitted_at
        result['calibration_sample_count'] = project.calibration_sample_count
        result['score_normalization_version'] = project.score_normalization_version
        result['endpoint_manifest_match'] = bool(manifest_match)
        result['endpoint_manifest_class'] = manifest_match.get("classification") if manifest_match else None

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
        traffic_class: Optional[str] = None,
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

        flags = flags or {}
        manifest_match = self._match_endpoint_manifest(project, method, path)
        path_policy = self._classify_path_policy(path)
        if not traffic_class:
            traffic_class = path_policy["traffic_class"] if path_policy else "user_traffic"
        if traffic_class == "user_traffic" and not path_policy and manifest_match and manifest_match.get("classification") == "internal_probe":
            traffic_class = "internal_probe"
        baseline_eligible = bool(
            traffic_class == "user_traffic"
            and not any(
                bool(flags.get(flag_name))
                for flag_name in (
                    'synthetic_attack',
                    'manual_malicious_override',
                    'rule_hit',
                    'parse_failed',
                    'internal_probe',
                    'late_or_invalid_event',
                    'duplicate_in_batch',
                )
            )
        )
        if path_policy:
            baseline_eligible = bool(path_policy["baseline_eligible"])
        if baseline_eligible and manifest_match and manifest_match.get("baseline_eligible") is False:
            baseline_eligible = False
        session, session_stats = self._get_or_create_session(project_id, session_key, log_data)
        normalized_template = normalized_event or self._normalize_template_with_manifest(log_data, manifest_match)
        features = self.extract_features(log_data, session_stats)
        self.project_manager.increment_log_count(project_id)

        clean_position = project.clean_baseline_count + int((metadata or {}).get("clean_baseline_offset", 1 if baseline_eligible else 0))
        split_name = self._split_name_for_position(clean_position, project.warmup_threshold)

        if project.phase == ProjectPhase.ACTIVE.value and project_id in self.students:
            result = self._detect_with_student(project_id, log_data, normalized_template, session, session_stats, features)
        else:
            result = self._detect_with_teacher(project_id, log_data, normalized_template, session, session_stats, features)
            if project.phase == ProjectPhase.WARMUP.value and baseline_eligible and split_name == "train":
                self._collect_training_data(project_id, normalized_template, session_key, features)
            if project.phase == ProjectPhase.TRAINING.value:
                self._maybe_trigger_student_training(project_id)

        decision = self._compose_final_decision(
            project=project,
            traffic_class=traffic_class,
            baseline_eligible=baseline_eligible,
            raw_result=result,
        )
        calibrated_threshold = self._update_project_calibration(
            project_id,
            decision.get('anomaly_score', 0.0),
            baseline_eligible=baseline_eligible,
            split_name=split_name,
        )
        decision['raw_anomaly_score'] = decision.get('anomaly_score', 0.0)
        decision['anomaly_score'] = max(decision.get('anomaly_score', 0.0), decision.get('policy_score', 0.0))
        if decision['final_decision'] not in {'skipped', 'threat_detected'}:
            decision['is_anomaly'] = decision['anomaly_score'] >= calibrated_threshold
            decision['final_decision'] = "threat_detected" if decision['is_anomaly'] else "not_flagged"
            if decision['is_anomaly']:
                decision['decision_reason'] = "behavioral_anomaly"
        result['calibration'] = {
            'project_threshold': calibrated_threshold,
            'baseline_eligible': baseline_eligible,
        }
        incident = self._build_incident(
            project_id,
            log_data,
            normalized_template,
            is_anomaly=decision['is_anomaly'],
            decision_reason=decision.get('decision_reason'),
            raw_result=result,
            component_status=decision.get('component_status'),
        )
        if incident:
            result.update(incident)

        result.update(decision)
        student = self.students.get(project_id)
        if student is not None:
            student.record_reservoir_observation(
                sequence=list(session['templates']),
                is_anomaly=result['is_anomaly'],
                is_known_attack=bool(result.get('rule_based', {}).get('is_attack')),
            )
            self.project_manager.update_reservoir_counts(
                project_id,
                clean_normal_reservoir_count=len(student.clean_normal_reservoir),
                suspicious_reservoir_count=len(student.suspicious_reservoir),
                confirmed_malicious_reservoir_count=len(student.confirmed_malicious_reservoir),
            )
        self._maybe_promote_project(project_id)
        project = self.project_manager.get_project(project_id) or project
        runtime_metrics.increment('structured_detections_total')
        result['project_id'] = project_id
        result['project_name'] = project.project_name
        result['phase'] = project.phase
        result['log_count'] = project.current_log_count
        result['warmup_progress'] = min(100, (project.current_log_count / project.warmup_threshold) * 100)
        result['model_version'] = self.model_version
        result['feature_schema_version'] = self.feature_schema_version
        result['student_training_blockers'] = project.student_training_blockers
        result['traffic_class'] = traffic_class
        result['baseline_eligible'] = baseline_eligible
        result['threshold_source'] = project.threshold_source
        result['threshold_fitted_at'] = project.threshold_fitted_at
        result['calibration_sample_count'] = project.calibration_sample_count
        result['score_normalization_version'] = project.score_normalization_version
        result['endpoint_manifest_match'] = bool(manifest_match)
        result['endpoint_manifest_class'] = manifest_match.get("classification") if manifest_match else None
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
                self.project_manager.update_reservoir_counts(
                    project_id,
                    clean_normal_reservoir_count=len(student.clean_normal_reservoir),
                    suspicious_reservoir_count=len(student.suspicious_reservoir),
                    confirmed_malicious_reservoir_count=len(student.confirmed_malicious_reservoir),
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
                project = self.project_manager.get_project(project_id)
                profile_settings = self._profile_settings_for_project(project) if project else self.profile_settings["standard"]
                success = student.train_from_teacher(
                    teacher_model=self.teacher,
                    epochs=5,
                    learning_rate=1e-4,
                    distillation_alpha=0.5,
                    temperature=3.0,
                    min_training_sequences=profile_settings["min_training_sequences"],
                    min_if_feature_rows=profile_settings["min_if_feature_rows"],
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
