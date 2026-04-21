"""
Log Service
Business logic for log processing and management
"""

from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timezone
import uuid
import csv
import io
import logging
import ipaddress
import json
import asyncio
import hashlib
import os
import re

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from fastapi import HTTPException

from app.models.log_entry import LogEntry, LogEntryCreate, CorrectLogRequest
from app.models.ip_db import IPDB, IPStatusEnum
from app.models.user_db import UserDB, RoleEnum
from app.models.project_db import ProjectDB
from app.services.elasticsearch_service import ElasticsearchService
from app.services.email_service import can_send_alert, mark_alert_sent, send_email
from app.controllers.websocket_controller import send_log_update

logger = logging.getLogger(__name__)
APACHE_LOG_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S +0000"


class LogService:
    """Service class for log-related business logic"""
    DETECTION_SKIP_PATHS = {
        "/health",
        "/healthz",
        "/ready",
        "/readyz",
        "/live",
        "/livez",
        "/metrics",
    }
    SYNTHETIC_FLAG_FIELDS = ("synthetic_attack", "allowlisted_synthetic_attack")
    MANUAL_OVERRIDE_FIELDS = ("manual_malicious_override", "manual_override", "forced_malicious")
    RULE_PATTERNS = (
        re.compile(r"(?:\.\./|%2e%2e%2f|/etc/passwd|/proc/self|/windows/system32)", re.IGNORECASE),
        re.compile(r"(?:\b(?:cmd|command)\b.*(?:=|%3d)|(?:;|&&|\|\|)\s*(?:cat|wget|curl|bash|sh)\b)", re.IGNORECASE),
        re.compile(r"(?:\bunion\b.+\bselect\b|\bor\b\s*['\"]?1['\"]?\s*=\s*['\"]?1|\bsleep\s*\(|\bbenchmark\s*\()", re.IGNORECASE),
        re.compile(r"(?:<script|javascript:|onerror=|onload=)", re.IGNORECASE),
    )
    TRANSPORT_NOISE_PREFIXES = ("/socket.io/",)
    SIGNED_ASSET_PREFIXES = ("/storage/v1/object/sign/",)
    MAX_FUTURE_EVENT_SECONDS = int(os.getenv("LOG_EVENT_MAX_FUTURE_SECONDS", "300"))
    MAX_PAST_EVENT_SECONDS = int(os.getenv("LOG_EVENT_MAX_PAST_SECONDS", str(7 * 24 * 3600)))
    
    def __init__(self):
        self.logs_storage = []  # Placeholder for actual storage
        self.websocket_connections = {}  # Placeholder for WebSocket management
    
    @staticmethod
    def _build_csv_content(logs: List[dict]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            'Timestamp',
            'IP Address',
            'API Accessed',
            'Status Code',
            'Infected',
            'Ensemble Anomaly Score',
            'Rule-Based Detection',
            'Rule-Based Confidence',
            'Rule-Based Attack Types',
            'Isolation Forest Detection',
            'Isolation Forest Score',
            'Transformer Detection',
            'Transformer NLL Score',
            'Transformer Threshold',
            'Transformer Sequence Length'
        ])

        for log in logs:
            anomaly_details = log.get('anomaly_details', {})

            rule_based = anomaly_details.get('rule_based', {})
            rule_attack = rule_based.get('is_attack', False)
            rule_confidence = rule_based.get('confidence', 0.0)
            rule_attack_types = ', '.join(rule_based.get('attack_types', []))

            iso_forest = anomaly_details.get('isolation_forest', {})
            iso_anomaly = iso_forest.get('is_anomaly', 0)
            iso_score = iso_forest.get('score', 0.0)

            transformer = anomaly_details.get('transformer', {})
            trans_anomaly = transformer.get('is_anomaly', 0)
            trans_score = transformer.get('score', 0.0)
            trans_threshold = transformer.get('threshold', 0.0)
            trans_seq_len = transformer.get('sequence_length', 0)

            ensemble = anomaly_details.get('ensemble', {})
            ensemble_score = ensemble.get('score', 0.0)

            writer.writerow([
                log.get('timestamp', ''),
                log.get('ip_address') or '',
                log.get('api_accessed', ''),
                log.get('status_code', ''),
                log.get('infected', False),
                ensemble_score,
                'Yes' if rule_attack else 'No',
                rule_confidence,
                rule_attack_types,
                'Yes' if iso_anomaly == 1 else 'No',
                iso_score,
                'Yes' if trans_anomaly == 1 else 'No',
                trans_score,
                trans_threshold,
                trans_seq_len
            ])

        return output.getvalue()

    @staticmethod
    def _is_structured_nginx_log(record: Dict[str, Any]) -> bool:
        return all(key in record for key in ['remote', 'method', 'path', 'code'])

    @staticmethod
    def _extract_known_log_field(record: Dict[str, Any], common_fields: List[str]) -> str | None:
        for field_name in common_fields:
            if field_name in record:
                return record[field_name]
        return None

    @staticmethod
    def _extract_nested_log_content(record: Dict[str, Any], common_fields: List[str]) -> str | None:
        nested_record = record.get('record')
        if not isinstance(nested_record, dict):
            return None

        if LogService._is_structured_nginx_log(nested_record):
            return LogService._convert_nginx_to_combined(nested_record)

        return LogService._extract_known_log_field(nested_record, common_fields)

    @staticmethod
    def _extract_fallback_string(record: Dict[str, Any]) -> str | None:
        for key, value in record.items():
            if (
                isinstance(value, str)
                and len(value) > 10
                and key not in ['date', 'time', 'timestamp', '@timestamp', 'host', 'source']
            ):
                return value
        return None

    @staticmethod
    def _extract_log_content(record: Any, common_fields: List[str]) -> str | None:
        if isinstance(record, str):
            return record

        if not isinstance(record, dict):
            return None

        if LogService._is_structured_nginx_log(record):
            return LogService._convert_nginx_to_combined(record)

        direct_content = LogService._extract_known_log_field(record, common_fields)
        if direct_content is not None:
            return direct_content

        nested_content = LogService._extract_nested_log_content(record, common_fields)
        if nested_content is not None:
            return nested_content

        return None

    @staticmethod
    def _extract_event_time(record: Any) -> Optional[Any]:
        if not isinstance(record, dict):
            return None

        for field_name in ("timestamp", "@timestamp", "time", "date"):
            if field_name in record and record[field_name] not in (None, ""):
                return record[field_name]

        nested_record = record.get("record")
        if isinstance(nested_record, dict):
            for field_name in ("timestamp", "@timestamp", "time", "date"):
                if field_name in nested_record and nested_record[field_name] not in (None, ""):
                    return nested_record[field_name]

        return None

    @staticmethod
    def _extract_candidate_payload(record: Any, common_fields: List[str]) -> tuple[Optional[str], Optional[str]]:
        if isinstance(record, str):
            return record, None

        if not isinstance(record, dict):
            return None, "unsupported_record_type"

        if LogService._is_structured_nginx_log(record):
            return LogService._convert_nginx_to_combined(record), None

        direct_content = LogService._extract_known_log_field(record, common_fields)
        if direct_content is not None:
            return direct_content, None

        nested_record = record.get("record")
        if isinstance(nested_record, dict):
            if LogService._is_structured_nginx_log(nested_record):
                return LogService._convert_nginx_to_combined(nested_record), None

            nested_content = LogService._extract_known_log_field(nested_record, common_fields)
            if nested_content is not None:
                return nested_content, None

            return None, "unsupported_nested_record"

        return None, "unsupported_record_format"

    @staticmethod
    def _stable_record_hash(record: Any) -> str:
        try:
            serialized = json.dumps(record, sort_keys=True, default=str)
        except TypeError:
            serialized = str(record)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @staticmethod
    def _clean_identity_value(value: Any) -> Optional[str]:
        if not isinstance(value, str):
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        if cleaned.lower() in {"-", "null", "none", "unknown", "n/a"}:
            return None
        return cleaned

    @staticmethod
    def _extract_coarse_identity_value(parsed_log: Dict[str, Any], source_record: Any) -> Optional[str]:
        """
        Build a coarse but stable identity when logs have no explicit user/session/IP.

        This avoids per-log hash fallback (which creates one-event sessions and yields
        constant transformer outputs with insufficient sequence context).
        """
        candidates: List[str] = []

        user_agent = LogService._clean_identity_value(parsed_log.get("user_agent"))
        if user_agent:
            candidates.append(f"ua:{user_agent}")

        source_records: List[Dict[str, Any]] = []
        if isinstance(source_record, dict):
            source_records.append(source_record)
            nested_record = source_record.get("record")
            if isinstance(nested_record, dict):
                source_records.append(nested_record)

        source_fields = (
            "source",
            "tag",
            "host",
            "hostname",
            "stream",
            "container_name",
            "pod_name",
            "service",
            "app",
        )
        for record in source_records:
            for field_name in source_fields:
                value = LogService._clean_identity_value(record.get(field_name))
                if value:
                    candidates.append(f"{field_name}:{value}")
            kubernetes = record.get("kubernetes")
            if isinstance(kubernetes, dict):
                for field_name in ("namespace_name", "pod_name", "container_name", "host"):
                    value = LogService._clean_identity_value(kubernetes.get(field_name))
                    if value:
                        candidates.append(f"k8s.{field_name}:{value}")

        if not candidates:
            return None

        basis = "|".join(sorted(set(candidates)))
        return f"coarse-{hashlib.sha256(basis.encode('utf-8')).hexdigest()[:24]}"

    @staticmethod
    def _extract_identity_value(parsed_log: Dict[str, Any], source_record: Any) -> Optional[str]:
        parsed_candidates = [
            parsed_log.get("auth_user"),
            parsed_log.get("session_id"),
            parsed_log.get("user_id"),
        ]
        for value in parsed_candidates:
            cleaned = LogService._clean_identity_value(value)
            if cleaned:
                return cleaned

        candidate_records: List[Dict[str, Any]] = []
        if isinstance(source_record, dict):
            candidate_records.append(source_record)
            nested_record = source_record.get("record")
            if isinstance(nested_record, dict):
                candidate_records.append(nested_record)

        identity_fields = (
            "session_id",
            "session",
            "sessionId",
            "user_id",
            "userId",
            "uid",
            "auth_user",
            "authUser",
            "user",
            "username",
            "principal",
            "client_ip",
            "ip",
            "remote",
        )
        for candidate_record in candidate_records:
            for field_name in identity_fields:
                value = candidate_record.get(field_name)
                cleaned = LogService._clean_identity_value(value)
                if cleaned:
                    return cleaned

        ip_address = LogService._clean_identity_value(parsed_log.get("ip_address"))
        if ip_address:
            return ip_address

        return None

    @staticmethod
    def build_session_key(project_id: str, parsed_log: Dict[str, Any], source_record: Any) -> str:
        identity = LogService._extract_identity_value(parsed_log, source_record)
        if identity:
            return f"{project_id}:{identity}"
        coarse_identity = LogService._extract_coarse_identity_value(parsed_log, source_record)
        if coarse_identity:
            return f"{project_id}:{coarse_identity}"
        return f"{project_id}:{LogService._stable_record_hash(source_record)}"

    @staticmethod
    def build_session_key_hash(session_key: str) -> str:
        return hashlib.sha256(session_key.encode("utf-8")).hexdigest()

    @staticmethod
    def normalize_ip_for_storage(raw_ip: Any) -> Optional[str]:
        """
        Return a valid IP literal for Elasticsearch `ip` mapping, else None.

        Elasticsearch rejects empty strings for `ip` fields, but accepts null.
        """
        if raw_ip is None:
            return None
        candidate = str(raw_ip).strip()
        if not candidate:
            return None
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            return None

    @staticmethod
    def should_skip_detection(parsed_log: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        path = (parsed_log.get("path") or "").strip().lower()
        if path in LogService.DETECTION_SKIP_PATHS:
            return True, "health_check_skipped"
        if path.startswith(LogService.TRANSPORT_NOISE_PREFIXES):
            return True, "transport_noise_skipped"
        if path.startswith(LogService.SIGNED_ASSET_PREFIXES):
            return True, "signed_asset_skipped"
        return False, None

    @staticmethod
    def _parse_event_datetime(event_time: Any) -> Optional[datetime]:
        if not isinstance(event_time, str) or not event_time:
            return None
        try:
            parsed = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            return None

    @staticmethod
    def detect_rule_hit(parsed_log: Dict[str, Any]) -> bool:
        path = parsed_log.get("path") or ""
        if not path:
            return False
        return any(pattern.search(path) for pattern in LogService.RULE_PATTERNS)

    @staticmethod
    def classify_traffic(
        *,
        parsed_log: Dict[str, Any],
        source_record: Any,
        raw_log: Optional[str],
        event_time: Optional[str],
    ) -> Dict[str, Any]:
        flags: Dict[str, Any] = {
            "rule_hit": LogService.detect_rule_hit(parsed_log),
            "synthetic_attack": False,
            "manual_malicious_override": False,
            "parse_failed": False,
            "internal_probe": False,
            "late_or_invalid_event": False,
            "duplicate_in_batch": False,
        }

        candidates: List[Dict[str, Any]] = []
        if isinstance(source_record, dict):
            candidates.append(source_record)
            nested_record = source_record.get("record")
            if isinstance(nested_record, dict):
                candidates.append(nested_record)

        for candidate in candidates:
            if any(bool(candidate.get(field_name)) for field_name in LogService.SYNTHETIC_FLAG_FIELDS):
                flags["synthetic_attack"] = True
            if any(bool(candidate.get(field_name)) for field_name in LogService.MANUAL_OVERRIDE_FIELDS):
                flags["manual_malicious_override"] = True

        should_skip, skip_reason = LogService.should_skip_detection(parsed_log)
        if should_skip and skip_reason == "health_check_skipped":
            flags["internal_probe"] = True

        parsed_event_time = LogService._parse_event_datetime(event_time or parsed_log.get("timestamp"))
        if parsed_event_time is not None:
            now = datetime.now(timezone.utc)
            delta_seconds = (parsed_event_time - now).total_seconds()
            if delta_seconds > LogService.MAX_FUTURE_EVENT_SECONDS or delta_seconds < -LogService.MAX_PAST_EVENT_SECONDS:
                flags["late_or_invalid_event"] = True

        if flags["internal_probe"]:
            traffic_class = "internal_probe"
            detection_status = "skipped"
            decision_reason = skip_reason or "internal_probe_skipped"
        elif skip_reason == "transport_noise_skipped":
            traffic_class = "transport_noise"
            detection_status = "skipped"
            decision_reason = "transport_noise_skipped"
        elif skip_reason == "signed_asset_skipped":
            traffic_class = "signed_asset_access"
            detection_status = "skipped"
            decision_reason = "signed_asset_skipped"
        elif flags["late_or_invalid_event"]:
            traffic_class = "data_quality_late_event"
            detection_status = "skipped"
            decision_reason = "late_event_skipped"
        elif flags["synthetic_attack"]:
            traffic_class = "synthetic_attack"
            detection_status = "pending"
            decision_reason = "synthetic_attack_excluded"
        elif flags["manual_malicious_override"]:
            traffic_class = "manual_override"
            detection_status = "pending"
            decision_reason = "manual_override_excluded"
        else:
            traffic_class = "user_traffic"
            detection_status = "pending"
            decision_reason = "behavioral_detection_pending"

        baseline_eligible = (
            traffic_class == "user_traffic"
            and not flags["rule_hit"]
            and not flags["late_or_invalid_event"]
        )

        return {
            "traffic_class": traffic_class,
            "flags": flags,
            "baseline_eligible": baseline_eligible,
            "decision_reason": decision_reason,
            "detection_status": detection_status,
        }

    @staticmethod
    def extract_log_candidates(records: List[Any]) -> List[Dict[str, Any]]:
        """Extract candidate raw logs plus source metadata from Fluent Bit records."""
        candidates: List[Dict[str, Any]] = []
        common_fields = ['log', 'message', 'msg', '_raw', 'content', 'line', 'MESSAGE', 'Log', 'Message']

        logger.debug(
            "[extract_log_candidates] Processing %s records",
            len(records) if hasattr(records, "__len__") else "unknown",
        )

        for index, record in enumerate(records):
            raw_log, extraction_error = LogService._extract_candidate_payload(record, common_fields)
            candidate = {
                "index": index,
                "record": record,
                "raw_log": raw_log.strip() if isinstance(raw_log, str) else None,
                "event_time": LogService._extract_event_time(record),
                "extraction_error": extraction_error,
            }
            candidates.append(candidate)

        return candidates

    
    async def export_logs_to_csv(self, logs: List[dict]) -> str:
        """
        Export logs to CSV format with anomaly scores for each model
        
        Args:
            logs: List of log dictionaries from Elasticsearch
            
        Returns:
            CSV string content
        """
        return await asyncio.to_thread(self._build_csv_content, logs)
    

    async def correct_log_status(
        self,
        request: CorrectLogRequest,
        user_info: Dict[str, Any],
        db: AsyncSession,
        elasticsearch_service: ElasticsearchService
    ) -> Dict[str, Any]:
        """
        Correct log status for an IP address.

        Args:
            request: CorrectLogRequest with ip and status
            user_info: User information dict with email, role, org_id
            db: Database session
            elasticsearch_service: Elasticsearch service instance

        Returns:
            Dict with correction results
        """
        # Extract user information
        user_email = user_info.get("email", "unknown")
        org_id = user_info["org_id"]

        # Validate IP address format
        try:
            ipaddress.ip_address(request.ip)
        except ValueError:
            raise ValueError("Invalid IP address format")

        # Validate and normalize status
        status_lower = request.status.lower()
        if status_lower not in ["clean", "malicious"]:
            raise ValueError("Status must be either 'clean' or 'malicious'")

        status_enum = IPStatusEnum.CLEAN if status_lower == "clean" else IPStatusEnum.MALICIOUS
        infected = status_enum == IPStatusEnum.MALICIOUS

        # Check if IP already exists in database for this org
        result = await db.execute(select(IPDB).where(IPDB.ip == request.ip, IPDB.org == org_id))
        existing_ip = result.scalar_one_or_none()

        # Prepare database operation
        if existing_ip:
            # Update existing IP record
            existing_ip.status = status_enum

            logger.warning(
                "[HUMAN CORRECTION] Existing IP status override recorded. "
                "Manual correction will override model predictions."
            )
        else:
            # Create new IP record
            new_ip = IPDB(
                ip=request.ip,
                status=status_enum,
                org=org_id
            )
            db.add(new_ip)

            logger.warning(
                "[HUMAN CORRECTION] New IP status override recorded."
            )

        # Update all logs for this IP in Elasticsearch
        update_result = await elasticsearch_service.update_logs_by_ip(
            ip_address=request.ip,
            infected=infected,
            org_id=org_id
        )

        # Handle Elasticsearch update results
        if update_result["status"] == "error":
            logger.error("[HUMAN CORRECTION] Failed to update logs in Elasticsearch")
            return {
                "message": "IP status updated in database, but Elasticsearch update failed",
                "ip": request.ip,
                "status": request.status,
                "database_updated": True,
                "elasticsearch_updated": False,
                "elasticsearch_error": update_result.get("message"),
                "logs_updated_count": 0,
                "corrected_by": user_email
            }

        logs_count = update_result.get("update_count", 0)
        logger.info("[HUMAN CORRECTION] Elasticsearch update completed for %s log(s)", logs_count)

        return {
            "message": "IP status updated successfully",
            "ip": request.ip,
            "status": request.status,
            "database_updated": True,
            "elasticsearch_updated": True,
            "logs_updated_count": logs_count,
            "corrected_by": user_email
        }

    @staticmethod
    def parse_fluent_bit_request(body: bytes) -> List[Dict[str, Any]]:
        """
        Parse the raw request body from Fluent Bit.
        Supports both JSON and MessagePack formats.

        Args:
            body: Raw request body bytes

        Returns:
            List of log records

        Raises:
            HTTPException: If request format is invalid
        """
        logger.debug(f"[parse_fluent_bit_request] Parsing {len(body)} bytes")
        logger.debug(f"[parse_fluent_bit_request] First 100 bytes: {body[:100]}")
        
        # Try MessagePack first (common Fluent Bit format)
        try:
            import msgpack
            request_data = msgpack.unpackb(body, raw=False)
            logger.debug("[parse_fluent_bit_request] Successfully parsed as MessagePack")
            if not isinstance(request_data, list):
                request_data = [request_data]  # Wrap single record in list
            return request_data
        except Exception as msgpack_error:
            logger.debug(f"[parse_fluent_bit_request] MessagePack failed: {msgpack_error}")
        
        # Try JSON format
        try:
            request_data = json.loads(body)
            logger.debug("[parse_fluent_bit_request] Successfully parsed as JSON")
        except json.JSONDecodeError as json_error:
            logger.debug(f"[parse_fluent_bit_request] JSON failed: {json_error}")
            raise HTTPException(status_code=400, detail=f"Invalid request format. Body must be JSON or MessagePack. JSON error: {str(json_error)}")

        if not isinstance(request_data, list):
            request_data = [request_data]  # Wrap single record in list
            
        return request_data

    @staticmethod
    def extract_raw_logs_from_records(records: List[Any]) -> List[str]:
        """
        Extract raw log strings from Fluent Bit records.

        Args:
            records: List of records from Fluent Bit (dicts with 'log' key or strings)

        Returns:
            List of raw log strings in Apache Combined Log Format
        """
        candidates = LogService.extract_log_candidates(records)
        raw_logs = [
            candidate["raw_log"]
            for candidate in candidates
            if isinstance(candidate.get("raw_log"), str) and candidate["raw_log"]
        ]
        logger.debug("[extract_raw_logs] Extracted %s logs from %s records", len(raw_logs), len(records))
        return raw_logs

    @staticmethod
    def _convert_nginx_to_combined(record: Dict) -> str:
        """
        Convert structured nginx log record to Apache Combined Log Format.
        
        Expected record format:
        {
            "date": 1769347254.0,
            "remote": "139.135.32.142",
            "user": "-",
            "method": "GET",
            "path": "/login",
            "code": "304",
            "size": "0",
            "referer": "-",
            "agent": "Mozilla/5.0 ..."
        }
        
        Returns:
            Apache Combined Log Format string:
            139.135.32.142 - - [01/Jan/2024:12:00:00 +0000] "GET /login HTTP/1.1" 304 0 "-" "Mozilla/5.0 ..."
        """
        from datetime import datetime
        
        # Extract fields with defaults
        ip = record.get('remote', '127.0.0.1')
        user = record.get('user', '-')
        method = record.get('method', 'GET')
        path = record.get('path', '/')
        code = record.get('code', '200')
        size = record.get('size', '0')
        referer = record.get('referer', '-')
        agent = record.get('agent', '-')
        
        # Convert Unix timestamp to log format
        timestamp = record.get('date')
        if timestamp:
            try:
                dt = datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
                timestamp_str = dt.strftime(APACHE_LOG_TIMESTAMP_FORMAT)
            except (TypeError, ValueError, OSError):
                timestamp_str = datetime.now(timezone.utc).strftime(APACHE_LOG_TIMESTAMP_FORMAT)
        else:
            timestamp_str = datetime.now(timezone.utc).strftime(APACHE_LOG_TIMESTAMP_FORMAT)
        
        # Handle size = "-" or "0"
        if size == '-':
            size = '0'
        
        # Build Combined Log Format line
        log_line = f'{ip} - {user} [{timestamp_str}] "{method} {path} HTTP/1.1" {code} {size} "{referer}" "{agent}"'
        
        return log_line

    @staticmethod
    async def get_ip_status_map(unique_ips: set, org_id: str, db: AsyncSession) -> Dict[str, bool]:
        """
        Query IP database for status overrides for given IPs.

        Args:
            unique_ips: Set of unique IP addresses
            org_id: Organization ID
            db: Database session

        Returns:
            Dict mapping IP addresses to infected status (True for malicious)
        """
        ip_status_map = {}

        if not unique_ips:
            return ip_status_map

        try:
            result = await db.execute(
                select(IPDB).where(IPDB.ip.in_(list(unique_ips)), IPDB.org == org_id)
            )
            ip_records = result.scalars().all()

            for ip_record in ip_records:
                # Map status to infected boolean: malicious = True, clean = False
                ip_status_map[ip_record.ip] = ip_record.status == IPStatusEnum.MALICIOUS

            logger.debug(f"Found {len(ip_status_map)} IPs in IP table out of {len(unique_ips)} unique IPs for org {org_id}")

        except Exception as e:
            logger.error(f"Error querying IP table: {e}")

        return ip_status_map

    @staticmethod
    def format_log_for_storage(
        parsed_log: Dict[str, Any],
        raw_log: str,
        anomaly_result: Dict[str, Any],
        ip_status_map: Dict[str, bool],
        batch_id: str,
        org_id: str,
        project_id: str,
        session_key_hash: Optional[str] = None,
        parse_status: str = "parsed",
        parse_error: Optional[str] = None,
        detection_status: str = "scored",
        detection_error: Optional[str] = None,
        traffic_class: Optional[str] = None,
        baseline_eligible: Optional[bool] = None,
        decision_reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Format a parsed log for Elasticsearch storage.

        Args:
            parsed_log: Parsed log data from log parser
            raw_log: Original raw log string
            anomaly_result: Anomaly detection result
            ip_status_map: IP status override map
            batch_id: Batch identifier
            org_id: Organization ID

        Returns:
            Formatted log dict for Elasticsearch
        """
        ip_address = LogService.normalize_ip_for_storage(parsed_log.get("ip_address"))
        final_decision = anomaly_result.get("final_decision")
        infected_status = final_decision == "threat_detected"
        if final_decision is None:
            infected_status = anomaly_result.get("is_anomaly", False)

        # Override infected status if IP is in the IP table
        if ip_address and ip_address in ip_status_map:
            infected_status = ip_status_map[ip_address]
            logger.debug(f"Overriding infected status for IP {ip_address} to {infected_status} based on IP table")

        # Format for storage - use original ISO timestamp for Elasticsearch
        formatted_log = {
            "timestamp": parsed_log["timestamp"],  # Keep original ISO format for Elasticsearch
            "event_time": parsed_log["timestamp"],
            "ingest_time": datetime.now(timezone.utc).isoformat(),
            "ip_address": ip_address,
            "api_accessed": parsed_log["path"],
            "status_code": parsed_log["status_code"],
            "infected": infected_status,
            "anomaly_score": anomaly_result.get("anomaly_score", 0.0),
            "anomaly_details": {
                "rule_based": anomaly_result.get("details", {}).get("rule_based", {}),
                "isolation_forest": anomaly_result.get("details", {}).get("isolation_forest", {}),
                "transformer": anomaly_result.get("details", {}).get("transformer", {}),
                "ensemble": anomaly_result.get("details", {}).get("ensemble", {})
            },
            "raw_log": raw_log,
            "method": parsed_log.get("method", ""),
            "protocol": parsed_log.get("protocol", ""),
            "size": parsed_log.get("size", 0),
            "batch_id": batch_id,
            "source": "fluent_bit",
            "org_id": org_id,
            "project_id": project_id,
            "parse_status": parse_status,
            "parse_error": parse_error,
            "detection_status": detection_status,
            "detection_error": detection_error,
            "traffic_class": traffic_class,
            "baseline_eligible": baseline_eligible,
            "decision_reason": decision_reason or anomaly_result.get("decision_reason"),
            "policy_score": anomaly_result.get("policy_score", 0.0),
            "final_decision": final_decision,
            "component_status": anomaly_result.get("component_status", {}),
            "session_key_hash": session_key_hash,
            "normalized_template": parsed_log.get("normalized_event"),
            "incident_id": anomaly_result.get("incident_id"),
            "incident_type": anomaly_result.get("incident_type"),
            "incident_bucket_start": anomaly_result.get("incident_bucket_start"),
            "incident_grouped_event_count": anomaly_result.get("incident_grouped_event_count"),
            "incident_reason": anomaly_result.get("incident_reason"),
            "top_contributing_signals": anomaly_result.get("top_contributing_signals", []),
            "calibration": anomaly_result.get("calibration", {}),
            "raw_anomaly_score": anomaly_result.get("raw_anomaly_score", anomaly_result.get("anomaly_score", 0.0)),
            "model_type": anomaly_result.get("model_type"),
            "detector_phase": anomaly_result.get("phase"),
            "model_version": anomaly_result.get("model_version", "adaptive-v2"),
            "feature_schema_version": anomaly_result.get("feature_schema_version", "access-log-v1"),
            "threshold_source": anomaly_result.get("threshold_source"),
            "threshold_fitted_at": anomaly_result.get("threshold_fitted_at"),
            "calibration_sample_count": anomaly_result.get("calibration_sample_count"),
            "score_normalization_version": anomaly_result.get("score_normalization_version"),
            "unknown_template_ratio": anomaly_result.get("unknown_template_ratio"),
        }

        return formatted_log

    @staticmethod
    def format_parse_failure_for_storage(
        raw_log: Optional[str],
        batch_id: str,
        org_id: str,
        event_time: str,
        parse_error: str,
        source_record: Any,
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        resolved_project_id = project_id or org_id
        return {
            "timestamp": event_time,
            "event_time": event_time,
            "ingest_time": datetime.now(timezone.utc).isoformat(),
            "ip_address": None,
            "api_accessed": "",
            "status_code": 0,
            "infected": False,
            "anomaly_score": 0.0,
            "anomaly_details": {},
            "raw_log": raw_log or "",
            "batch_id": batch_id,
            "source": "fluent_bit",
            "org_id": org_id,
            "project_id": resolved_project_id,
            "parse_status": "failed",
            "parse_error": parse_error,
            "detection_status": "skipped",
            "detection_error": "parse_failed",
            "traffic_class": "unsupported_format",
            "baseline_eligible": False,
            "decision_reason": "parse_failure",
            "policy_score": 0.0,
            "final_decision": "parse_failed",
            "component_status": {},
            "session_key_hash": LogService.build_session_key_hash(
                f"{org_id}:{LogService._stable_record_hash(source_record)}"
            ),
            "normalized_template": None,
            "incident_id": None,
            "incident_type": "parse_failure",
            "incident_bucket_start": event_time,
            "incident_grouped_event_count": None,
            "incident_reason": "parse_failure",
            "top_contributing_signals": [],
            "calibration": {},
            "raw_anomaly_score": 0.0,
            "model_type": None,
            "detector_phase": "skipped",
            "model_version": "adaptive-v2",
            "feature_schema_version": "access-log-v1",
            "threshold_source": None,
            "threshold_fitted_at": None,
            "calibration_sample_count": 0,
            "score_normalization_version": None,
            "unknown_template_ratio": None,
        }

    @staticmethod
    def convert_log_for_websocket(log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert Elasticsearch log format to WebSocket format (camelCase).

        Args:
            log: Log in Elasticsearch format

        Returns:
            Log in WebSocket format
        """
        return {
            "timestamp": log.get("timestamp", ""),
            "eventTime": log.get("event_time") or log.get("timestamp", ""),
            "ingestTime": log.get("ingest_time") or log.get("created_at", ""),
            "ipAddress": log.get("ip_address") or "",
            "apiAccessed": log.get("api_accessed", ""),
            "statusCode": log.get("status_code", 0),
            "infected": log.get("infected", False),
            "anomaly_score": log.get("anomaly_score", 0.0),
            "anomaly_details": log.get("anomaly_details", {}),
            "parseStatus": log.get("parse_status", "parsed"),
            "parseError": log.get("parse_error"),
            "detectionStatus": log.get("detection_status", "scored"),
            "detectionError": log.get("detection_error"),
            "trafficClass": log.get("traffic_class"),
            "baselineEligible": log.get("baseline_eligible"),
            "decisionReason": log.get("decision_reason"),
            "policyScore": log.get("policy_score"),
            "finalDecision": log.get("final_decision"),
            "componentStatus": log.get("component_status", {}),
            "incidentId": log.get("incident_id"),
            "incidentType": log.get("incident_type"),
            "incidentGroupedEventCount": log.get("incident_grouped_event_count"),
            "incidentReason": log.get("incident_reason"),
            "topContributingSignals": log.get("top_contributing_signals", []),
            "normalizedTemplate": log.get("normalized_template"),
            "sessionKeyHash": log.get("session_key_hash"),
            "modelVersion": log.get("model_version"),
            "featureSchemaVersion": log.get("feature_schema_version"),
            "detectorPhase": log.get("detector_phase"),
            "modelType": log.get("model_type"),
            "rawAnomalyScore": log.get("raw_anomaly_score"),
            "calibration": log.get("calibration", {}),
            "thresholdSource": log.get("threshold_source"),
            "thresholdFittedAt": log.get("threshold_fitted_at"),
            "calibrationSampleCount": log.get("calibration_sample_count"),
            "scoreNormalizationVersion": log.get("score_normalization_version"),
            "unknownTemplateRatio": log.get("unknown_template_ratio"),
        }

    @staticmethod
    async def send_anomaly_alert(
        anomalies_detected: int,
        processed_logs: List[Dict[str, Any]],
        batch_id: str,
        org_id: str,
        db: AsyncSession
    ) -> None:
        """
        Send email alert for detected anomalies.

        Args:
            anomalies_detected: Number of anomalies detected
            processed_logs: List of processed logs
            batch_id: Batch identifier
            org_id: Organization ID
            db: Database session
        """
        try:
            if anomalies_detected > 0 and can_send_alert():
                # Fetch manager emails for this organization
                result = await db.execute(
                    select(UserDB).where(UserDB.role == RoleEnum.MANAGER, UserDB.org_id == org_id)
                )
                managers = result.scalars().all()
                recipients = [u.email for u in managers if getattr(u, 'enabled', True)]

                if recipients:
                    grouped_incidents: Dict[str, Dict[str, Any]] = {}
                    for log in processed_logs:
                        if not log.get("infected", False):
                            continue
                        incident_id = log.get("incident_id") or f"fallback:{log.get('api_accessed')}:{log.get('ip_address')}"
                        grouped_incidents.setdefault(incident_id, log)

                    example = next(iter(grouped_incidents.values()), None)
                    subject = f"LogGuard Alert: {len(grouped_incidents)} incident(s) detected"
                    body_lines = [
                        "Anomaly summary:",
                        f"- Batch ID: {batch_id}",
                        f"- Incident groups: {len(grouped_incidents)}",
                        f"- Anomalous logs: {anomalies_detected}",
                    ]

                    for incident_id, incident_log in list(grouped_incidents.items())[:5]:
                        body_lines.extend(
                            [
                                "",
                                f"Incident: {incident_id}",
                                f"Type: {incident_log.get('incident_type', 'anomaly')}",
                                f"Template: {incident_log.get('normalized_template', '')}",
                                f"IP: {incident_log.get('ip_address') or ''}",
                                f"API: {incident_log.get('api_accessed', '')}",
                                f"Status: {incident_log.get('status_code', '')}",
                                f"Score: {incident_log.get('anomaly_score', '')}",
                            ]
                        )

                    if example:
                        body_lines += [
                            "",
                            "First incident example:",
                            f"Time: {example.get('timestamp', '')}",
                            f"IP: {example.get('ip_address') or ''}",
                            f"API: {example.get('api_accessed', '')}",
                            f"Status: {example.get('status_code', '')}",
                            f"Score: {example.get('anomaly_score', '')}",
                        ]

                    body = "\n".join(body_lines)
                    # Send email (best-effort)
                    await asyncio.to_thread(send_email, subject, body, recipients)
                    mark_alert_sent()

        except Exception as alert_err:
            logger.warning(f"Failed to send anomaly alert email: {alert_err}")

    @staticmethod
    async def process_parsed_logs_batch(
        parsed_logs_data: List[Dict[str, Any]],
        anomaly_results: List[Dict[str, Any]],
        ip_status_map: Dict[str, bool],
        batch_id: str,
        org_id: str,
        project_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Process a batch of parsed logs into formatted logs for storage.

        Args:
            parsed_logs_data: List of parsed log data
            anomaly_results: List of anomaly detection results
            ip_status_map: IP status override map
            batch_id: Batch identifier
            org_id: Organization ID
            project_id: Project ID

        Returns:
            List of formatted logs for storage
        """
        processed_logs = []

        for log_data in parsed_logs_data:
            try:
                parsed_log = log_data["parsed_log"]
                raw_log = log_data["raw_log"]
                i = log_data["anomaly_index"]

                # Get anomaly result for this log
                anomaly_result = anomaly_results[i] if i < len(anomaly_results) else {
                    "is_anomaly": False,
                    "anomaly_score": 0.0,
                    "details": {}
                }

                formatted_log = LogService.format_log_for_storage(
                    parsed_log,
                    raw_log,
                    anomaly_result,
                    ip_status_map,
                    batch_id,
                    org_id,
                    project_id or org_id,
                )

                processed_logs.append(formatted_log)

            except Exception as e:
                logger.error(f"Error processing individual log: {e}")
                continue


        return processed_logs

    @staticmethod
    async def send_logs_to_websocket(
        processed_logs: List[Dict[str, Any]],
        org_id: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> None:
        """
        Send processed logs to WebSocket connections for real-time updates.

        Args:
            processed_logs: List of processed logs
            org_id: Organization ID to filter which clients receive the updates
            project_id: Project ID to filter which project dashboards receive updates
        """
        for log in processed_logs:
            try:
                # Get org_id from log if not explicitly provided
                log_org_id = org_id or log.get("org_id")
                log_project_id = project_id or log.get("project_id")
                websocket_log = LogService.convert_log_for_websocket(log)
                await send_log_update(websocket_log, org_id=log_org_id, project_id=log_project_id)
                logger.debug(f"Sent log to WebSocket: {websocket_log}")
                logger.info(
                    "WebSocket log sent - IP: %s, API: %s, org_id: %s, project_id: %s",
                    websocket_log.get('ipAddress'),
                    websocket_log.get('apiAccessed'),
                    log_org_id,
                    log_project_id,
                )
            except Exception as e:
                logger.error(f"Error sending log to WebSocket: {e}")

    @staticmethod
    async def increment_org_log_count(
        org_id: str,
        count: int,
        db: AsyncSession,
        model_phase: Optional[str] = None,
    ) -> None:
        """
        Increment the log count for an organization and update warmup progress.
        
        Args:
            org_id: Organization ID
            count: Number of logs to add
            db: Database session
            model_phase: Optional detector phase to mirror in project model_status
        """
        try:
            # Get current org data
            result = await db.execute(
                select(ProjectDB).where(ProjectDB.id == org_id)
            )
            org = result.scalar_one_or_none()
            
            if org:
                # Calculate new values
                new_log_count = (org.log_count or 0) + count
                warmup_threshold = org.warmup_threshold or 10000
                new_progress = min(100.0, (new_log_count / warmup_threshold) * 100)
                
                # Update organization
                await db.execute(
                    update(ProjectDB)
                    .where(ProjectDB.id == org_id)
                    .values(
                        log_count=new_log_count,
                        warmup_progress=new_progress,
                        model_status=(
                            "ready" if model_phase == "active"
                            else "training" if model_phase == "training"
                            else "warmup"
                        ) if model_phase else org.model_status,
                    )
                )
                await db.commit()
                
                logger.info(f"Updated org {org_id}: log_count={new_log_count}, progress={new_progress:.1f}%")
            else:
                logger.warning(f"Organization {org_id} not found for log count update")
                
        except Exception as e:
            logger.error(f"Error updating org log count: {e}")
            # Don't fail the main operation if count update fails
            await db.rollback()
