"""
Ensemble Anomaly Detector
Combines Transformer, Rule-Based, and Isolation Forest for real-time log anomaly detection.
"""

import json
import math
import re
import pickle
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import deque
from urllib.parse import unquote

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.ensemble import IsolationForest


# ============================================================================
# TRANSFORMER MODEL ARCHITECTURE
# ============================================================================

class TemplateTransformer(nn.Module):
    """Transformer model for sequence anomaly detection"""
    
    def __init__(self, vocab_size, pad_id=0, d_model=256, n_heads=8, n_layers=4, 
                 ffn_dim=1024, max_length=512, dropout=0.1):
        super().__init__()
        self.pad_id = pad_id
        self.max_length = max_length
        self.embedding = nn.Embedding(vocab_size, d_model, padding_idx=pad_id)
        self.positional = nn.Parameter(torch.zeros(1, max_length, d_model))
        
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=n_heads,
            dim_feedforward=ffn_dim,
            dropout=dropout,
            batch_first=True,
            activation='gelu'
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=n_layers)
        self.dropout = nn.Dropout(dropout)
        self.norm = nn.LayerNorm(d_model)
        self.output = nn.Linear(d_model, vocab_size)
        
        self.register_buffer(
            'causal_mask',
            torch.triu(torch.ones(max_length, max_length), diagonal=1).bool(),
            persistent=False
        )
    
    def forward(self, input_ids, attention_mask=None):
        seq_len = input_ids.size(1)
        x = self.embedding(input_ids)
        x = x + self.positional[:, :seq_len, :]
        
        causal = self.causal_mask[:seq_len, :seq_len]
        causal = causal.float().masked_fill(causal, float('-inf'))
        
        if attention_mask is not None:
            key_padding = attention_mask == 0
            x = self.encoder(x, mask=causal, src_key_padding_mask=key_padding)
        else:
            x = self.encoder(x, mask=causal)
        
        x = self.dropout(self.norm(x))
        logits = self.output(x)
        
        return logits


# ============================================================================
# RULE-BASED DETECTOR
# ============================================================================

class RuleBasedDetector:
    """Pattern-based attack detection for HTTP logs"""
    
    def __init__(self):
        # SQL Injection patterns
        self.sql_patterns = [
            r"(?i)(union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1)",
            r"(?i)(select.*from|insert.*into|delete.*from|update.*set)",
            r"(?i)(drop\s+table|truncate\s+table)",
            r"['\"]\s*(or|and)\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
            r"(?i)(exec\(|execute\(|sp_executesql)",
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"(?i)(<img[^>]+src\s*=|<iframe|<object|<embed)",
            r"(?i)(onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=)",
            r"javascript:",
            r"(?i)(alert\(|prompt\(|confirm\(|eval\()",
        ]
        
        # Path Traversal patterns
        self.path_traversal_patterns = [
            r"\.\./",
            r"%2e%2e/",
            r"\.\.\\",
            r"%5c%2e%2e",
        ]
        
        # Command Injection patterns
        self.command_injection_patterns = [
            # Semicolon followed by suspicious binary or shell keyword
            r"(?ix)(?<!\w);\s*(?:bash|sh|cmd|powershell|pwsh|nc|netcat|python|perl|php|ruby|wget|curl|ftp|tftp|scp|nc|telnet|rm|cat|ls|sleep)\b",
            # Pipe into suspicious command
            r"(?ix)\|\s*(?:bash|sh|cmd|powershell|pwsh|nc|netcat|python|perl|php|ruby|wget|curl|ftp|tftp|scp|nc|telnet|rm|cat|ls|sleep)\b",
            # Double operators commonly used to chain commands
            r"(?:&&|\|\|)",
            # Command substitution patterns
            r"\$\([^)]+\)",
            r"`[^`]+`",
            # Environment variable expansion with braces often seen in payloads
            r"\$\{[^}]+\}",
            # Direct invocation of suspicious binaries
            r"(?ix)(?:^|[\s=/])(bash|sh|cmd|powershell|pwsh|nc|netcat|python|perl|php|ruby|wget|curl|ftp|tftp|scp|telnet)(?:\.exe)?(?=$|[\s/?&])",
        ]
        
        # Compile all patterns
        self.all_patterns = {
            'sql_injection': [re.compile(p) for p in self.sql_patterns],
            'xss': [re.compile(p) for p in self.xss_patterns],
            'path_traversal': [re.compile(p) for p in self.path_traversal_patterns],
            'command_injection': [re.compile(p) for p in self.command_injection_patterns]
        }
    
    def detect(self, path: str, method: str = 'GET', status: int = 200) -> Dict:
        """Detect attacks in HTTP request"""
        detected_attacks = []
        decoded_path = unquote(path)
        
        for attack_type, patterns in self.all_patterns.items():
            for pattern in patterns:
                if pattern.search(decoded_path):
                    detected_attacks.append(attack_type)
                    break
        
        # Additional heuristics
        if status in [400, 403, 500]:
            if detected_attacks:
                detected_attacks.append('error_with_attack_pattern')
        
        if len(decoded_path) > 500:
            detected_attacks.append('abnormally_long_path')
        
        is_attack = len(detected_attacks) > 0
        confidence = min(len(detected_attacks) * 0.3 + 0.4, 1.0) if is_attack else 0.0
        
        return {
            'is_attack': is_attack,
            'attack_types': detected_attacks,
            'confidence': confidence
        }


# ============================================================================
# LOG NORMALIZATION
# ============================================================================

class ApacheLogNormalizer:
    """Normalize Apache logs for template extraction"""
    
    def __init__(self):
        self.RE_IPv4 = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
        self.RE_NUM = re.compile(r'(?<![A-Za-z])[-+]?\d+(?:\.\d+)?(?![A-Za-z])')
        self.RE_PATH = re.compile(r'(?:/[^/\s]+)+')
        self.RE_URL = re.compile(r'https?://\S+')
    
    def normalize(self, msg: str) -> str:
        """HTTP-aware normalization preserving attack signatures"""
        if not msg:
            return msg
        
        out = msg
        
        # Replace URLs and IPs
        out = self.RE_URL.sub('<URL>', out)
        out = self.RE_IPv4.sub('<IP>', out)
        
        # Normalize paths while preserving attack patterns
        def normalize_path(match):
            path = match.group(0)
            
            # Preserve attack signatures
            if any(kw in path.lower() for kw in ['select', 'union', 'insert', 'drop', 'delete', '--', 'or 1=1']):
                return path
            if any(kw in path.lower() for kw in ['<script', 'javascript:', 'onerror', 'onload']):
                return path
            if '../' in path or '..\\' in path:
                return path
            if any(kw in path for kw in ['|', ';', '&&', '$(', '`']):
                return path
            
            # Normalize normal paths
            path = re.sub(r'/\d+', '/<NUM>', path)
            path = re.sub(r'/[0-9a-fA-F]{8,}', '/<HEX>', path)
            return path
        
        out = self.RE_PATH.sub(normalize_path, out)
        
        # Bucket numbers by magnitude
        def bucket_number(m):
            s = m.group(0)
            if any(c in s for c in ['=', '<', '>']):
                return s
            try:
                val = float(s) if '.' in s else int(s)
                if val == 0:
                    return '<NUM_E0>'
                mag = int(math.floor(math.log10(abs(val))))
                return f'<NUM_E{mag}>'
            except:
                return '<NUM>'
        
        parts = out.split()
        normalized_parts = []
        for part in parts:
            if self.RE_NUM.fullmatch(part):
                normalized_parts.append(bucket_number(self.RE_NUM.match(part)))
            else:
                normalized_parts.append(part)
        
        out = ' '.join(normalized_parts)
        out = re.sub(r'\s+', ' ', out).strip()
        
        return out


# ============================================================================
# ENSEMBLE DETECTOR
# ============================================================================

class EnsembleAnomalyDetector:
    """
    Real-time ensemble anomaly detector combining:
    - Transformer (sequence-based)
    - Rule-based (pattern matching)
    - Isolation Forest (statistical)
    """
    
    def __init__(self, model_dir: Path, window_size: int = 20, device: str = 'cpu'):
        self.model_dir = Path(model_dir)
        self.window_size = window_size
        self.device = torch.device(device)
        self.normalizer = ApacheLogNormalizer()
        
        # Session windows (keyed by IP or session ID)
        self.session_windows = {}
        
        # Load models
        self._load_models()
    
    def _load_models(self):
        """Load all ensemble components"""
        logger.info("Loading ensemble models...")
        
        # 1. Load vocabulary
        vocab_path = self.model_dir / 'template_vocab.json'
        with open(vocab_path, 'r') as f:
            vocab_data = json.load(f)
        
        if isinstance(vocab_data, dict) and 'template_to_id' in vocab_data:
            self.vocab = vocab_data['template_to_id']
            self.vocab_size = vocab_data['vocab_size']
        else:
            self.vocab = vocab_data
            self.vocab_size = len(vocab_data)
        
        self.pad_id = self.vocab_size  # PAD token
        logger.info(f"Loaded vocabulary: {self.vocab_size:,} templates")
        
        # 2. Load configuration
        config_path = self.model_dir / 'model_config.json'
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        
        self.optimal_threshold = self.config.get('optimal_threshold', 6.5)
        logger.info(f"Loaded config (threshold: {self.optimal_threshold:.4f})")
        
        # 3. Load Transformer
        checkpoint_path = self.model_dir / 'transformer_model.pt'
        checkpoint = torch.load(checkpoint_path, map_location=self.device)
        
        model_cfg = checkpoint.get('model_config', checkpoint.get('config', {}))
        checkpoint_vocab_size = model_cfg.get('vocab_size', self.vocab_size + 1)
        
        self.transformer = TemplateTransformer(
            vocab_size=checkpoint_vocab_size,
            pad_id=checkpoint_vocab_size - 1,
            d_model=model_cfg.get('d_model', 256),
            n_heads=model_cfg.get('n_heads', model_cfg.get('nhead', 8)),
            n_layers=model_cfg.get('n_layers', model_cfg.get('num_layers', 6)),
            ffn_dim=model_cfg.get('ffn_dim', model_cfg.get('dim_feedforward', 1024)),
            max_length=model_cfg.get('max_length', model_cfg.get('max_seq_len', 512)),
            dropout=model_cfg.get('dropout', 0.1)
        ).to(self.device)
        
        self.transformer.load_state_dict(checkpoint['model_state_dict'])
        self.transformer.eval()
        logger.info(f"Loaded Transformer ({sum(p.numel() for p in self.transformer.parameters()):,} params)")
        
        # 4. Load Isolation Forest
        iso_path = self.model_dir / 'isolation_forest.pkl'
        with open(iso_path, 'rb') as f:
            self.iso_forest = pickle.load(f)
        logger.info(f"Loaded Isolation Forest ({self.iso_forest.n_estimators} estimators)")
        
        # 5. Initialize Rule-based detector
        self.rule_detector = RuleBasedDetector()
        logger.info(f"Initialized Rule-based detector")
        
        logger.info("Ensemble model loaded successfully!\n")
    
    def parse_apache_log(self, log_line: str) -> Optional[Dict]:
        """Parse Apache access log line"""
        APACHE_PATTERN = re.compile(
            r'^(?P<ip>\S+) \S+ \S+ '
            r'\[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
            r'(?P<status>\d+) '
            r'(?P<size>\S+)'
        )
        
        match = APACHE_PATTERN.match(log_line.strip())
        if not match:
            return None
        
        d = match.groupdict()
        return {
            'ip': d['ip'],
            'method': d.get('method', 'GET'),
            'path': d.get('path', '/'),
            'protocol': d.get('protocol', 'HTTP/1.1'),
            'status': int(d.get('status', 200)),
            'raw_line': log_line.strip()
        }
    
    def extract_features(self, log_data: Dict, session_stats: Dict) -> np.ndarray:
        """Extract features for Isolation Forest"""
        features = [
            session_stats.get('request_count', 1),
            session_stats.get('error_rate', 0.0),
            session_stats.get('unique_paths', 1),
            session_stats.get('error_count', 0),
            1 if log_data['method'] == 'GET' else 0,
            1 if log_data['method'] == 'POST' else 0,
            1 if log_data['status'] >= 400 else 0,
            len(log_data['path']),
            log_data['path'].count('/'),
            1 if '?' in log_data['path'] else 0,
            0  # time_hour (placeholder)
        ]
        return np.array(features).reshape(1, -1)
    
    def get_template_id(self, log_data: Dict) -> int:
        """Convert log to template ID"""
        message = f"{log_data['method']} {log_data['path']} {log_data['protocol']} {log_data['status']}"
        normalized = self.normalizer.normalize(message)
        return self.vocab.get(normalized, self.pad_id)
    
    def calculate_transformer_score(self, sequence: List[int]) -> float:
        """Calculate anomaly score from transformer (NLL)"""
        if len(sequence) < 2:
            return 0.0
        
        # Pad or truncate to window size
        if len(sequence) < self.window_size:
            sequence = sequence + [self.pad_id] * (self.window_size - len(sequence))
        else:
            sequence = sequence[-self.window_size:]
        
        input_ids = torch.tensor([sequence], dtype=torch.long).to(self.device)
        attention_mask = torch.tensor(
            [[1 if t != self.pad_id else 0 for t in sequence]], 
            dtype=torch.long
        ).to(self.device)
        
        with torch.no_grad():
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
            else:
                return 0.0
    
    def detect(self, log_line: str, session_id: Optional[str] = None) -> Dict:
        """
        Detect anomalies in a single log line
        
        Returns:
            {
                'is_anomaly': bool,
                'anomaly_score': float,
                'rule_based': dict,
                'isolation_forest': dict,
                'transformer': dict,
                'ensemble': dict,
                'log_data': dict
            }
        """
        # Parse log
        log_data = self.parse_apache_log(log_line)
        if not log_data:
            return {
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'error': 'Failed to parse log',
                'rule_based': {'is_attack': False, 'attack_types': [], 'confidence': 0.0},
                'isolation_forest': {'is_anomaly': 0, 'score': 0.0},
                'transformer': {'is_anomaly': 0, 'score': 0.0},
                'ensemble': {'score': 0.0, 'votes': {}, 'weights': {}},
                'log_data': {}
            }
        
        # Use IP as session ID if not provided
        if session_id is None:
            session_id = log_data['ip']
        
        # Initialize session if needed
        if session_id not in self.session_windows:
            self.session_windows[session_id] = {
                'templates': deque(maxlen=self.window_size),
                'request_count': 0,
                'error_count': 0,
                'unique_paths': set()
            }
        
        session = self.session_windows[session_id]
        
        # Update session stats
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
        
        # 1. Rule-based detection
        rule_result = self.rule_detector.detect(
            log_data['path'], 
            log_data['method'], 
            log_data['status']
        )
        
        # 2. Isolation Forest
        features = self.extract_features(log_data, session_stats)
        iso_pred = self.iso_forest.predict(features)[0]
        iso_score = -self.iso_forest.score_samples(features)[0]
        iso_result = {
            'is_anomaly': int(iso_pred == -1),
            'score': float(iso_score)
        }
        
        # 3. Transformer (sequence-based)
        template_id = self.get_template_id(log_data)
        session['templates'].append(template_id)
        
        transformer_score = self.calculate_transformer_score(list(session['templates']))
        transformer_result = {
            'is_anomaly': 1 if transformer_score > self.optimal_threshold else 0,
            'score': float(transformer_score)
        }
        
        # 4. Ensemble voting (weighted)
        votes = []
        weights = []
        
        # Rule-based (high precision)
        if rule_result['is_attack']:
            votes.append(1)
            weights.append(rule_result['confidence'])
        else:
            votes.append(0)
            weights.append(0.3)
        
        # Isolation Forest
        votes.append(iso_result['is_anomaly'])
        weights.append(0.6)
        
        # Transformer
        votes.append(transformer_result['is_anomaly'])
        weights.append(0.7)
        
        total_weight = sum(weights)
        weighted_sum = sum(v * w for v, w in zip(votes, weights))
        ensemble_score = weighted_sum / total_weight
        
        is_anomaly = ensemble_score > 0.5
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': ensemble_score,
            'rule_based': rule_result,
            'isolation_forest': iso_result,
            'transformer': transformer_result,
            'ensemble': {
                'score': ensemble_score,
                'votes': dict(zip(['rule', 'iso', 'transformer'], votes)),
                'weights': dict(zip(['rule', 'iso', 'transformer'], weights))
            },
            'log_data': log_data
        }
    
    def reset_session(self, session_id: str):
        """Reset a specific session"""
        if session_id in self.session_windows:
            del self.session_windows[session_id]
    
    def reset_all_sessions(self):
        """Reset all sessions"""
        self.session_windows.clear()
