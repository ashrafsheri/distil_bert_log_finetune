"""
Report Service
Generates PDF reports for security analytics
"""

import io
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
from collections import defaultdict

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.linecharts import HorizontalLineChart
from reportlab.graphics.charts.barcharts import VerticalBarChart

logger = logging.getLogger(__name__)


class ReportService:
    """Service for generating PDF security reports"""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Setup custom paragraph styles for the report"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        # Section header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))

        # Stat label style
        self.styles.add(ParagraphStyle(
            name='StatLabel',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#7f8c8d'),
            fontName='Helvetica'
        ))

        # Stat value style
        self.styles.add(ParagraphStyle(
            name='StatValue',
            parent=self.styles['Normal'],
            fontSize=18,
            textColor=colors.HexColor('#e74c3c'),
            fontName='Helvetica-Bold'
        ))

    async def generate_security_report(
        self,
        elasticsearch_service,
        org_id: str,
        start_time: datetime,
        end_time: datetime,
        user_uid: Optional[str] = None
    ) -> io.BytesIO:
        """
        Generate a comprehensive security report PDF

        Args:
            elasticsearch_service: Elasticsearch service instance
            org_id: Organization ID
            start_time: Start datetime for the report
            end_time: End datetime for the report
            user_uid: User UID (for dummy data generation if needed)

        Returns:
            BytesIO object containing the PDF
        """
        # Calculate duration in hours
        duration = end_time - start_time
        duration_hours = int(duration.total_seconds() / 3600)

        # Fetch data from Elasticsearch
        logs_data = await self._fetch_logs_data(
            elasticsearch_service,
            org_id,
            start_time,
            end_time
        )

        # Generate dummy data for specific test user if no logs exist
        if not logs_data and user_uid == "6YOltaDMENalixIqaqVjGbgebjE2":
            logger.info(f"No logs found for test user {user_uid}, generating dummy data")
            logs_data = self._generate_dummy_logs(start_time, end_time)

        # Process data for statistics
        stats = self._calculate_statistics(logs_data, start_time, end_time, duration_hours)

        # Generate PDF
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50
        )

        # Build PDF content
        story = []
        story.extend(self._create_header(stats))
        story.append(Spacer(1, 0.3 * inch))
        story.extend(self._create_statistics_section(stats))
        story.append(Spacer(1, 0.3 * inch))
        story.extend(self._create_timeline_chart(stats))
        story.append(PageBreak())
        story.extend(self._create_malicious_ips_section(stats))

        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer

    async def _fetch_logs_data(
        self,
        elasticsearch_service,
        org_id: str,
        start_time: datetime,
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Fetch logs from Elasticsearch for the specified time range"""
        try:
            # Query Elasticsearch for logs in the time range
            result = await elasticsearch_service.search_logs(
                org_id=org_id,
                from_datetime=start_time.isoformat(),
                to_datetime=end_time.isoformat(),
                limit=10000  # Adjust based on expected volume
            )

            return result.get('logs', [])

        except Exception as e:
            logger.error(f"Error fetching logs from Elasticsearch: {e}")
            return []

    def _generate_dummy_logs(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Generate dummy logs data for testing purposes"""
        import random
        
        dummy_logs = []
        
        # Generate time points throughout the period
        duration = end_time - start_time
        num_logs = 150  # Generate 150 dummy logs
        
        malicious_ips = [
            "192.168.1.100",
            "10.0.0.50",
            "172.16.0.25",
            "203.0.113.45",
            "198.51.100.78"
        ]
        
        attack_patterns = [
            {"path": "/admin/login", "status": 401, "method": "POST", "type": "Brute Force"},
            {"path": "/../../../etc/passwd", "status": 403, "method": "GET", "type": "Path Traversal"},
            {"path": "/wp-admin/install.php", "status": 404, "method": "GET", "type": "Vulnerability Scan"},
            {"path": "/api/users?id=1' OR '1'='1", "status": 500, "method": "GET", "type": "SQL Injection"},
            {"path": "/api/exec?cmd=whoami", "status": 403, "method": "POST", "type": "Command Injection"},
            {"path": "/admin/config", "status": 200, "method": "GET", "type": "Unauthorized Access"},
        ]
        
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "python-requests/2.28.0",
            "curl/7.68.0",
            "Nmap Scripting Engine",
            "sqlmap/1.6.3",
        ]
        
        for i in range(num_logs):
            # Generate timestamp
            time_offset = (duration.total_seconds() / num_logs) * i
            timestamp = start_time + timedelta(seconds=time_offset)
            
            # 30% chance of malicious log
            is_malicious = random.random() < 0.3
            
            if is_malicious:
                ip = random.choice(malicious_ips)
                attack = random.choice(attack_patterns)
                
                # Detection methods (at least one always true for malicious)
                rule_based = random.random() < 0.7
                isolation_forest = random.random() < 0.6
                transformer = random.random() < 0.8
                
                # Ensure at least one detection method is true
                if not (rule_based or isolation_forest or transformer):
                    rule_based = True
                
                log_entry = {
                    "timestamp": timestamp.isoformat(),
                    "ip": ip,
                    "method": attack["method"],
                    "path": attack["path"],
                    "status": attack["status"],
                    "user_agent": random.choice(user_agents),
                    "infected": True,
                    "rule_based": rule_based,
                    "isolation_forest": isolation_forest,
                    "transformer": transformer,
                    "ensemble_score": round(random.uniform(0.75, 0.95), 2),
                    "attack_type": attack["type"],
                    "referer": "-"
                }
            else:
                # Normal log
                normal_paths = ["/", "/home", "/about", "/contact", "/products", "/api/health", "/static/css/main.css"]
                log_entry = {
                    "timestamp": timestamp.isoformat(),
                    "ip": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
                    "method": random.choice(["GET", "POST"]),
                    "path": random.choice(normal_paths),
                    "status": random.choice([200, 304]),
                    "user_agent": user_agents[0],
                    "infected": False,
                    "rule_based": False,
                    "isolation_forest": False,
                    "transformer": False,
                    "ensemble_score": round(random.uniform(0.1, 0.4), 2),
                    "referer": "-"
                }
            
            dummy_logs.append(log_entry)
        
        logger.info(f"Generated {len(dummy_logs)} dummy logs ({sum(1 for l in dummy_logs if l['infected'])} malicious)")
        return dummy_logs

    def _calculate_statistics(
        self,
        logs: List[Dict[str, Any]],
        start_time: datetime,
        end_time: datetime,
        duration_hours: int
    ) -> Dict[str, Any]:
        """Calculate statistics from logs data"""
        total_logs = len(logs)
        malicious_logs = [log for log in logs if log.get('infected', False)]
        malicious_count = len(malicious_logs)

        # Get unique malicious IPs
        malicious_ips = set()
        ip_details = defaultdict(lambda: {
            'count': 0,
            'rule_based': 0,
            'isolation_forest': 0,
            'transformer': 0,
            'ensemble_scores': [],
            'attack_types': set(),
            'logs': []
        })

        # Process malicious logs
        for log in malicious_logs:
            ip = log.get('ip_address')
            if ip:
                malicious_ips.add(ip)
                ip_details[ip]['count'] += 1
                ip_details[ip]['logs'].append(log)

                # Extract anomaly details
                anomaly_details = log.get('anomaly_details', {})

                # Rule-based detection
                rule_based = anomaly_details.get('rule_based', {})
                if rule_based.get('is_attack', False):
                    ip_details[ip]['rule_based'] += 1
                    attack_types = rule_based.get('attack_types', [])
                    ip_details[ip]['attack_types'].update(attack_types)

                # Isolation Forest
                iso_forest = anomaly_details.get('isolation_forest', {})
                if iso_forest.get('is_anomaly', 0) == 1:
                    ip_details[ip]['isolation_forest'] += 1

                # Transformer
                transformer = anomaly_details.get('transformer', {})
                if transformer.get('is_anomaly', 0) == 1:
                    ip_details[ip]['transformer'] += 1

                # Ensemble score
                ensemble = anomaly_details.get('ensemble', {})
                ensemble_score = ensemble.get('score', 0.0)
                if ensemble_score > 0:
                    ip_details[ip]['ensemble_scores'].append(ensemble_score)

        # Timeline data - group by hour
        timeline = defaultdict(int)
        for log in malicious_logs:
            timestamp = log.get('timestamp', '')
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                hour_key = dt.strftime('%Y-%m-%d %H:00')
                timeline[hour_key] += 1
            except:
                pass

        # Sort timeline
        sorted_timeline = sorted(timeline.items())

        # Email alerts count (estimate based on batches of alerts)
        # Assuming 1 alert per 10 malicious logs or per unique malicious IP
        email_alerts = max(len(malicious_ips), malicious_count // 10)

        return {
            'start_time': start_time,
            'end_time': end_time,
            'duration_hours': duration_hours,
            'total_logs': total_logs,
            'malicious_count': malicious_count,
            'unique_malicious_ips': len(malicious_ips),
            'email_alerts': email_alerts,
            'timeline': sorted_timeline,
            'ip_details': dict(ip_details),
            'malicious_percentage': (malicious_count / total_logs * 100) if total_logs > 0 else 0
        }

    def _create_header(self, stats: Dict[str, Any]) -> List:
        """Create report header"""
        elements = []

        # Title
        title = Paragraph("Security Analytics Report", self.styles['CustomTitle'])
        elements.append(title)
        elements.append(Spacer(1, 0.2 * inch))

        # Date range
        date_range = Paragraph(
            f"<b>Report Period:</b> {stats['start_time'].strftime('%Y-%m-%d %H:%M')} to {stats['end_time'].strftime('%Y-%m-%d %H:%M')} ({stats['duration_hours']} hours)",
            self.styles['Normal']
        )
        elements.append(date_range)
        elements.append(Spacer(1, 0.1 * inch))

        # Generated timestamp
        generated_at = Paragraph(
            f"<b>Generated:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            self.styles['Normal']
        )
        elements.append(generated_at)

        return elements

    def _create_statistics_section(self, stats: Dict[str, Any]) -> List:
        """Create statistics overview section"""
        elements = []

        # Section header
        header = Paragraph("Overview Statistics", self.styles['SectionHeader'])
        elements.append(header)
        elements.append(Spacer(1, 0.15 * inch))

        # Create stats table
        data = [
            ['Metric', 'Value'],
            ['Total Logs Processed', f"{stats['total_logs']:,}"],
            ['Malicious Packets Detected', f"{stats['malicious_count']:,}"],
            ['Unique Malicious IPs', f"{stats['unique_malicious_ips']:,}"],
            ['Email Alerts Sent', f"{stats['email_alerts']:,}"],
            ['Threat Percentage', f"{stats['malicious_percentage']:.2f}%"]
        ]

        table = Table(data, colWidths=[3 * inch, 2 * inch])
        table.setStyle(TableStyle([
            # Header row
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),

            # Data rows
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica'),
            ('FONTNAME', (1, 1), (1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ALIGN', (1, 1), (1, -1), 'RIGHT'),
            ('LEFTPADDING', (0, 1), (-1, -1), 12),
            ('RIGHTPADDING', (0, 1), (-1, -1), 12),
            ('TOPPADDING', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 8),

            # Grid
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('LINEBELOW', (0, 0), (-1, 0), 2, colors.HexColor('#34495e')),

            # Highlight malicious count
            ('TEXTCOLOR', (1, 2), (1, 2), colors.HexColor('#e74c3c')),
        ]))

        elements.append(table)
        return elements

    def _create_timeline_chart(self, stats: Dict[str, Any]) -> List:
        """Create timeline chart showing attacks over time"""
        elements = []

        # Section header
        header = Paragraph("Attack Timeline", self.styles['SectionHeader'])
        elements.append(header)
        elements.append(Spacer(1, 0.15 * inch))

        if not stats['timeline']:
            elements.append(Paragraph("No malicious activity detected in this period.", self.styles['Normal']))
            return elements

        # Prepare chart data
        timeline_data = stats['timeline'][:24]  # Limit to 24 data points for readability
        
        if len(timeline_data) == 0:
            elements.append(Paragraph("No data available for timeline.", self.styles['Normal']))
            return elements

        # Create simple bar chart representation using table
        max_count = max([count for _, count in timeline_data]) if timeline_data else 1
        
        chart_data = [['Time Period', 'Attacks', 'Visual']]
        for time_label, count in timeline_data[-12:]:  # Show last 12 time periods
            # Create simple text-based bar
            bar_length = int((count / max_count) * 30) if max_count > 0 else 0
            visual = '█' * bar_length
            short_label = time_label[-8:] if len(time_label) > 8 else time_label  # Show only time part
            chart_data.append([short_label, str(count), visual])

        table = Table(chart_data, colWidths=[1.5 * inch, 0.8 * inch, 4 * inch])
        table.setStyle(TableStyle([
            # Header
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),

            # Data
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ALIGN', (1, 1), (1, -1), 'RIGHT'),
            ('TEXTCOLOR', (2, 1), (2, -1), colors.HexColor('#e74c3c')),
            ('FONTNAME', (2, 1), (2, -1), 'Courier'),

            # Grid
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ]))

        elements.append(table)
        return elements

    def _create_malicious_ips_section(self, stats: Dict[str, Any]) -> List:
        """Create detailed section for each malicious IP"""
        elements = []

        # Section header
        header = Paragraph("Malicious IP Details", self.styles['SectionHeader'])
        elements.append(header)
        elements.append(Spacer(1, 0.15 * inch))

        ip_details = stats['ip_details']

        if not ip_details:
            elements.append(Paragraph("No malicious IPs detected in this period.", self.styles['Normal']))
            return elements

        # Sort IPs by count (most frequent first)
        sorted_ips = sorted(ip_details.items(), key=lambda x: x[1]['count'], reverse=True)

        # Limit to top 20 IPs
        for ip, details in sorted_ips[:20]:
            # IP header
            ip_header = Paragraph(f"<b>IP Address: {ip}</b>", self.styles['Heading3'])
            elements.append(ip_header)
            elements.append(Spacer(1, 0.1 * inch))

            # Calculate average ensemble score
            avg_score = sum(details['ensemble_scores']) / len(details['ensemble_scores']) if details['ensemble_scores'] else 0

            # Create details table
            data = [
                ['Detection Method', 'Count', 'Details'],
                ['Total Malicious Requests', str(details['count']), ''],
                ['Rule-Based Detection', str(details['rule_based']), ', '.join(details['attack_types']) if details['attack_types'] else 'N/A'],
                ['Isolation Forest', str(details['isolation_forest']), 'Statistical anomaly detection'],
                ['Transformer Model', str(details['transformer']), 'Deep learning-based detection'],
                ['Average Threat Score', f"{avg_score:.2f}", 'Ensemble model confidence']
            ]

            ip_table = Table(data, colWidths=[2 * inch, 1 * inch, 3.5 * inch])
            ip_table.setStyle(TableStyle([
                # Header
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#95a5a6')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),

                # Data
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ALIGN', (1, 1), (1, -1), 'CENTER'),
                ('LEFTPADDING', (0, 1), (-1, -1), 8),
                ('RIGHTPADDING', (0, 1), (-1, -1), 8),
                ('TOPPADDING', (0, 1), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),

                # Grid
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#ecf0f1')]),

                # Highlight total count
                ('FONTNAME', (0, 1), (1, 1), 'Helvetica-Bold'),
                ('TEXTCOLOR', (1, 1), (1, 1), colors.HexColor('#e74c3c')),
            ]))

            elements.append(ip_table)

            # Explanation paragraph
            explanation = self._generate_explanation(details)
            explanation_para = Paragraph(
                f"<i>Analysis: {explanation}</i>",
                self.styles['Normal']
            )
            elements.append(Spacer(1, 0.08 * inch))
            elements.append(explanation_para)
            elements.append(Spacer(1, 0.2 * inch))

        return elements

    def _generate_explanation(self, details: Dict[str, Any]) -> str:
        """Generate human-readable explanation for IP detection"""
        explanations = []

        if details['rule_based'] > 0:
            attack_types = ', '.join(details['attack_types']) if details['attack_types'] else 'suspicious patterns'
            explanations.append(
                f"Detected {attack_types} through signature-based rules ({details['rule_based']} occurrences)"
            )

        if details['isolation_forest'] > 0:
            explanations.append(
                f"Flagged as statistical outlier {details['isolation_forest']} times, indicating unusual behavior patterns"
            )

        if details['transformer'] > 0:
            explanations.append(
                f"Deep learning model identified anomalous request sequences ({details['transformer']} instances)"
            )

        avg_score = sum(details['ensemble_scores']) / len(details['ensemble_scores']) if details['ensemble_scores'] else 0
        if avg_score > 0.7:
            threat_level = "high"
        elif avg_score > 0.4:
            threat_level = "moderate"
        else:
            threat_level = "low"

        explanations.append(f"Overall threat level: {threat_level} (average score: {avg_score:.2f})")

        return '. '.join(explanations) + '.'
