#!/usr/bin/env python3
"""
Threat Intelligence Updater Service
Periodically updates threat intelligence feeds and IP reputation data
"""

import os
import sys
import time
import json
import logging
import schedule
import requests
import redis
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
import yaml


class ThreatIntelligenceService:
    def __init__(self):
        self.setup_logging()
        self.setup_redis()
        self.load_config()
        self.setup_feeds()
        
    def setup_logging(self):
        """Configure logging"""
        log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('/var/log/threat_intel/threat_intel.log')
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def setup_redis(self):
        """Setup Redis connection"""
        try:
            self.redis_client = redis.Redis(
                host=os.getenv('REDIS_HOST', 'session_store'),
                port=int(os.getenv('REDIS_PORT', 6379)),
                password=os.getenv('REDIS_PASSWORD'),
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True
            )
            # Test connection
            self.redis_client.ping()
            self.logger.info("Connected to Redis successfully")
        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {e}")
            sys.exit(1)
            
    def load_config(self):
        """Load configuration"""
        self.config = {
            'update_interval': int(os.getenv('UPDATE_INTERVAL', 3600)),
            'feeds': {
                'ipsum': {
                    'url': 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
                    'enabled': True,
                    'score': 80,
                    'description': 'Malicious IPs from ipsum feed'
                },
                'feodo': {
                    'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
                    'enabled': True,
                    'score': 90,
                    'description': 'Feodo Tracker botnet IPs'
                },
                'sslbl': {
                    'url': 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
                    'enabled': True,
                    'score': 85,
                    'description': 'SSL Blacklist malicious IPs'
                },
                'blocklist_de': {
                    'url': 'https://lists.blocklist.de/lists/all.txt',
                    'enabled': True,
                    'score': 70,
                    'description': 'Blocklist.de attack IPs'
                }
            },
            'whitelist': [
                '127.0.0.0/8',
                '10.0.0.0/8',
                '172.16.0.0/12',
                '192.168.0.0/16',
                '169.254.0.0/16',
                '100.64.0.0/10'  # Tailscale
            ]
        }
        
    def setup_feeds(self):
        """Initialize threat intelligence feeds"""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'HoneypotIDS-ThreatIntel/1.0'
        })
        
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private ranges"""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.config['whitelist']:
                if ip_obj in ipaddress.ip_network(network):
                    return True
            return False
        except:
            return False
            
    def fetch_feed(self, feed_name: str, feed_config: Dict) -> Set[str]:
        """Fetch IPs from a threat intelligence feed"""
        try:
            self.logger.info(f"Fetching {feed_name} feed from {feed_config['url']}")
            response = self.session.get(feed_config['url'], timeout=30)
            response.raise_for_status()
            
            ips = set()
            for line in response.text.splitlines():
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#') or line.startswith(';'):
                    continue
                    
                # Extract IP from various formats
                ip = self.extract_ip_from_line(line)
                if ip and not self.is_private_ip(ip):
                    ips.add(ip)
                    
            self.logger.info(f"Fetched {len(ips)} IPs from {feed_name}")
            return ips
            
        except Exception as e:
            self.logger.error(f"Failed to fetch {feed_name} feed: {e}")
            return set()
            
    def extract_ip_from_line(self, line: str) -> Optional[str]:
        """Extract IP address from feed line"""
        import re
        
        # Common IP regex pattern
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        # Try to find IP in the line
        match = re.search(ip_pattern, line)
        if match:
            ip = match.group()
            # Basic validation
            parts = ip.split('.')
            if len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts):
                return ip
        return None
        
    def update_threat_ips(self):
        """Update threat IP database"""
        self.logger.info("Starting threat IP update")
        
        # Get existing threat data
        try:
            existing_data = self.redis_client.get('threat_ips')
            threat_ips = json.loads(existing_data) if existing_data else {}
        except:
            threat_ips = {}
            
        # Track statistics
        stats = {
            'feeds_processed': 0,
            'new_ips': 0,
            'updated_ips': 0,
            'total_ips': len(threat_ips)
        }
        
        # Process each enabled feed
        for feed_name, feed_config in self.config['feeds'].items():
            if not feed_config.get('enabled', False):
                continue
                
            feed_ips = self.fetch_feed(feed_name, feed_config)
            stats['feeds_processed'] += 1
            
            # Update threat database
            for ip in feed_ips:
                if ip in threat_ips:
                    # Update existing entry
                    threat_ips[ip]['score'] = max(
                        threat_ips[ip].get('score', 0),
                        feed_config['score']
                    )
                    threat_ips[ip]['feeds'].append(feed_name)
                    threat_ips[ip]['feeds'] = list(set(threat_ips[ip]['feeds']))
                    threat_ips[ip]['updated'] = int(time.time())
                    stats['updated_ips'] += 1
                else:
                    # Add new entry
                    threat_ips[ip] = {
                        'score': feed_config['score'],
                        'reason': f"{feed_name}_feed",
                        'feeds': [feed_name],
                        'updated': int(time.time()),
                        'first_seen': int(time.time()),
                        'description': feed_config['description']
                    }
                    stats['new_ips'] += 1
                    
        # Clean old entries (older than 30 days)
        cutoff_time = int(time.time()) - (30 * 24 * 60 * 60)
        old_ips = [ip for ip, data in threat_ips.items() 
                  if data.get('updated', 0) < cutoff_time]
        
        for ip in old_ips:
            del threat_ips[ip]
            
        stats['removed_old'] = len(old_ips)
        stats['final_total'] = len(threat_ips)
        
        # Store updated data
        self.redis_client.set('threat_ips', json.dumps(threat_ips))
        
        # Store statistics
        stats['last_update'] = int(time.time())
        self.redis_client.set('threat_intel_stats', json.dumps(stats))
        
        self.logger.info(f"Threat IP update completed: {stats}")
        
    def update_user_agents(self):
        """Update malicious user agent patterns"""
        self.logger.info("Updating malicious user agent patterns")
        
        # Known malicious user agents and scanners
        malicious_agents = [
            # Vulnerability scanners
            'sqlmap', 'nmap', 'masscan', 'zap', 'nikto', 'dirb', 'gobuster',
            'wpscan', 'whatweb', 'nuclei', 'burpsuite', 'havij', 'pangolin',
            'acunetix', 'nessus', 'openvas', 'w3af', 'skipfish',
            
            # Attack tools
            'metasploit', 'msfconsole', 'exploit', 'payload', 'shellshock',
            'beef', 'xsshunter', 'commix', 'sqlninja',
            
            # Automated tools
            'python-requests', 'curl', 'wget', 'lwp-', 'libwww',
            'httpie', 'requests/', 'urllib',
            
            # Suspicious patterns
            'scanner', 'crawl', 'spider', 'bot', 'scraper',
            'test', 'check', 'probe', 'enum',
            
            # Specific malware
            'mirai', 'tsunami', 'gafgyt', 'bashlite'
        ]
        
        # Store in Redis
        self.redis_client.set('malicious_agents', json.dumps(malicious_agents))
        
        self.logger.info(f"Updated {len(malicious_agents)} malicious user agent patterns")
        
    def update_attack_patterns(self):
        """Update attack pattern signatures"""
        self.logger.info("Updating attack patterns")
        
        attack_patterns = {
            'sql_injection': [
                r"union.*select", r"or.*1.*=.*1", r"'.*or.*'",
                r"select.*from", r"drop.*table", r"insert.*into",
                r"update.*set", r"delete.*from", r"information_schema",
                r"concat\s*\(", r"substring\s*\(", r"database\s*\(",
                r"version\s*\(", r"user\s*\(", r"sleep\s*\(",
                r"waitfor\s+delay", r"benchmark\s*\("
            ],
            'xss': [
                r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
                r"onmouseover\s*=", r"onfocus\s*=", r"onblur\s*=",
                r"alert\s*\(", r"prompt\s*\(", r"confirm\s*\(",
                r"document\.cookie", r"document\.location",
                r"window\.location", r"eval\s*\("
            ],
            'command_injection': [
                r";.*cat", r";.*ls", r";.*ps", r";.*id", r";.*whoami",
                r";.*uname", r"\|.*nc", r"\|.*netcat", r"&&.*curl",
                r"&&.*wget", r"`.*`", r"\$\(.*\)", r"system\s*\(",
                r"exec\s*\(", r"passthru\s*\(", r"shell_exec\s*\("
            ],
            'directory_traversal': [
                r"\.\./", r"%2e%2e/", r"\.\.\\", r"%2e%2e%5c",
                r"\.\.%2f", r"%2e%2e%2f", r"\.\.%5c", r"%2e%2e%5c"
            ],
            'file_inclusion': [
                r"php://", r"file://", r"data://", r"zip://",
                r"phar://", r"expect://", r"input://", r"filter://"
            ]
        }
        
        # Store patterns in Redis
        self.redis_client.set('attack_patterns', json.dumps(attack_patterns))
        
        total_patterns = sum(len(patterns) for patterns in attack_patterns.values())
        self.logger.info(f"Updated {total_patterns} attack patterns across {len(attack_patterns)} categories")
        
    def update_vulnerability_signatures(self):
        """Update vulnerability signatures for CVE detection"""
        self.logger.info("Updating vulnerability signatures")
        
        cve_signatures = {
            'CVE-2023-28121': {
                'headers': ['X-WCPAY-PLATFORM-CHECKOUT-USER'],
                'uri_patterns': ['wp/v2/users'],
                'severity': 'HIGH',
                'description': 'WooCommerce Payments unauthorized admin access'
            },
            'CVE-2023-2986': {
                'uri_patterns': ['wcal_action=checkout_link', 'validate='],
                'severity': 'HIGH',
                'description': 'Abandoned Cart Lite hardcoded encryption key'
            },
            'CVE-2025-4403': {
                'uri_patterns': ['dnd_codedropz_upload', 'supported_type'],
                'severity': 'CRITICAL',
                'description': 'Drag and Drop file upload type control'
            },
            'CVE-2025-2266': {
                'uri_patterns': ['cwmpUpdateOptions'],
                'severity': 'CRITICAL',
                'description': 'Unauthenticated WordPress options update'
            },
            'CVE-2025-47577': {
                'uri_patterns': ['mwb_wgm_preview_mail'],
                'severity': 'CRITICAL',
                'description': 'Gift Voucher file upload RCE'
            },
            'CVE-2024-8425': {
                'uri_patterns': ['mwb_wgm_preview_mail'],
                'severity': 'CRITICAL',
                'description': 'Gift Voucher file upload RCE variant'
            },
            'CVE-2024-2387': {
                'uri_patterns': ['advanced-form-integration-log', 'integration_id'],
                'severity': 'HIGH',
                'description': 'Advanced Form Integration SQL injection'
            },
            'CVE-2025-10142': {
                'uri_patterns': ['pc_added_uploaded_image', 'file[path]'],
                'severity': 'HIGH',
                'description': 'PagSeguro Connect file path traversal'
            },
            'CVE-2024-50508': {
                'uri_patterns': ['file[path]'],
                'severity': 'HIGH',
                'description': 'WordPress file upload directory traversal'
            }
        }
        
        # Store signatures in Redis
        self.redis_client.set('cve_signatures', json.dumps(cve_signatures))
        
        self.logger.info(f"Updated {len(cve_signatures)} CVE signatures")
        
    def update_geolocation_data(self):
        """Update geolocation threat data"""
        self.logger.info("Updating geolocation threat data")
        
        # High-risk countries/regions based on common attack sources
        high_risk_locations = {
            'countries': ['CN', 'RU', 'KP', 'IR', 'PK'],
            'regions': ['TOR', 'VPN', 'PROXY'],
            'asn_ranges': [
                # Known hosting/VPS providers commonly used by attackers
                'AS13335',  # Cloudflare
                'AS16509',  # Amazon
                'AS14061',  # DigitalOcean
                'AS20473'   # Choopa/Vultr
            ]
        }
        
        # Store in Redis
        self.redis_client.set('geo_threat_data', json.dumps(high_risk_locations))
        
        self.logger.info("Geolocation threat data updated")
        
    def update_honeypot_intelligence(self):
        """Update honeypot-specific intelligence"""
        self.logger.info("Updating honeypot intelligence")
        
        # WordPress-specific attack indicators
        wordpress_intel = {
            'vulnerable_plugins': [
                'woocommerce-payments', 'abandoned-cart-lite',
                'drag-and-drop-multiple-file-upload', 'cwmp',
                'gift-voucher', 'advanced-form-integration',
                'pagseguro-connect-woocommerce', 'wp-file-upload'
            ],
            'common_attack_paths': [
                '/wp-admin/', '/wp-login.php', '/wp-config.php',
                '/xmlrpc.php', '/wp-json/', '/wp-content/',
                '/wp-includes/', '/readme.html', '/license.txt'
            ],
            'enumeration_endpoints': [
                '/wp-json/wp/v2/users', '/?author=1',
                '/wp-admin/admin-ajax.php', '/feed/',
                '/comments/feed/', '/wp-sitemap.xml'
            ],
            'brute_force_indicators': [
                'wp-login.php', 'xmlrpc.php', 'admin-ajax.php'
            ]
        }
        
        # Store in Redis
        self.redis_client.set('wordpress_intel', json.dumps(wordpress_intel))
        
        self.logger.info("Honeypot intelligence updated")
        
    def generate_threat_report(self):
        """Generate threat intelligence summary report"""
        self.logger.info("Generating threat intelligence report")
        
        try:
            # Get current data
            threat_ips_data = self.redis_client.get('threat_ips')
            stats_data = self.redis_client.get('threat_intel_stats')
            
            threat_ips = json.loads(threat_ips_data) if threat_ips_data else {}
            stats = json.loads(stats_data) if stats_data else {}
            
            # Generate report
            report = {
                'timestamp': int(time.time()),
                'summary': {
                    'total_threat_ips': len(threat_ips),
                    'feeds_processed': stats.get('feeds_processed', 0),
                    'last_update': stats.get('last_update', 0),
                    'new_ips_added': stats.get('new_ips', 0),
                    'updated_ips': stats.get('updated_ips', 0)
                },
                'top_threat_sources': {},
                'severity_breakdown': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0
                }
            }
            
            # Analyze threat data
            feed_counts = {}
            for ip, data in threat_ips.items():
                score = data.get('score', 0)
                feeds = data.get('feeds', [])
                
                # Count by feed source
                for feed in feeds:
                    feed_counts[feed] = feed_counts.get(feed, 0) + 1
                    
                # Categorize by severity
                if score >= 90:
                    report['severity_breakdown']['critical'] += 1
                elif score >= 70:
                    report['severity_breakdown']['high'] += 1
                elif score >= 50:
                    report['severity_breakdown']['medium'] += 1
                else:
                    report['severity_breakdown']['low'] += 1
                    
            report['top_threat_sources'] = dict(
                sorted(feed_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            )
            
            # Store report
            self.redis_client.set('threat_intel_report', json.dumps(report))
            
            self.logger.info(f"Threat intelligence report generated: {report['summary']}")
            
        except Exception as e:
            self.logger.error(f"Failed to generate threat report: {e}")
            
    def run_full_update(self):
        """Run complete threat intelligence update"""
        self.logger.info("Starting full threat intelligence update")
        
        try:
            # Update all components
            self.update_threat_ips()
            self.update_user_agents()
            self.update_attack_patterns()
            self.update_vulnerability_signatures()
            self.update_geolocation_data()
            self.update_honeypot_intelligence()
            self.generate_threat_report()
            
            # Update last run timestamp
            self.redis_client.set('threat_intel_last_run', int(time.time()))
            
            self.logger.info("Full threat intelligence update completed successfully")
            
        except Exception as e:
            self.logger.error(f"Threat intelligence update failed: {e}")
            
    def health_check(self):
        """Perform health check"""
        try:
            # Check Redis connectivity
            self.redis_client.ping()
            
            # Check last update time
            last_run = self.redis_client.get('threat_intel_last_run')
            if last_run:
                last_run_time = int(last_run)
                time_since_update = int(time.time()) - last_run_time
                
                # Alert if no update in last 2 hours
                if time_since_update > 7200:
                    self.logger.warning(f"Last update was {time_since_update} seconds ago")
                    return False
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False
            
    def run_scheduler(self):
        """Run the threat intelligence update scheduler"""
        self.logger.info("Starting threat intelligence scheduler")
        
        # Schedule regular updates
        update_interval = self.config.get('update_interval', 3600)
        schedule.every(update_interval).seconds.do(self.run_full_update)
        
        # Schedule health checks every 15 minutes
        schedule.every(15).minutes.do(self.health_check)
        
        # Run initial update
        self.run_full_update()
        
        # Keep running
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
            
    def run_once(self):
        """Run threat intelligence update once and exit"""
        self.logger.info("Running single threat intelligence update")
        self.run_full_update()


def main():
    """Main entry point"""
    service = ThreatIntelligenceService()
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == '--once':
            service.run_once()
        elif sys.argv[1] == '--health':
            if service.health_check():
                print("Service is healthy")
                sys.exit(0)
            else:
                print("Service is unhealthy")
                sys.exit(1)
        else:
            print("Usage: threat_intel.py [--once|--health]")
            sys.exit(1)
    else:
        # Run scheduler (default)
        service.run_scheduler()


if __name__ == "__main__":
    main()