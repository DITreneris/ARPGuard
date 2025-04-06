import requests
import json
import time
import threading
import ipaddress
import re
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Set, Tuple
import logging
from urllib.parse import urlparse

from app.utils.logger import get_logger

# Module logger
logger = get_logger('components.threat_intelligence')

class ThreatIntelligence:
    """Cloud-based threat intelligence integration module.
    
    This module integrates with external threat intelligence sources to provide
    enhanced detection of threats, malicious IPs, and known attack patterns.
    """
    
    def __init__(self):
        """Initialize the threat intelligence component."""
        self.running = False
        self.update_thread = None
        self.callback = None
        
        # Store threat data
        self.malicious_ips = {}  # IP -> {score, categories, source, last_updated}
        self.malicious_domains = {}  # Domain -> {score, categories, source, last_updated}
        self.attack_signatures = {}  # Signature ID -> {pattern, description, severity, source}
        
        # API configuration - would typically be loaded from config
        self.api_keys = {}
        self.load_api_keys()
        
        # Data update frequency (in seconds)
        self.update_interval = 3600  # 1 hour
        
        # Last update timestamp
        self.last_update = None
    
    def load_api_keys(self):
        """Load API keys from environment variables or config file."""
        # Try to load from environment variables first
        self.api_keys['abuseipdb'] = os.environ.get('ABUSEIPDB_API_KEY', '')
        self.api_keys['virustotal'] = os.environ.get('VIRUSTOTAL_API_KEY', '')
        self.api_keys['otx'] = os.environ.get('OTX_API_KEY', '')
        
        # If keys are not in env vars, try to load from config file
        if not any(self.api_keys.values()):
            try:
                config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'api_keys.json')
                if os.path.exists(config_path):
                    with open(config_path, 'r') as f:
                        self.api_keys.update(json.load(f))
            except Exception as e:
                logger.error(f"Error loading API keys from config: {e}")
    
    def start_updates(self, callback: Optional[Callable[[bool, str, Dict[str, Any]], None]] = None) -> bool:
        """Start the threat intelligence update process.
        
        Args:
            callback: Function to call with update status
                callback(success, message, details)
                
        Returns:
            bool: True if the update process was started successfully
        """
        if self.running:
            logger.warning("Threat intelligence updates already running")
            return False
        
        self.callback = callback
        self.running = True
        
        # Start update thread
        self.update_thread = threading.Thread(target=self._update_loop)
        self.update_thread.daemon = True
        self.update_thread.start()
        
        logger.info("Threat intelligence updates started")
        return True
    
    def stop_updates(self) -> bool:
        """Stop the threat intelligence update process.
        
        Returns:
            bool: True if the update process was stopped successfully
        """
        if not self.running:
            logger.warning("Threat intelligence updates not running")
            return False
        
        self.running = False
        
        # Wait for thread to terminate
        if self.update_thread and self.update_thread.is_alive():
            self.update_thread.join(timeout=2.0)
        
        logger.info("Threat intelligence updates stopped")
        return True
    
    def _update_loop(self):
        """Background thread for periodic updates of threat intelligence data."""
        while self.running:
            try:
                # Perform the update
                success, message, details = self.update_all()
                
                # Notify via callback
                if self.callback:
                    self.callback(success, message, details)
                
                # Sleep until next update time
                for _ in range(int(self.update_interval / 5)):  # Check stopping condition every 5 seconds
                    if not self.running:
                        break
                    time.sleep(5)
                    
            except Exception as e:
                logger.error(f"Error in threat intelligence update loop: {e}")
                if self.callback:
                    self.callback(False, f"Error in threat intelligence update: {e}", {})
                time.sleep(60)  # Shorter sleep after error
    
    def update_all(self) -> Tuple[bool, str, Dict[str, Any]]:
        """Update all threat intelligence data.
        
        Returns:
            Tuple[bool, str, Dict[str, Any]]: (success, message, details)
        """
        start_time = datetime.now()
        update_stats = {
            'malicious_ips_updated': 0,
            'malicious_domains_updated': 0,
            'attack_signatures_updated': 0,
            'sources_successful': [],
            'sources_failed': []
        }
        
        # Update from each source
        sources = [
            ('abuseipdb', self._update_from_abuseipdb),
            ('virustotal', self._update_from_virustotal),
            ('otx', self._update_from_otx),
            ('emergingthreats', self._update_from_emerging_threats)
        ]
        
        success_count = 0
        for source_name, update_func in sources:
            try:
                source_success, source_stats = update_func()
                if source_success:
                    success_count += 1
                    update_stats['sources_successful'].append(source_name)
                    # Merge source-specific stats
                    for key, value in source_stats.items():
                        if key in update_stats and isinstance(value, int):
                            update_stats[key] += value
                else:
                    update_stats['sources_failed'].append(source_name)
            except Exception as e:
                logger.error(f"Error updating from {source_name}: {e}")
                update_stats['sources_failed'].append(source_name)
        
        # Update last update timestamp
        self.last_update = datetime.now()
        update_stats['update_duration'] = (self.last_update - start_time).total_seconds()
        
        # Determine overall success
        success = len(update_stats['sources_successful']) > 0
        
        if success:
            message = f"Updated threat intelligence data from {len(update_stats['sources_successful'])} sources"
            logger.info(message)
        else:
            message = "Failed to update threat intelligence data from any source"
            logger.error(message)
        
        return success, message, update_stats
    
    def _update_from_abuseipdb(self) -> Tuple[bool, Dict[str, Any]]:
        """Update threat data from AbuseIPDB.
        
        Returns:
            Tuple[bool, Dict[str, Any]]: (success, update_stats)
        """
        api_key = self.api_keys.get('abuseipdb')
        if not api_key:
            logger.warning("No API key for AbuseIPDB")
            return False, {}
        
        stats = {'malicious_ips_updated': 0}
        
        try:
            # AbuseIPDB blacklist endpoint
            url = "https://api.abuseipdb.com/api/v2/blacklist"
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            params = {
                'confidenceMinimum': 90,  # Only high confidence matches
                'limit': 1000  # Max IPs to retrieve
            }
            
            response = requests.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    ip = item.get('ipAddress')
                    if ip:
                        self.malicious_ips[ip] = {
                            'score': item.get('abuseConfidenceScore', 0),
                            'categories': item.get('categories', []),
                            'source': 'abuseipdb',
                            'last_updated': datetime.now()
                        }
                        stats['malicious_ips_updated'] += 1
                
                logger.info(f"Updated {stats['malicious_ips_updated']} IPs from AbuseIPDB")
                return True, stats
            else:
                logger.error(f"Error from AbuseIPDB API: {response.status_code} - {response.text}")
                return False, stats
                
        except Exception as e:
            logger.error(f"Error updating from AbuseIPDB: {e}")
            return False, stats
    
    def _update_from_virustotal(self) -> Tuple[bool, Dict[str, Any]]:
        """Update threat data from VirusTotal.
        
        Returns:
            Tuple[bool, Dict[str, Any]]: (success, update_stats)
        """
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            logger.warning("No API key for VirusTotal")
            return False, {}
        
        stats = {
            'malicious_ips_updated': 0,
            'malicious_domains_updated': 0
        }
        
        # In a real implementation, this would query the VirusTotal API for 
        # recently detected malicious URLs or IPs. For this example, we'll 
        # just add some sample data.
        
        # Simulate VirusTotal data
        sample_data = [
            {'type': 'ip', 'indicator': '45.235.101.89', 'score': 85, 'categories': ['malware_host']},
            {'type': 'ip', 'indicator': '185.220.100.252', 'score': 95, 'categories': ['tor_exit_node']},
            {'type': 'domain', 'indicator': 'malicious-site.com', 'score': 90, 'categories': ['phishing']},
            {'type': 'domain', 'indicator': 'fake-bank.org', 'score': 95, 'categories': ['phishing']}
        ]
        
        for item in sample_data:
            if item['type'] == 'ip':
                self.malicious_ips[item['indicator']] = {
                    'score': item['score'],
                    'categories': item['categories'],
                    'source': 'virustotal',
                    'last_updated': datetime.now()
                }
                stats['malicious_ips_updated'] += 1
            elif item['type'] == 'domain':
                self.malicious_domains[item['indicator']] = {
                    'score': item['score'],
                    'categories': item['categories'],
                    'source': 'virustotal',
                    'last_updated': datetime.now()
                }
                stats['malicious_domains_updated'] += 1
        
        logger.info(f"Updated {stats['malicious_ips_updated']} IPs and {stats['malicious_domains_updated']} domains from VirusTotal (simulated)")
        return True, stats
    
    def _update_from_otx(self) -> Tuple[bool, Dict[str, Any]]:
        """Update threat data from AlienVault OTX.
        
        Returns:
            Tuple[bool, Dict[str, Any]]: (success, update_stats)
        """
        api_key = self.api_keys.get('otx')
        if not api_key:
            logger.warning("No API key for AlienVault OTX")
            return False, {}
        
        stats = {
            'malicious_ips_updated': 0,
            'malicious_domains_updated': 0,
            'attack_signatures_updated': 0
        }
        
        # In a real implementation, this would query the OTX API for 
        # pulse indicators. For this example, we'll just add some sample data.
        
        # Simulate OTX data
        sample_ips = [
            {'indicator': '93.184.220.29', 'score': 80, 'categories': ['c2', 'bot']},
            {'indicator': '45.227.253.91', 'score': 75, 'categories': ['scanner']}
        ]
        
        sample_domains = [
            {'indicator': 'evil-tracker.net', 'score': 85, 'categories': ['malware']},
            {'indicator': 'malware-delivery.com', 'score': 90, 'categories': ['malware']}
        ]
        
        sample_signatures = [
            {
                'id': 'otx-1001',
                'pattern': r'POST \/admin\/config\.php',
                'description': 'Attempted admin access to PHP configuration',
                'severity': 'high'
            },
            {
                'id': 'otx-1002',
                'pattern': r'\\x00\\x00\\x00\\x45\\xff\\x53\\x4d\\x42',
                'description': 'SMB exploit attempt signature',
                'severity': 'critical'
            }
        ]
        
        # Add sample IPs
        for item in sample_ips:
            self.malicious_ips[item['indicator']] = {
                'score': item['score'],
                'categories': item['categories'],
                'source': 'otx',
                'last_updated': datetime.now()
            }
            stats['malicious_ips_updated'] += 1
        
        # Add sample domains
        for item in sample_domains:
            self.malicious_domains[item['indicator']] = {
                'score': item['score'],
                'categories': item['categories'],
                'source': 'otx',
                'last_updated': datetime.now()
            }
            stats['malicious_domains_updated'] += 1
        
        # Add sample signatures
        for item in sample_signatures:
            self.attack_signatures[item['id']] = {
                'pattern': item['pattern'],
                'description': item['description'],
                'severity': item['severity'],
                'source': 'otx'
            }
            stats['attack_signatures_updated'] += 1
        
        logger.info(f"Updated {stats['malicious_ips_updated']} IPs, {stats['malicious_domains_updated']} domains, and {stats['attack_signatures_updated']} signatures from OTX (simulated)")
        return True, stats
    
    def _update_from_emerging_threats(self) -> Tuple[bool, Dict[str, Any]]:
        """Update threat data from Emerging Threats open ruleset.
        
        Returns:
            Tuple[bool, Dict[str, Any]]: (success, update_stats)
        """
        stats = {'attack_signatures_updated': 0}
        
        try:
            # Emerging Threats open rules URL
            url = "https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-malware.rules"
            
            response = requests.get(url)
            
            if response.status_code == 200:
                rules_text = response.text
                
                # Simple regex to extract signature details from Suricata/Snort rules
                # In a real implementation, this would use a proper parser
                pattern = r'alert\s+\w+\s+[^"]*"([^"]*)"[^[]*\[\s*sid\s*:\s*(\d+)\s*[^]]*\]'
                
                for match in re.finditer(pattern, rules_text):
                    message = match.group(1)
                    sid = "et-" + match.group(2)
                    
                    # Determine severity based on message content
                    severity = "medium"
                    if any(kw in message.lower() for kw in ["critical", "exploit", "overflow", "trojan"]):
                        severity = "high"
                    elif any(kw in message.lower() for kw in ["suspicious", "attempt", "scan"]):
                        severity = "medium"
                    
                    # Extract pattern (simplified)
                    content_match = re.search(r'content\s*:\s*"([^"]*)";', rules_text)
                    pattern = content_match.group(1) if content_match else ""
                    
                    self.attack_signatures[sid] = {
                        'pattern': pattern,
                        'description': message,
                        'severity': severity,
                        'source': 'emerging_threats'
                    }
                    stats['attack_signatures_updated'] += 1
                    
                    # Limit the number of signatures for sample implementation
                    if stats['attack_signatures_updated'] >= 100:
                        break
                
                logger.info(f"Updated {stats['attack_signatures_updated']} signatures from Emerging Threats")
                return True, stats
            else:
                logger.error(f"Error from Emerging Threats: {response.status_code}")
                return False, stats
                
        except Exception as e:
            logger.error(f"Error updating from Emerging Threats: {e}")
            return False, stats
    
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check if an IP is known to be malicious.
        
        Args:
            ip: IP address to check
            
        Returns:
            Dict with threat information or empty dict if not found
        """
        return self.malicious_ips.get(ip, {})
    
    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check if a domain is known to be malicious.
        
        Args:
            domain: Domain to check
            
        Returns:
            Dict with threat information or empty dict if not found
        """
        return self.malicious_domains.get(domain, {})
    
    def check_url(self, url: str) -> Dict[str, Any]:
        """Check if a URL is known to be malicious.
        
        Args:
            url: URL to check
            
        Returns:
            Dict with threat information or empty dict if not found
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Check if domain is in our malicious domains list
            domain_info = self.check_domain(domain)
            if domain_info:
                return domain_info
            
            # If not found by domain, try resolving to IP and check that
            try:
                import socket
                ip = socket.gethostbyname(domain)
                ip_info = self.check_ip(ip)
                if ip_info:
                    return ip_info
            except:
                pass
                
            return {}
            
        except Exception as e:
            logger.error(f"Error checking URL: {e}")
            return {}
    
    def get_attack_signatures(self, severity: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """Get attack signatures, optionally filtered by severity.
        
        Args:
            severity: Optional severity filter ('low', 'medium', 'high', 'critical')
            
        Returns:
            Dict of signature_id -> signature_details
        """
        if not severity:
            return self.attack_signatures
        
        return {sid: details for sid, details in self.attack_signatures.items() 
                if details.get('severity') == severity}
    
    def get_all_malicious_ips(self, min_score: int = 0) -> Dict[str, Dict[str, Any]]:
        """Get all known malicious IPs with score >= min_score.
        
        Args:
            min_score: Minimum score threshold (0-100)
            
        Returns:
            Dict of ip -> threat_details
        """
        return {ip: details for ip, details in self.malicious_ips.items() 
                if details.get('score', 0) >= min_score}
    
    def get_all_malicious_domains(self, min_score: int = 0) -> Dict[str, Dict[str, Any]]:
        """Get all known malicious domains with score >= min_score.
        
        Args:
            min_score: Minimum score threshold (0-100)
            
        Returns:
            Dict of domain -> threat_details
        """
        return {domain: details for domain, details in self.malicious_domains.items() 
                if details.get('score', 0) >= min_score}
    
    def get_last_update_time(self) -> Optional[datetime]:
        """Get the timestamp of the last successful update.
        
        Returns:
            Datetime of last update or None if never updated
        """
        return self.last_update
    
    def is_running(self) -> bool:
        """Check if threat intelligence updates are running.
        
        Returns:
            bool: True if updates are running
        """
        return self.running

# Singleton instance
_threat_intelligence_instance = None

def get_threat_intelligence():
    """Get the global ThreatIntelligence instance.
    
    Returns:
        ThreatIntelligence: The global instance
    """
    global _threat_intelligence_instance
    if _threat_intelligence_instance is None:
        _threat_intelligence_instance = ThreatIntelligence()
    return _threat_intelligence_instance 