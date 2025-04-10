#!/usr/bin/env python3
"""
ARPGuard API Endpoint Testing Script
This script tests API endpoints for ARPGuard integration validation.
"""

import sys
import time
import logging
import json
import yaml
import platform
import socket
import requests
import argparse
import os
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
from requests.exceptions import RequestException

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api_tests.log'),
        logging.StreamHandler()
    ]
)

class APIEndpointTests:
    def __init__(self, use_mock: bool = False, base_url: str = None, api_key: str = None):
        self.test_results = []
        self.use_mock = use_mock
        
        # Load configuration
        try:
            self.config = self._load_config()
        except Exception as e:
            logging.error(f"Failed to load configuration: {str(e)}")
            self.config = {}
            
        # Set API parameters
        self.base_url = base_url or self.config.get('api_url', 'http://localhost:8080')
        self.api_key = api_key or self.config.get('api_key', '')
        self.headers = {
            'X-API-Key': self.api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        # Define timeout and retry settings
        self.timeout = self.config.get('request_timeout', 10)
        self.max_retries = self.config.get('max_retries', 3)
        self.retry_delay = self.config.get('retry_delay', 1)

    def _load_config(self) -> Dict[str, Any]:
        """Load test configuration from YAML file."""
        config_path = 'config/api_test_config.yaml'
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f)
            else:
                logging.warning(f"Configuration file {config_path} not found, using default values")
                return {}
        except Exception as e:
            logging.error(f"Error loading configuration: {str(e)}")
            return {}

    def _log_test_result(self, test_name: str, passed: bool, details: str):
        """Log test result with timestamp."""
        result = {
            'test_name': test_name,
            'passed': passed,
            'timestamp': datetime.now().isoformat(),
            'details': details
        }
        self.test_results.append(result)
        status = "PASSED" if passed else "FAILED"
        logging.info(f"{test_name}: {status} - {details}")

    def _make_request(self, method: str, endpoint: str, data: Dict = None) -> Tuple[bool, Dict, str]:
        """Make API request with retries."""
        if self.use_mock:
            logging.info(f"Mock mode: Simulating {method} request to {endpoint}")
            mock_responses = {
                'GET/api/v1/arp-table': {'status': 'success', 'data': [
                    {'ip': '192.168.1.1', 'mac': '00:11:22:33:44:55', 'interface': 'eth0', 'timestamp': datetime.now().isoformat()},
                    {'ip': '192.168.1.2', 'mac': '00:aa:bb:cc:dd:ee', 'interface': 'eth0', 'timestamp': datetime.now().isoformat()}
                ]},
                'GET/api/v1/statistics': {'status': 'success', 'data': {
                    'packets_processed': 15620,
                    'alerts_generated': 12,
                    'uptime_seconds': 3600,
                    'cpu_usage': 5.2,
                    'memory_usage': 128.4
                }},
                'GET/api/v1/alerts': {'status': 'success', 'data': [
                    {'id': 'alert-1', 'type': 'arp_spoofing', 'severity': 'high', 'timestamp': datetime.now().isoformat()},
                    {'id': 'alert-2', 'type': 'mac_spoofing', 'severity': 'medium', 'timestamp': datetime.now().isoformat()}
                ]},
                'GET/api/v1/network-interfaces': {'status': 'success', 'data': [
                    {'name': 'eth0', 'mac': '00:11:22:33:44:55', 'ip': '192.168.1.100'},
                    {'name': 'lo', 'mac': '00:00:00:00:00:00', 'ip': '127.0.0.1'}
                ]},
                'GET/api/v1/protection-rules': {'status': 'success', 'data': [
                    {'id': 'rule-1', 'ip_address': '192.168.1.1', 'mac_address': '00:11:22:33:44:55', 'description': 'Gateway rule'},
                    {'id': 'rule-2', 'ip_address': '192.168.1.10', 'mac_address': '00:aa:bb:cc:dd:ee', 'description': 'Server rule'}
                ]},
                'POST/api/v1/actions/scan': {'status': 'success', 'message': 'Network scan initiated'},
                'POST/api/v1/protection-rules': {'status': 'success', 'data': {'id': 'rule-new', 'ip_address': '192.168.1.5', 'mac_address': '00:11:22:33:44:55'}}
            }
            key = f"{method}/{endpoint}"
            if key in mock_responses:
                return True, mock_responses[key], "Mock response"
            return False, {"error": "Not found"}, "Endpoint not found in mock responses"
            
        url = f"{self.base_url}{endpoint}"
        for attempt in range(self.max_retries):
            try:
                if method.upper() == 'GET':
                    response = requests.get(url, headers=self.headers, timeout=self.timeout)
                elif method.upper() == 'POST':
                    response = requests.post(url, headers=self.headers, json=data, timeout=self.timeout)
                elif method.upper() == 'PUT':
                    response = requests.put(url, headers=self.headers, json=data, timeout=self.timeout)
                elif method.upper() == 'DELETE':
                    response = requests.delete(url, headers=self.headers, timeout=self.timeout)
                else:
                    return False, {}, f"Unsupported method: {method}"
                
                if response.status_code in [200, 201, 204]:
                    try:
                        return True, response.json(), f"Status code: {response.status_code}"
                    except ValueError:
                        return True, {}, f"Status code: {response.status_code}, no JSON response"
                elif response.status_code == 429:  # Rate limited
                    retry_after = int(response.headers.get('Retry-After', self.retry_delay))
                    logging.warning(f"Rate limited. Retrying after {retry_after} seconds.")
                    time.sleep(retry_after)
                    continue
                else:
                    error_msg = f"Status code: {response.status_code}"
                    try:
                        error_data = response.json()
                        error_msg += f", Error: {error_data.get('error', 'Unknown error')}"
                    except ValueError:
                        error_msg += f", Response: {response.text}"
                    return False, {}, error_msg
            except RequestException as e:
                if attempt == self.max_retries - 1:
                    return False, {}, f"Request failed after {self.max_retries} attempts: {str(e)}"
                logging.warning(f"Request failed (attempt {attempt+1}/{self.max_retries}): {str(e)}. Retrying...")
                time.sleep(self.retry_delay)
        
        return False, {}, f"All {self.max_retries} attempts failed"

    def test_arp_table_endpoint(self) -> bool:
        """Test GET /api/v1/arp-table endpoint."""
        try:
            endpoint = "/api/v1/arp-table"
            success, response, details = self._make_request('GET', endpoint)
            
            if success:
                # Validate response structure
                if 'data' in response and isinstance(response['data'], list):
                    if len(response['data']) > 0:
                        # Check if first entry has required fields
                        entry = response['data'][0]
                        if all(key in entry for key in ['ip', 'mac']):
                            self._log_test_result(
                                "ARP Table Endpoint",
                                True,
                                f"Successfully retrieved {len(response['data'])} ARP entries"
                            )
                            return True
                        else:
                            self._log_test_result(
                                "ARP Table Endpoint",
                                False,
                                f"ARP entry missing required fields: {entry}"
                            )
                            return False
                    else:
                        # Empty table is valid but log as info
                        self._log_test_result(
                            "ARP Table Endpoint",
                            True,
                            "ARP table is empty"
                        )
                        return True
                else:
                    self._log_test_result(
                        "ARP Table Endpoint",
                        False,
                        f"Invalid response structure: {response}"
                    )
                    return False
            else:
                self._log_test_result(
                    "ARP Table Endpoint",
                    False,
                    f"Request failed: {details}"
                )
                return False
        except Exception as e:
            self._log_test_result(
                "ARP Table Endpoint",
                False,
                f"Test failed with error: {str(e)}"
            )
            return False

    def test_statistics_endpoint(self) -> bool:
        """Test GET /api/v1/statistics endpoint."""
        try:
            endpoint = "/api/v1/statistics"
            success, response, details = self._make_request('GET', endpoint)
            
            if success:
                # Validate response structure
                if 'data' in response and isinstance(response['data'], dict):
                    if all(key in response['data'] for key in ['packets_processed', 'uptime_seconds']):
                        self._log_test_result(
                            "Statistics Endpoint",
                            True,
                            f"Successfully retrieved system statistics"
                        )
                        return True
                    else:
                        self._log_test_result(
                            "Statistics Endpoint",
                            False,
                            f"Statistics missing required fields: {response['data']}"
                        )
                        return False
                else:
                    self._log_test_result(
                        "Statistics Endpoint",
                        False,
                        f"Invalid response structure: {response}"
                    )
                    return False
            else:
                self._log_test_result(
                    "Statistics Endpoint",
                    False,
                    f"Request failed: {details}"
                )
                return False
        except Exception as e:
            self._log_test_result(
                "Statistics Endpoint",
                False,
                f"Test failed with error: {str(e)}"
            )
            return False

    def test_alerts_endpoint(self) -> bool:
        """Test GET /api/v1/alerts endpoint."""
        try:
            endpoint = "/api/v1/alerts"
            success, response, details = self._make_request('GET', endpoint)
            
            if success:
                # Validate response structure
                if 'data' in response and isinstance(response['data'], list):
                    # Empty alert list is valid
                    if len(response['data']) > 0:
                        # Check if first entry has required fields
                        alert = response['data'][0]
                        if all(key in alert for key in ['id', 'type', 'severity']):
                            self._log_test_result(
                                "Alerts Endpoint",
                                True,
                                f"Successfully retrieved {len(response['data'])} alerts"
                            )
                            return True
                        else:
                            self._log_test_result(
                                "Alerts Endpoint",
                                False,
                                f"Alert missing required fields: {alert}"
                            )
                            return False
                    else:
                        self._log_test_result(
                            "Alerts Endpoint",
                            True,
                            "No alerts found"
                        )
                        return True
                else:
                    self._log_test_result(
                        "Alerts Endpoint",
                        False,
                        f"Invalid response structure: {response}"
                    )
                    return False
            else:
                self._log_test_result(
                    "Alerts Endpoint",
                    False,
                    f"Request failed: {details}"
                )
                return False
        except Exception as e:
            self._log_test_result(
                "Alerts Endpoint",
                False,
                f"Test failed with error: {str(e)}"
            )
            return False

    def test_network_interfaces_endpoint(self) -> bool:
        """Test GET /api/v1/network-interfaces endpoint."""
        try:
            endpoint = "/api/v1/network-interfaces"
            success, response, details = self._make_request('GET', endpoint)
            
            if success:
                # Validate response structure
                if 'data' in response and isinstance(response['data'], list):
                    if len(response['data']) > 0:
                        # Check if first entry has required fields
                        interface = response['data'][0]
                        if all(key in interface for key in ['name']):
                            self._log_test_result(
                                "Network Interfaces Endpoint",
                                True,
                                f"Successfully retrieved {len(response['data'])} network interfaces"
                            )
                            return True
                        else:
                            self._log_test_result(
                                "Network Interfaces Endpoint",
                                False,
                                f"Interface missing required fields: {interface}"
                            )
                            return False
                    else:
                        self._log_test_result(
                            "Network Interfaces Endpoint",
                            False,
                            "No network interfaces found"
                        )
                        return False
                else:
                    self._log_test_result(
                        "Network Interfaces Endpoint",
                        False,
                        f"Invalid response structure: {response}"
                    )
                    return False
            else:
                self._log_test_result(
                    "Network Interfaces Endpoint",
                    False,
                    f"Request failed: {details}"
                )
                return False
        except Exception as e:
            self._log_test_result(
                "Network Interfaces Endpoint",
                False,
                f"Test failed with error: {str(e)}"
            )
            return False

    def test_protection_rules_endpoint(self) -> bool:
        """Test GET /api/v1/protection-rules endpoint."""
        try:
            endpoint = "/api/v1/protection-rules"
            success, response, details = self._make_request('GET', endpoint)
            
            if success:
                # Validate response structure
                if 'data' in response and isinstance(response['data'], list):
                    if len(response['data']) > 0:
                        # Check if first entry has required fields
                        rule = response['data'][0]
                        if all(key in rule for key in ['id', 'ip_address', 'mac_address']):
                            self._log_test_result(
                                "Protection Rules Endpoint",
                                True,
                                f"Successfully retrieved {len(response['data'])} protection rules"
                            )
                            return True
                        else:
                            self._log_test_result(
                                "Protection Rules Endpoint",
                                False,
                                f"Rule missing required fields: {rule}"
                            )
                            return False
                    else:
                        # Empty rules list is valid
                        self._log_test_result(
                            "Protection Rules Endpoint",
                            True,
                            "No protection rules found"
                        )
                        return True
                else:
                    self._log_test_result(
                        "Protection Rules Endpoint",
                        False,
                        f"Invalid response structure: {response}"
                    )
                    return False
            else:
                self._log_test_result(
                    "Protection Rules Endpoint",
                    False,
                    f"Request failed: {details}"
                )
                return False
        except Exception as e:
            self._log_test_result(
                "Protection Rules Endpoint",
                False,
                f"Test failed with error: {str(e)}"
            )
            return False

    def test_scan_action_endpoint(self) -> bool:
        """Test POST /api/v1/actions/scan endpoint."""
        try:
            endpoint = "/api/v1/actions/scan"
            success, response, details = self._make_request('POST', endpoint)
            
            if success:
                self._log_test_result(
                    "Scan Action Endpoint",
                    True,
                    f"Successfully triggered network scan"
                )
                return True
            else:
                self._log_test_result(
                    "Scan Action Endpoint",
                    False,
                    f"Request failed: {details}"
                )
                return False
        except Exception as e:
            self._log_test_result(
                "Scan Action Endpoint",
                False,
                f"Test failed with error: {str(e)}"
            )
            return False

    def test_create_protection_rule_endpoint(self) -> bool:
        """Test POST /api/v1/protection-rules endpoint."""
        try:
            endpoint = "/api/v1/protection-rules"
            test_rule = {
                "ip_address": "192.168.1.5",
                "mac_address": "00:11:22:33:44:55",
                "description": "Test rule created by API test"
            }
            success, response, details = self._make_request('POST', endpoint, test_rule)
            
            if success:
                # Validate response structure
                if 'data' in response and isinstance(response['data'], dict):
                    if all(key in response['data'] for key in ['id', 'ip_address', 'mac_address']):
                        self._log_test_result(
                            "Create Protection Rule Endpoint",
                            True,
                            f"Successfully created protection rule with ID: {response['data'].get('id')}"
                        )
                        return True
                    else:
                        self._log_test_result(
                            "Create Protection Rule Endpoint",
                            False,
                            f"Response missing required fields: {response['data']}"
                        )
                        return False
                else:
                    self._log_test_result(
                        "Create Protection Rule Endpoint",
                        False,
                        f"Invalid response structure: {response}"
                    )
                    return False
            else:
                self._log_test_result(
                    "Create Protection Rule Endpoint",
                    False,
                    f"Request failed: {details}"
                )
                return False
        except Exception as e:
            self._log_test_result(
                "Create Protection Rule Endpoint",
                False,
                f"Test failed with error: {str(e)}"
            )
            return False

    def run_all_tests(self) -> bool:
        """Run all API endpoint tests and return overall status."""
        logging.info("Starting API Endpoint Tests")
        logging.info(f"System: {platform.system()}, Python: {platform.python_version()}")
        logging.info(f"API URL: {self.base_url}")
        logging.info(f"Mock mode: {self.use_mock}")
        
        tests = [
            ("ARP Table Endpoint", self.test_arp_table_endpoint),
            ("Statistics Endpoint", self.test_statistics_endpoint),
            ("Alerts Endpoint", self.test_alerts_endpoint),
            ("Network Interfaces Endpoint", self.test_network_interfaces_endpoint),
            ("Protection Rules Endpoint", self.test_protection_rules_endpoint),
            ("Scan Action Endpoint", self.test_scan_action_endpoint),
            ("Create Protection Rule Endpoint", self.test_create_protection_rule_endpoint)
        ]
        
        all_passed = True
        for test_name, test_func in tests:
            logging.info(f"Running test: {test_name}")
            if not test_func():
                all_passed = False
        
        # Generate summary report
        self._generate_report()
        
        logging.info(f"API Endpoint Tests {'PASSED' if all_passed else 'FAILED'}")
        return all_passed

    def _generate_report(self):
        """Generate detailed test report."""
        report = {
            "test_suite": "API Endpoint Tests",
            "timestamp": datetime.now().isoformat(),
            "system_info": {
                "hostname": socket.gethostname(),
                "os": platform.system(),
                "os_release": platform.release(),
                "python_version": platform.python_version()
            },
            "api_info": {
                "base_url": self.base_url,
                "mock_mode": self.use_mock
            },
            "test_results": self.test_results,
            "summary": {
                "total_tests": len(self.test_results),
                "passed": sum(1 for r in self.test_results if r['passed']),
                "failed": sum(1 for r in self.test_results if not r['passed'])
            }
        }
        
        # Save as JSON
        try:
            report_file = f"api_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_file, "w") as f:
                json.dump(report, f, indent=2)
            
            logging.info(f"Test report generated: {report_file}. Passed: {report['summary']['passed']}, Failed: {report['summary']['failed']}")
        except Exception as e:
            logging.error(f"Failed to generate report: {str(e)}")

def main():
    try:
        parser = argparse.ArgumentParser(description="Test ARPGuard API endpoints")
        parser.add_argument("--mock", action="store_true", help="Run in mock mode (no actual API calls)")
        parser.add_argument("--url", help="Base URL for API", default=None)
        parser.add_argument("--key", help="API key", default=None)
        
        args = parser.parse_args()
        
        tests = APIEndpointTests(
            use_mock=args.mock,
            base_url=args.url,
            api_key=args.key
        )
        success = tests.run_all_tests()
        sys.exit(0 if success else 1)
    except Exception as e:
        logging.error(f"Test execution failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 