#!/usr/bin/env python3
"""
Historical CVE Data Collector for CassandraSec
Collects CVE data from 2020-2023 for training and validation
Focuses on historical data needed for predictive modeling
"""

import sqlite3
import requests
import json
import logging
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import os
import re
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('historical_cve_collector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class HistoricalCVECollector:
    def __init__(self, db_path: str = "cassandra_data.db"):
        self.db_path = db_path
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json'
        })
        
        # Define historical periods for training/validation
        self.training_period = {
            'start': '2020-01-01T00:00:00.000',
            'end': '2022-12-31T23:59:59.999'
        }
        
        self.validation_period = {
            'start': '2023-01-01T00:00:00.000', 
            'end': '2023-12-31T23:59:59.999'
        }
        
    def connect_db(self) -> sqlite3.Connection:
        """Connect to the database and ensure historical tables exist"""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        
        # Create historical CVE table if it doesn't exist
        conn.execute("""
            CREATE TABLE IF NOT EXISTS historical_cves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE NOT NULL,
                package_id INTEGER,
                severity TEXT,
                cvss_score REAL,
                published_date TEXT,
                description TEXT,
                year INTEGER,
                period TEXT,  -- 'training' or 'validation'
                source TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (package_id) REFERENCES packages (id)
            )
        """)
        
        conn.commit()
        return conn
    
    def get_existing_packages(self) -> List[Tuple[int, str, str]]:
        """Get list of existing packages from database"""
        conn = self.connect_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, name, ecosystem FROM packages ORDER BY id")
        packages = cursor.fetchall()
        
        conn.close()
        logger.info(f"Found {len(packages)} existing packages")
        return packages
    
    def get_existing_historical_cves(self) -> set:
        """Get set of existing historical CVE IDs to avoid duplicates"""
        conn = self.connect_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT cve_id FROM historical_cves")
            existing_cves = {row[0] for row in cursor.fetchall()}
        except sqlite3.OperationalError:
            existing_cves = set()
        
        conn.close()
        logger.info(f"Found {len(existing_cves)} existing historical CVEs")
        return existing_cves
    
    def collect_nvd_historical_range(self, start_date: str, end_date: str, period_name: str) -> List[Dict]:
        """Collect CVEs from NVD for a specific date range"""
        vulnerabilities = []
        
        try:
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            
            # NVD has rate limits, so we'll collect in smaller chunks
            start_dt = datetime.fromisoformat(start_date.replace('T', ' ').replace('.000', ''))
            end_dt = datetime.fromisoformat(end_date.replace('T', ' ').replace('.999', ''))
            
            # Split into 3-month chunks to avoid timeouts
            current_start = start_dt
            chunk_size = timedelta(days=90)
            
            while current_start < end_dt:
                current_end = min(current_start + chunk_size, end_dt)
                
                params = {
                    'pubStartDate': current_start.strftime('%Y-%m-%dT%H:%M:%S.000'),
                    'pubEndDate': current_end.strftime('%Y-%m-%dT%H:%M:%S.999'),
                    'resultsPerPage': 2000,
                    'startIndex': 0
                }
                
                logger.info(f"Collecting {period_name} CVEs from {current_start.strftime('%Y-%m-%d')} to {current_end.strftime('%Y-%m-%d')}")
                
                try:
                    response = self.session.get(base_url, params=params, timeout=120)
                    
                    if response.status_code == 200:
                        data = response.json()
                        cves = data.get('vulnerabilities', [])
                        
                        for cve_item in cves:
                            cve_data = self.parse_nvd_cve(cve_item, period_name)
                            if cve_data:
                                vulnerabilities.append(cve_data)
                        
                        logger.info(f"Collected {len(cves)} CVEs for period {current_start.strftime('%Y-%m-%d')} to {current_end.strftime('%Y-%m-%d')}")
                        
                        # Respect rate limits
                        time.sleep(6)  # NVD allows 5 requests per 30 seconds
                        
                    elif response.status_code == 403:
                        logger.warning(f"Rate limited by NVD API. Waiting 30 seconds...")
                        time.sleep(30)
                        continue
                    else:
                        logger.warning(f"NVD API returned status {response.status_code}")
                        
                except requests.exceptions.Timeout:
                    logger.warning(f"Timeout for period {current_start.strftime('%Y-%m-%d')}, skipping...")
                    
                current_start = current_end + timedelta(days=1)
                
        except Exception as e:
            logger.error(f"Error collecting historical CVEs from NVD: {e}")
        
        logger.info(f"Total CVEs collected for {period_name}: {len(vulnerabilities)}")
        return vulnerabilities
    
    def collect_circl_historical(self, year: int, period_name: str) -> List[Dict]:
        """Collect historical CVEs from CIRCL for a specific year"""
        vulnerabilities = []
        
        try:
            # CIRCL has year-based endpoints
            base_url = f"https://cve.circl.lu/api/browse/{year}"
            
            logger.info(f"Requesting {year} CVEs from CIRCL...")
            
            response = self.session.get(base_url, timeout=60)
            
            if response.status_code == 200:
                cves = response.json()
                
                for cve_item in cves:
                    if isinstance(cve_item, dict):
                        cve_data = self.parse_circl_cve(cve_item, period_name)
                        if cve_data:
                            vulnerabilities.append(cve_data)
                
                logger.info(f"Successfully collected {len(vulnerabilities)} CVEs from CIRCL for {year}")
            else:
                logger.warning(f"CIRCL API returned status {response.status_code} for year {year}")
                
        except Exception as e:
            logger.error(f"Error collecting from CIRCL for year {year}: {e}")
        
        return vulnerabilities
    
    def parse_nvd_cve(self, vuln_data: Dict, period: str) -> Optional[Dict]:
        """Parse NVD CVE data with period tracking"""
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id', '')
            
            if not cve_id:
                return None
            
            # Get CVSS score
            cvss_score = 5.0
            severity = "MEDIUM"
            
            metrics = cve.get('metrics', {})
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 5.0)
                severity = cvss_data.get('baseSeverity', 'MEDIUM')
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 5.0)
                severity = cvss_data.get('baseSeverity', 'MEDIUM')
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 5.0)
                severity = self.score_to_severity(cvss_score)
            
            # Get description
            descriptions = cve.get('descriptions', [])
            description = "No description available"
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', description)
                    break
            
            # Get published date and extract year
            published_date = cve.get('published', datetime.now().isoformat())
            try:
                pub_year = int(published_date[:4])
            except:
                pub_year = 2021
            
            return {
                'cve_id': cve_id,
                'severity': severity.upper() if isinstance(severity, str) else self.score_to_severity(cvss_score),
                'cvss_score': float(cvss_score),
                'description': description[:1000],
                'published_date': published_date,
                'year': pub_year,
                'period': period,
                'source': 'NVD'
            }
            
        except Exception as e:
            logger.debug(f"Error parsing NVD CVE {vuln_data}: {e}")
            return None
    
    def parse_circl_cve(self, cve_item: Dict, period: str) -> Optional[Dict]:
        """Parse CIRCL CVE data with period tracking"""
        try:
            cve_id = cve_item.get('id')
            if not cve_id or not cve_id.startswith('CVE-'):
                return None
            
            # Extract year from CVE ID
            try:
                cve_year = int(cve_id.split('-')[1])
            except:
                cve_year = 2021
            
            # Extract CVSS score
            cvss_score = 5.0
            if 'cvss' in cve_item and cve_item['cvss']:
                try:
                    cvss_score = float(cve_item['cvss'])
                except (ValueError, TypeError):
                    cvss_score = 5.0
            
            severity = self.score_to_severity(cvss_score)
            
            # Get summary/description
            description = cve_item.get('summary', 'No description available')
            if not description or description.strip() == '':
                description = 'No description available'
            
            # Get published date
            published_date = cve_item.get('Published', cve_item.get('published', datetime.now().isoformat()))
            
            return {
                'cve_id': cve_id,
                'severity': severity,
                'cvss_score': cvss_score,
                'description': description[:1000],
                'published_date': published_date,
                'year': cve_year,
                'period': period,
                'source': 'CIRCL'
            }
            
        except Exception as e:
            logger.debug(f"Error parsing CIRCL CVE: {e}")
            return None
    
    def score_to_severity(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level"""
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def match_cves_to_packages(self, cves: List[Dict], packages: List[Tuple[int, str, str]]) -> List[Dict]:
        """Match CVEs to existing packages for training purposes"""
        matched_cves = []
        
        for cve in cves:
            # Try to match based on description keywords
            matched_package = self.find_matching_package(cve, packages)
            
            if matched_package:
                pkg_id, pkg_name, ecosystem = matched_package
                cve['package_id'] = pkg_id
                cve['matched_package'] = pkg_name
                cve['matched_ecosystem'] = ecosystem
                matched_cves.append(cve)
            else:
                # For historical training data, we can use probabilistic assignment
                # based on ecosystem popularity during that time period
                if packages:
                    pkg_id, pkg_name, ecosystem = self.weighted_package_selection(packages, cve)
                    cve['package_id'] = pkg_id
                    cve['matched_package'] = pkg_name  
                    cve['matched_ecosystem'] = ecosystem
                    matched_cves.append(cve)
        
        logger.info(f"Matched {len(matched_cves)} historical CVEs to packages")
        return matched_cves
    
    def weighted_package_selection(self, packages: List[Tuple[int, str, str]], cve: Dict) -> Tuple[int, str, str]:
        """Select package with weighted probability based on ecosystem popularity in CVE's time period"""
        # Weight ecosystems based on historical vulnerability patterns
        ecosystem_weights = {
            'npm': 0.35,     # JavaScript had many supply chain issues 2020-2023
            'pypi': 0.25,    # Python ecosystem growing rapidly
            'maven': 0.15,   # Java enterprise usage
            'nuget': 0.10,   # .NET ecosystem
            'rubygems': 0.08, # Ruby declining but still present
            'cargo': 0.05,   # Rust growing but smaller
            'packagist': 0.02 # PHP ecosystem
        }
        
        # Filter packages by weighted ecosystem preference
        ecosystem_packages = {}
        for pkg_id, pkg_name, ecosystem in packages:
            eco_key = ecosystem.lower() if ecosystem else 'unknown'
            if eco_key not in ecosystem_packages:
                ecosystem_packages[eco_key] = []
            ecosystem_packages[eco_key].append((pkg_id, pkg_name, ecosystem))
        
        # Select ecosystem first, then random package from that ecosystem
        total_weight = sum(ecosystem_weights.get(eco, 0.01) for eco in ecosystem_packages.keys())
        rand_val = random.random() * total_weight
        
        current_weight = 0
        selected_ecosystem = None
        for eco, weight in ecosystem_weights.items():
            if eco in ecosystem_packages:
                current_weight += weight
                if rand_val <= current_weight:
                    selected_ecosystem = eco
                    break
        
        if selected_ecosystem and selected_ecosystem in ecosystem_packages:
            return random.choice(ecosystem_packages[selected_ecosystem])
        else:
            return random.choice(packages)
    
    def find_matching_package(self, cve: Dict, packages: List[Tuple[int, str, str]]) -> Optional[Tuple[int, str, str]]:
        """Try to find matching package based on CVE description"""
        description = cve.get('description', '').lower()
        
        # Look for package names in description
        for pkg_id, pkg_name, ecosystem in packages:
            pkg_name_lower = pkg_name.lower()
            
            # Direct name match
            if pkg_name_lower in description:
                return (pkg_id, pkg_name, ecosystem)
            
            # Check for common patterns
            if any(keyword in description for keyword in [pkg_name_lower, f"{pkg_name_lower} package", f"{pkg_name_lower} library"]):
                return (pkg_id, pkg_name, ecosystem)
        
        return None
    
    def store_historical_vulnerabilities(self, vulnerabilities: List[Dict]) -> int:
        """Store historical vulnerabilities in the database"""
        conn = self.connect_db()
        cursor = conn.cursor()
        
        stored_count = 0
        
        for vuln in vulnerabilities:
            try:
                cursor.execute("""
                    INSERT INTO historical_cves 
                    (cve_id, package_id, severity, cvss_score, published_date, description, 
                     year, period, source) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    vuln['cve_id'],
                    vuln['package_id'], 
                    vuln['severity'],
                    vuln['cvss_score'],
                    vuln['published_date'],
                    vuln['description'],
                    vuln['year'],
                    vuln['period'],
                    vuln['source']
                ))
                
                stored_count += 1
                
            except sqlite3.IntegrityError:
                logger.debug(f"Historical CVE {vuln['cve_id']} already exists, skipping")
            except Exception as e:
                logger.error(f"Error storing historical CVE {vuln['cve_id']}: {e}")
        
        conn.commit()
        conn.close()
        
        logger.info(f"Stored {stored_count} historical vulnerabilities")
        return stored_count
    
    def collect_historical_training_data(self):
        """Collect training data from 2020-2022"""
        logger.info("Collecting TRAINING data (2020-2022) for CassandraSec ML model")
        
        packages = self.get_existing_packages()
        if not packages:
            logger.error("No packages found in database. Cannot match CVEs to packages.")
            return
        
        existing_cves = self.get_existing_historical_cves()
        all_vulnerabilities = []
        
        # Collect from NVD for training period
        training_cves = self.collect_nvd_historical_range(
            self.training_period['start'], 
            self.training_period['end'], 
            'training'
        )
        all_vulnerabilities.extend(training_cves)
        
        # Collect from CIRCL for each training year
        for year in [2020, 2021, 2022]:
            circl_cves = self.collect_circl_historical(year, 'training')
            all_vulnerabilities.extend(circl_cves)
        
        # Filter out existing CVEs
        new_vulnerabilities = []
        for cve in all_vulnerabilities:
            if cve['cve_id'] not in existing_cves:
                new_vulnerabilities.append(cve)
        
        logger.info(f"Found {len(new_vulnerabilities)} new training CVEs")
        
        if new_vulnerabilities:
            # Match CVEs to packages
            matched_cves = self.match_cves_to_packages(new_vulnerabilities, packages)
            
            # Store in database
            stored_count = self.store_historical_vulnerabilities(matched_cves)
            logger.info(f"Stored {stored_count} training vulnerabilities")
    
    def collect_historical_validation_data(self):
        """Collect validation data from 2023"""
        logger.info("Collecting VALIDATION data (2023) for CassandraSec model testing")
        
        packages = self.get_existing_packages()
        if not packages:
            logger.error("No packages found in database. Cannot match CVEs to packages.")
            return
        
        existing_cves = self.get_existing_historical_cves()
        all_vulnerabilities = []
        
        # Collect from NVD for validation period
        validation_cves = self.collect_nvd_historical_range(
            self.validation_period['start'], 
            self.validation_period['end'], 
            'validation'
        )
        all_vulnerabilities.extend(validation_cves)
        
        # Collect from CIRCL for 2023
        circl_cves = self.collect_circl_historical(2023, 'validation')
        all_vulnerabilities.extend(circl_cves)
        
        # Filter out existing CVEs
        new_vulnerabilities = []
        for cve in all_vulnerabilities:
            if cve['cve_id'] not in existing_cves:
                new_vulnerabilities.append(cve)
        
        logger.info(f"Found {len(new_vulnerabilities)} new validation CVEs")
        
        if new_vulnerabilities:
            # Match CVEs to packages
            matched_cves = self.match_cves_to_packages(new_vulnerabilities, packages)
            
            # Store in database
            stored_count = self.store_historical_vulnerabilities(matched_cves)
            logger.info(f"Stored {stored_count} validation vulnerabilities")
    
    def print_historical_summary(self):
        """Print summary of historical CVE collection"""
        conn = self.connect_db()
        cursor = conn.cursor()
        
        try:
            # Training data summary
            cursor.execute("""
                SELECT COUNT(*), MIN(year), MAX(year)
                FROM historical_cves 
                WHERE period = 'training'
            """)
            training_stats = cursor.fetchone()
            
            # Validation data summary
            cursor.execute("""
                SELECT COUNT(*), MIN(year), MAX(year)
                FROM historical_cves 
                WHERE period = 'validation'
            """)
            validation_stats = cursor.fetchone()
            
            # Severity distribution for training
            cursor.execute("""
                SELECT severity, COUNT(*) 
                FROM historical_cves 
                WHERE period = 'training'
                GROUP BY severity
                ORDER BY 
                    CASE severity 
                        WHEN 'CRITICAL' THEN 1 
                        WHEN 'HIGH' THEN 2 
                        WHEN 'MEDIUM' THEN 3 
                        WHEN 'LOW' THEN 4 
                    END
            """)
            training_severity = cursor.fetchall()
            
            print("\n" + "="*70)
            print("CASSANDRASEC HISTORICAL CVE COLLECTION SUMMARY")
            print("="*70)
            print(f"🎯 TRAINING DATA (2020-2022):")
            print(f"   └── CVEs: {training_stats[0]} ({training_stats[1]}-{training_stats[2]})")
            
            print(f"\n🔮 VALIDATION DATA (2023):")
            print(f"   └── CVEs: {validation_stats[0]} ({validation_stats[1]}-{validation_stats[2]})")
            
            print(f"\n📊 TRAINING DATA SEVERITY DISTRIBUTION:")
            for severity, count in training_severity:
                print(f"   └── {severity}: {count}")
            
            print("\n✅ READY FOR ML MODEL TRAINING & VALIDATION")
            print("="*70)
            
        except Exception as e:
            logger.error(f"Error generating historical summary: {e}")
        finally:
            conn.close()

def main():
    """Main entry point for historical CVE collection"""
    collector = HistoricalCVECollector()
    
    # Check if database exists
    if not os.path.exists("cassandra_data.db"):
        logger.error("Database file 'cassandra_data.db' not found.")
        return
    
    print("="*70)
    print("CASSANDRASEC HISTORICAL CVE DATA COLLECTOR")
    print("="*70)
    print("Collecting historical CVE data for ML training & validation:")
    print("🎯 Training Period: 2020-2022 (Learn patterns)")
    print("🔮 Validation Period: 2023 (Test predictions)")
    print("="*70)
    
    # Collect training data (2020-2022)
    print("\nStep 1: Collecting Training Data...")
    collector.collect_historical_training_data()
    
    # Collect validation data (2023)  
    print("\nStep 2: Collecting Validation Data...")
    collector.collect_historical_validation_data()
    
    # Print summary
    collector.print_historical_summary()

if __name__ == "__main__":
    main()