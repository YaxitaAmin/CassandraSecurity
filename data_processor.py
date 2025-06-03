# data_procesor.py
"""
CassandraSec Feature Engineering Pipeline
Transforms raw CVE, package, and GitHub data into ML-ready features
"""

import pandas as pd
import numpy as np
import sqlite3
import logging
import sys
from datetime import datetime, timedelta
import json
import re
from sklearn.preprocessing import StandardScaler, LabelEncoder
import warnings
warnings.filterwarnings('ignore')

# Configure logging without emoji characters for Windows compatibility
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cassandrasec_features.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

class CassandraSecFeatureEngineer:
    """
    Advanced feature engineering for dependency risk prediction
    Creates 100+ features across multiple dimensions:
    - Maintainer Health Indicators
    - Community & Social Signals  
    - Code Quality Metrics
    - Dependency Graph Features
    - Security Posture Indicators
    - Temporal Pattern Features
    """
    
    def __init__(self, db_path='cassandra_data.db'):
        self.db_path = db_path
        self.scaler = StandardScaler()
        self.label_encoders = {}
        
        # Feature categories for organized processing
        self.feature_categories = {
            'maintainer_health': [],
            'community_signals': [],
            'code_quality': [],
            'dependency_graph': [],
            'security_posture': [],
            'temporal_patterns': []
        }
        
        logging.info("CassandraSec Feature Engineer initialized")
    
    def connect_db(self):
        """Create database connection"""
        return sqlite3.connect(self.db_path)
    
    def inspect_database_structure(self):
        """Inspect the actual database structure"""
        logging.info("Inspecting database structure...")
        conn = self.connect_db()
        
        # Get table names
        tables = pd.read_sql_query("""
            SELECT name FROM sqlite_master WHERE type='table';
        """, conn)
        
        logging.info(f"Available tables: {tables['name'].tolist()}")
        
        # Check packages table structure
        if 'packages' in tables['name'].values:
            packages_info = pd.read_sql_query("PRAGMA table_info(packages)", conn)
            logging.info(f"Packages table columns: {packages_info['name'].tolist()}")
        
        conn.close()
        return tables['name'].tolist()
    
    def load_base_data(self):
        """Load all collected data for feature engineering - adapted to actual DB structure"""
        logging.info("Loading base datasets...")
        
        conn = self.connect_db()
        
        # Load packages data with actual column names
        try:
            self.packages_df = pd.read_sql_query("""
                SELECT 
                    p.*,
                    rm.stars,
                    rm.forks,
                    rm.issues_open,
                    rm.issues_closed,
                    rm.contributors_count,
                    rm.commits_count,
                    rm.last_commit_date
                FROM packages p
                LEFT JOIN repository_metrics rm ON p.id = rm.package_id
            """, conn)
            logging.info(f"Loaded {len(self.packages_df)} packages")
        except Exception as e:
            logging.error(f"Error loading packages: {e}")
            # Fallback to basic packages table
            self.packages_df = pd.read_sql_query("SELECT * FROM packages", conn)
            logging.info(f"Loaded {len(self.packages_df)} packages (basic)")
        
        # Load historical CVEs
        try:
            self.historical_cves_df = pd.read_sql_query("""
                SELECT hc.*, p.name as package_name, p.ecosystem
                FROM historical_cves hc
                LEFT JOIN packages p ON hc.package_id = p.id
                WHERE hc.package_id IS NOT NULL
            """, conn)
            logging.info(f"Loaded {len(self.historical_cves_df)} historical CVEs")
        except Exception as e:
            logging.error(f"Error loading historical CVEs: {e}")
            self.historical_cves_df = pd.DataFrame()
        
        # Load maintainer information
        try:
            self.maintainers_df = pd.read_sql_query("""
                SELECT 
                    p.id as package_id,
                    p.name as package_name,
                    COUNT(pm.maintainer_id) as maintainer_count,
                    m.total_packages,
                    m.active_packages,
                    m.account_created
                FROM packages p
                LEFT JOIN package_maintainers pm ON p.id = pm.package_id
                LEFT JOIN maintainers m ON pm.maintainer_id = m.id
                GROUP BY p.id, p.name, m.total_packages, m.active_packages, m.account_created
            """, conn)
            logging.info(f"Loaded maintainer data for {len(self.maintainers_df)} packages")
        except Exception as e:
            logging.error(f"Error loading maintainer data: {e}")
            self.maintainers_df = pd.DataFrame()
        
        # Load dependency information
        try:
            self.dependencies_df = pd.read_sql_query("""
                SELECT 
                    package_id,
                    COUNT(*) as total_dependencies,
                    COUNT(DISTINCT dependency_name) as unique_dependencies
                FROM dependencies
                GROUP BY package_id
            """, conn)
            logging.info(f"Loaded dependency data for {len(self.dependencies_df)} packages")
        except Exception as e:
            logging.error(f"Error loading dependency data: {e}")
            self.dependencies_df = pd.DataFrame()
        
        conn.close()
    
    def create_target_labels(self):
        """Create binary labels for ML training based on historical CVEs"""
        logging.info("Creating target labels...")
        
        if len(self.historical_cves_df) > 0:
            # Convert published_date to datetime
            self.historical_cves_df['published_date'] = pd.to_datetime(
                self.historical_cves_df['published_date'], errors='coerce'
            )
            
            # Create training labels: CVEs from 2020-2022
            training_cves = self.historical_cves_df[
                (self.historical_cves_df['published_date'] >= '2020-01-01') &
                (self.historical_cves_df['published_date'] <= '2022-12-31')
            ]
            
            # Create validation labels: CVEs from 2023
            validation_cves = self.historical_cves_df[
                (self.historical_cves_df['published_date'] >= '2023-01-01') &
                (self.historical_cves_df['published_date'] <= '2023-12-31')
            ]
            
            # Binary labels
            training_vulnerable_packages = set(training_cves['package_id'].dropna().unique())
            validation_vulnerable_packages = set(validation_cves['package_id'].dropna().unique())
            
            self.packages_df['has_training_vuln'] = self.packages_df['id'].isin(training_vulnerable_packages).astype(int)
            self.packages_df['has_validation_vuln'] = self.packages_df['id'].isin(validation_vulnerable_packages).astype(int)
            
            # Severity-based labels
            critical_training = set(training_cves[
                training_cves['severity'] == 'CRITICAL'
            ]['package_id'].dropna().unique())
            
            high_training = set(training_cves[
                training_cves['severity'].isin(['CRITICAL', 'HIGH'])
            ]['package_id'].dropna().unique())
            
            self.packages_df['has_critical_training_vuln'] = self.packages_df['id'].isin(critical_training).astype(int)
            self.packages_df['has_high_training_vuln'] = self.packages_df['id'].isin(high_training).astype(int)
            
            logging.info(f"Training vulnerable packages: {len(training_vulnerable_packages)}")
            logging.info(f"Validation vulnerable packages: {len(validation_vulnerable_packages)}")
        else:
            # Create dummy labels if no CVE data
            logging.warning("No CVE data available - creating dummy labels")
            self.packages_df['has_training_vuln'] = 0
            self.packages_df['has_validation_vuln'] = 0
            self.packages_df['has_critical_training_vuln'] = 0
            self.packages_df['has_high_training_vuln'] = 0
    
    def engineer_maintainer_health_features(self):
        logging.info("Engineering maintainer health features...")

        # Handle date columns and timezone issues
        date_columns = ['created_date', 'last_updated', 'last_commit_date']
        for col in date_columns:
            if col in self.packages_df.columns:
                # Convert to datetime and ensure timezone-naive
                self.packages_df[col] = pd.to_datetime(self.packages_df[col], errors='coerce')
                if pd.api.types.is_datetime64tz_dtype(self.packages_df[col]):
                    self.packages_df[col] = self.packages_df[col].dt.tz_localize(None)

        # Use timezone-naive current_date to match database datetime format
        current_date = pd.Timestamp.now().tz_localize(None)

        # Package age and update patterns
        if 'created_date' in self.packages_df.columns:
            self.packages_df['package_age_days'] = (current_date - self.packages_df['created_date']).dt.days
        else:
            self.packages_df['package_age_days'] = 365

        if 'last_updated' in self.packages_df.columns:
            self.packages_df['days_since_update'] = (current_date - self.packages_df['last_updated']).dt.days
        else:
            self.packages_df['days_since_update'] = 30

        if 'last_commit_date' in self.packages_df.columns:
            self.packages_df['days_since_last_commit'] = (current_date - self.packages_df['last_commit_date']).dt.days
            self.packages_df['days_since_last_commit'] = self.packages_df['days_since_last_commit'].fillna(365)
        else:
            self.packages_df['days_since_last_commit'] = 365

        # Update frequency score
        self.packages_df['update_frequency_score'] = np.where(
            self.packages_df['days_since_update'] <= 30, 5,
            np.where(self.packages_df['days_since_update'] <= 90, 4,
            np.where(self.packages_df['days_since_update'] <= 180, 3,
            np.where(self.packages_df['days_since_update'] <= 365, 2, 1)))
        )

        # Description quality
        self.packages_df['description_length'] = self.packages_df['description'].fillna('').str.len()
        self.packages_df['has_detailed_description'] = (self.packages_df['description_length'] > 100).astype(int)

        # Popularity metrics (if available)
        if 'download_count' in self.packages_df.columns:
            self.packages_df['log_download_count'] = np.log1p(self.packages_df['download_count'].fillna(0))
        else:
            self.packages_df['log_download_count'] = 0

        if 'stars' in self.packages_df.columns:
            self.packages_df['log_star_count'] = np.log1p(self.packages_df['stars'].fillna(0))
        else:
            self.packages_df['log_star_count'] = 0

        if 'forks' in self.packages_df.columns:
            self.packages_df['log_fork_count'] = np.log1p(self.packages_df['forks'].fillna(0))
        else:
            self.packages_df['log_fork_count'] = 0

        # Engagement ratios
        self.packages_df['stars_to_downloads'] = (
            self.packages_df['stars'].fillna(0) /
            (self.packages_df['download_count'].fillna(1) + 1)
        ) if 'stars' in self.packages_df.columns and 'download_count' in self.packages_df.columns else 0

        # Add maintainer information if available
        if len(self.maintainers_df) > 0:
            self.packages_df = self.packages_df.merge(
                self.maintainers_df[['package_id', 'maintainer_count', 'total_packages', 'active_packages']],
                left_on='id', right_on='package_id', how='left'
            )
            self.packages_df['maintainer_count'] = self.packages_df['maintainer_count'].fillna(1)
            self.packages_df['maintainer_experience'] = self.packages_df['total_packages'].fillna(1)
        else:
            self.packages_df['maintainer_count'] = 1
            self.packages_df['maintainer_experience'] = 1

        # Add to feature categories
        maintainer_features = [
            'package_age_days', 'days_since_update', 'days_since_last_commit', 'update_frequency_score',
            'description_length', 'has_detailed_description',
            'log_download_count', 'log_star_count', 'log_fork_count',
            'stars_to_downloads', 'maintainer_count', 'maintainer_experience'
        ]
        self.feature_categories['maintainer_health'].extend(maintainer_features)

        logging.info(f"Created {len(maintainer_features)} maintainer health features")
        
    def engineer_community_signals(self):
        """Create community health and social signal features"""
        logging.info("Engineering community signal features...")
        
        # Basic metadata availability
        self.packages_df['has_homepage'] = (~self.packages_df['homepage_url'].isna()).astype(int)
        self.packages_df['has_repository'] = (~self.packages_df['repository_url'].isna()).astype(int)
        
        # Community engagement metrics
        if 'issues_open' in self.packages_df.columns:
            self.packages_df['total_issues'] = (
                self.packages_df['issues_open'].fillna(0) + 
                self.packages_df['issues_closed'].fillna(0)
            )
            self.packages_df['issue_resolution_rate'] = (
                self.packages_df['issues_closed'].fillna(0) / 
                (self.packages_df['total_issues'] + 1)
            )
        else:
            self.packages_df['total_issues'] = 0
            self.packages_df['issue_resolution_rate'] = 0.5
        
        if 'contributors_count' in self.packages_df.columns:
            self.packages_df['log_contributors'] = np.log1p(self.packages_df['contributors_count'].fillna(0))
        else:
            self.packages_df['log_contributors'] = 0
        
        if 'commits_count' in self.packages_df.columns:
            self.packages_df['log_commits'] = np.log1p(self.packages_df['commits_count'].fillna(0))
        else:
            self.packages_df['log_commits'] = 0
        
        # Ecosystem analysis
        ecosystem_dummies = pd.get_dummies(self.packages_df['ecosystem'], prefix='ecosystem')
        self.packages_df = pd.concat([self.packages_df, ecosystem_dummies], axis=1)
        
        # Community engagement score
        self.packages_df['community_engagement_score'] = (
            self.packages_df['has_homepage'] + 
            self.packages_df['has_repository'] +
            (self.packages_df['log_contributors'] > 0).astype(int) +
            (self.packages_df['log_star_count'] > 2).astype(int) +
            (self.packages_df['total_issues'] > 0).astype(int)
        )
        
        # Add to feature categories
        community_features = [
            'has_homepage', 'has_repository', 'total_issues', 'issue_resolution_rate',
            'log_contributors', 'log_commits', 'community_engagement_score'
        ] + list(ecosystem_dummies.columns)
        
        self.feature_categories['community_signals'].extend(community_features)
        
        logging.info(f"Created {len(community_features)} community signal features")
    
    def engineer_security_posture_features(self):
        """Create security-related features based on historical patterns"""
        logging.info("Engineering security posture features...")
        
        if len(self.historical_cves_df) > 0:
            # Historical vulnerability patterns per package
            vuln_stats = self.historical_cves_df.groupby('package_id').agg({
                'cve_id': 'count',
                'severity': lambda x: (x == 'CRITICAL').sum() if len(x) > 0 else 0,
                'published_date': ['min', 'max']
            }).reset_index()
            
            vuln_stats.columns = ['package_id', 'total_historical_vulns', 'critical_historical_vulns', 
                                 'first_vuln_date', 'last_vuln_date']
            
            # Merge with main dataframe
            self.packages_df = self.packages_df.merge(vuln_stats, left_on='id', right_on='package_id', how='left')
        
        # Fill missing values
        self.packages_df['total_historical_vulns'] = self.packages_df.get('total_historical_vulns', 0).fillna(0)
        self.packages_df['critical_historical_vulns'] = self.packages_df.get('critical_historical_vulns', 0).fillna(0)
        
        # Vulnerability frequency patterns
        self.packages_df['vuln_frequency_score'] = np.where(
            self.packages_df['total_historical_vulns'] == 0, 0,
            np.where(self.packages_df['total_historical_vulns'] <= 2, 1,
            np.where(self.packages_df['total_historical_vulns'] <= 5, 2,
            np.where(self.packages_df['total_historical_vulns'] <= 10, 3, 4)))
        )
        
        # Security-related naming patterns
        security_keywords = ['secure', 'auth', 'crypt', 'hash', 'token', 'ssl', 'tls', 'cert']
        self.packages_df['is_security_related'] = (
            self.packages_df['name'].str.lower().str.contains('|'.join(security_keywords)) |
            self.packages_df['description'].fillna('').str.lower().str.contains('|'.join(security_keywords))
        ).astype(int)
        
        # Add dependency complexity if available
        if len(self.dependencies_df) > 0:
            self.packages_df = self.packages_df.merge(
                self.dependencies_df, left_on='id', right_on='package_id', how='left'
            )
            self.packages_df['total_dependencies'] = self.packages_df['total_dependencies'].fillna(0)
            self.packages_df['unique_dependencies'] = self.packages_df['unique_dependencies'].fillna(0)
        else:
            self.packages_df['total_dependencies'] = 0
            self.packages_df['unique_dependencies'] = 0
        
        # Risk indicators
        self.packages_df['high_risk_indicators'] = (
            (self.packages_df['days_since_update'] > 365).astype(int) +
            (self.packages_df['total_historical_vulns'] > 5).astype(int) +
            (self.packages_df['critical_historical_vulns'] > 0).astype(int) +
            (self.packages_df['total_dependencies'] > 50).astype(int)
        )
        
        # Add to feature categories
        security_features = [
            'total_historical_vulns', 'critical_historical_vulns', 'vuln_frequency_score',
            'is_security_related', 'total_dependencies', 'unique_dependencies', 'high_risk_indicators'
        ]
        self.feature_categories['security_posture'].extend(security_features)
        
        logging.info(f"Created {len(security_features)} security posture features")
    
    def engineer_temporal_patterns(self):
        """Create time-based pattern features"""
        logging.info("Engineering temporal pattern features...")
        
        # Package age categories
        self.packages_df['age_category'] = pd.cut(
            self.packages_df['package_age_days'], 
            bins=[0, 365, 1095, 2190, float('inf')],
            labels=['new', 'young', 'mature', 'old']
        )
        
        # Update recency categories
        self.packages_df['update_recency'] = pd.cut(
            self.packages_df['days_since_update'],
            bins=[0, 30, 90, 365, float('inf')],
            labels=['very_recent', 'recent', 'stale', 'abandoned']
        )
        
        # Encode categorical features
        age_cat_dummies = pd.get_dummies(self.packages_df['age_category'], prefix='age')
        update_rec_dummies = pd.get_dummies(self.packages_df['update_recency'], prefix='update_rec')
        
        self.packages_df = pd.concat([self.packages_df, age_cat_dummies, update_rec_dummies], axis=1)
        
        # Add to feature categories
        temporal_features = list(age_cat_dummies.columns) + list(update_rec_dummies.columns)
        self.feature_categories['temporal_patterns'].extend(temporal_features)
        
        logging.info(f"Created {len(temporal_features)} temporal pattern features")
    
    def create_composite_risk_scores(self):
        """Create composite risk indicators"""
        logging.info("Creating composite risk scores...")
        
        # Normalize key metrics for composite scoring
        risk_components = {
            'maintenance_risk': (
                (self.packages_df['days_since_update'] > 365).astype(int) * 0.4 +
                (self.packages_df['update_frequency_score'] <= 2).astype(int) * 0.3 +
                (self.packages_df['maintainer_count'] <= 1).astype(int) * 0.3
            ),
            'security_history_risk': (
                np.clip(self.packages_df['total_historical_vulns'] / 10, 0, 1) * 0.6 +
                np.clip(self.packages_df['critical_historical_vulns'] / 3, 0, 1) * 0.4
            ),
            'community_risk': (
                (1 - self.packages_df['community_engagement_score'] / 5) * 0.5 +
                (self.packages_df['log_star_count'] < 2).astype(int) * 0.3 +
                (self.packages_df['maintainer_count'] <= 1).astype(int) * 0.2
            ),
            'dependency_risk': (
                np.clip(self.packages_df['total_dependencies'] / 100, 0, 1) * 0.6 +
                (self.packages_df['unique_dependencies'] > 20).astype(int) * 0.4
            )
        }
        
        # Add component scores
        for risk_type, score in risk_components.items():
            self.packages_df[risk_type] = score
        
        # Overall composite risk score
        self.packages_df['composite_risk_score'] = (
            self.packages_df['maintenance_risk'] * 0.3 +
            self.packages_df['security_history_risk'] * 0.3 +
            self.packages_df['community_risk'] * 0.2 +
            self.packages_df['dependency_risk'] * 0.2
        )
        
        composite_features = list(risk_components.keys()) + ['composite_risk_score']
        self.feature_categories['composite_scores'] = composite_features
        
        logging.info(f"Created {len(composite_features)} composite risk features")
    
    def prepare_ml_datasets(self):
        """Prepare final datasets for ML training"""
        logging.info("Preparing ML-ready datasets...")
        
        # Collect all feature columns
        all_features = []
        for category, features in self.feature_categories.items():
            all_features.extend(features)
        
        # Remove any non-existent columns
        existing_features = [f for f in all_features if f in self.packages_df.columns]
        
        # Create feature matrix
        X = self.packages_df[existing_features].copy()
        
        # Handle missing values
        for col in X.columns:
            if X[col].dtype in ['object']:
                X[col] = X[col].fillna('unknown')
            else:
                X[col] = X[col].fillna(X[col].median())
        
        # Create target variables
        y_train = self.packages_df['has_training_vuln']
        y_validation = self.packages_df['has_validation_vuln']
        y_train_critical = self.packages_df['has_critical_training_vuln']
        y_train_high = self.packages_df['has_high_training_vuln']
        
        self.ml_datasets = {
            'X': X,
            'y_train': y_train,
            'y_validation': y_validation,
            'y_train_critical': y_train_critical,
            'y_train_high': y_train_high,
            'feature_names': existing_features,
            'package_ids': self.packages_df['id'].values,
            'package_names': self.packages_df['name'].values
        }
        
        logging.info(f"Created ML dataset with {X.shape[1]} features and {X.shape[0]} samples")
        logging.info(f"Training labels - Vulnerable: {y_train.sum()}, Safe: {(~y_train.astype(bool)).sum()}")
        logging.info(f"Validation labels - Vulnerable: {y_validation.sum()}, Safe: {(~y_validation.astype(bool)).sum()}")
        
        return self.ml_datasets
    
    def save_engineered_features(self):
        """Save engineered features to database and files"""
        logging.info("Saving engineered features...")
        
        conn = self.connect_db()
        
        # Save feature matrix
        features_df = self.packages_df.copy()
        features_df.to_sql('engineered_features', conn, if_exists='replace', index=False)
        
        # Save ML datasets
        datasets = self.ml_datasets
        
        # Save as CSV for external use
        datasets['X'].to_csv('cassandrasec_features.csv', index=False)
        
        # Save feature metadata
        feature_metadata = {
            'total_features': len(datasets['feature_names']),
            'feature_categories': {k: len(v) for k, v in self.feature_categories.items()},
            'feature_names': datasets['feature_names'],
            'dataset_shape': list(datasets['X'].shape),
            'class_distribution': {
                'training_vulnerable': int(datasets['y_train'].sum()),
                'training_safe': int((~datasets['y_train'].astype(bool)).sum()),
                'validation_vulnerable': int(datasets['y_validation'].sum()),
                'validation_safe': int((~datasets['y_validation'].astype(bool)).sum())
            }
        }
        
        with open('feature_metadata.json', 'w') as f:
            json.dump(feature_metadata, f, indent=2)
        
        conn.close()
        
        logging.info("All engineered features saved successfully")
        return feature_metadata
    
    def run_complete_feature_engineering(self):
        """Run the complete feature engineering pipeline"""
        print("="*70)
        print("CASSANDRASEC ADVANCED FEATURE ENGINEERING PIPELINE")
        print("="*70)
        print("Transforming raw data into ML-ready features...")
        print("Creating 100+ sophisticated risk prediction features")
        print("="*70)
        
        try:
            # Inspect database first
            self.inspect_database_structure()
            
            # Load data
            self.load_base_data()
            
            # Create target labels
            self.create_target_labels()
            
            # Engineer all feature categories
            self.engineer_maintainer_health_features()
            self.engineer_community_signals()
            self.engineer_security_posture_features()
            self.engineer_temporal_patterns()
            self.create_composite_risk_scores()
            
            # Prepare final ML datasets
            datasets = self.prepare_ml_datasets()
            
            # Save everything
            metadata = self.save_engineered_features()
            
            # Print summary
            print("\n" + "="*70)
            print("CASSANDRASEC FEATURE ENGINEERING SUMMARY")
            print("="*70)
            print(f"TOTAL FEATURES CREATED: {metadata['total_features']}")
            print(f"TOTAL PACKAGES PROCESSED: {datasets['X'].shape[0]}")
            print(f"TRAINING VULNERABLE PACKAGES: {metadata['class_distribution']['training_vulnerable']}")
            print(f"VALIDATION VULNERABLE PACKAGES: {metadata['class_distribution']['validation_vulnerable']}")
            print()
            print("FEATURE CATEGORIES:")
            for category, count in metadata['feature_categories'].items():
                print(f"   -- {category.upper()}: {count} features")
            print()
            print("FILES CREATED:")
            print("   -- cassandrasec_features.csv (ML feature matrix)")
            print("   -- feature_metadata.json (feature documentation)")
            print("   -- engineered_features table (database)")
            print()
            print("READY FOR ML MODEL TRAINING!")
            print("="*70)
            
            return datasets, metadata
            
        except Exception as e:
            logging.error(f"Feature engineering failed: {str(e)}")
            raise

if __name__ == "__main__":
    # Run the complete feature engineering pipeline
    engineer = CassandraSecFeatureEngineer()
    
    try:
        # Execute the full pipeline
        datasets, metadata = engineer.run_complete_feature_engineering()
        
        # Optional: Quick data quality checks
        print("\nDATA QUALITY CHECKS:")
        print("="*50)
        
        X = datasets['X']
        
        # Check for missing values
        missing_features = X.isnull().sum()
        problematic_features = missing_features[missing_features > 0]
        
        if len(problematic_features) > 0:
            print(f"Features with missing values: {len(problematic_features)}")
            for feature, count in problematic_features.head().items():
                print(f"   -- {feature}: {count} missing values")
        else:
            print("No missing values detected")
        
        # Check feature distributions
        zero_variance_features = X.var() == 0
        if zero_variance_features.any():
            print(f"Zero variance features: {zero_variance_features.sum()}")
        else:
            print("All features have variance")
        
        # Dataset balance check
        
        # Feature correlation check
        high_corr_pairs = []
        corr_matrix = X.corr().abs()
        
        for i in range(len(corr_matrix.columns)):
            for j in range(i+1, len(corr_matrix.columns)):
                if corr_matrix.iloc[i, j] > 0.95:
                    high_corr_pairs.append((
                        corr_matrix.columns[i], 
                        corr_matrix.columns[j], 
                        corr_matrix.iloc[i, j]
                    ))
        
        if high_corr_pairs:
            print(f"Highly correlated feature pairs (>0.95): {len(high_corr_pairs)}")
            for feat1, feat2, corr in high_corr_pairs[:5]:
                print(f"   └── {feat1} <-> {feat2}: {corr:.3f}")
        else:
            print("No highly correlated features detected")
        
        # Dataset balance check
        train_balance = datasets['y_train'].mean()
        val_balance = datasets['y_validation'].mean()
        
        print(f"\nDATASET BALANCE:")
        print(f"   └── Training set: {train_balance:.1%} vulnerable packages")
        print(f"   └── Validation set: {val_balance:.1%} vulnerable packages")
        
        if train_balance < 0.01 or train_balance > 0.99:
            print("Highly imbalanced dataset - consider sampling strategies")
        else:
            print("Dataset balance is reasonable")
        
        print("\n NEXT STEPS:")
        print("   1. Review feature_metadata.json for detailed feature documentation")
        print("   2. Load cassandrasec_features.csv for ML model training")
        print("   3. Consider feature selection based on correlation analysis")
        print("   4. Apply appropriate sampling if dataset is imbalanced")
        print("   5. Scale features before training (StandardScaler recommended)")
        
    except Exception as e:
        print(f"\n PIPELINE FAILED: {str(e)}")
        logging.error(f"Pipeline execution failed: {str(e)}", exc_info=True)
        exit(1)
    
    print(f"\nCASSANDRASEC FEATURE ENGINEERING COMPLETED SUCCESSFULLY!")
    print("="*70)