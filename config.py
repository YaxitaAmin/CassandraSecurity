"""
CassandraSec Configuration - World's First Dependency Risk Predictor
Configuration management for data sources, APIs, and ML models
"""

import os
from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path
import yaml
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

@dataclass
class DatabaseConfig:
    """Database configuration for storing historical data"""
    host: str = os.getenv('DB_HOST', 'localhost')
    port: int = int(os.getenv('DB_PORT', '5432'))
    name: str = os.getenv('DB_NAME', 'riskanalysis')
    user: str = os.getenv('DB_USER', 'postgres')
    password: str = os.getenv('DB_PASSWORD', '2003')
    
    @property
    def url(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"

@dataclass
class APIConfig:
    """API keys and endpoints for data collection"""
    # GitHub API for repository analysis
    github_token: str = os.getenv('GITHUB_TOKEN', '')
    github_api_url: str = 'https://api.github.com'
    
    # NVD API for CVE data
    nvd_api_key: str = os.getenv('NVD_API_KEY', '')
    nvd_api_url: str = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    
    # Package registry APIs
    npm_registry_url: str = 'https://registry.npmjs.org'
    pypi_api_url: str = 'https://pypi.org/pypi'
    maven_central_url: str = 'https://search.maven.org/solrsearch/select'
    
    # Security advisory feeds
    github_advisories_url: str = 'https://api.github.com/advisories'
    npm_advisories_url: str = 'https://github.com/advisories.json'

@dataclass
class MLConfig:
    """Machine Learning model configuration"""
    # Model architecture
    gnn_hidden_dim: int = 256
    lstm_hidden_dim: int = 128
    bert_model: str = 'distilbert-base-uncased'
    ensemble_weights: List[float] = None
    
    # Training parameters
    learning_rate: float = 0.001
    batch_size: int = 32
    epochs: int = 100
    early_stopping_patience: int = 10
    
    # Cross-validation
    cv_folds: int = 5
    test_split: float = 0.2
    
    # Feature engineering
    time_window_days: int = 365
    min_package_age_days: int = 90
    
    def __post_init__(self):
        if self.ensemble_weights is None:
            self.ensemble_weights = [0.4, 0.3, 0.3]  # GNN, LSTM, BERT

@dataclass
class DataConfig:
    """Data collection and processing configuration"""
    # Time ranges for historical analysis
    training_start_date: str = '2020-01-01'
    training_end_date: str = '2022-12-31'
    validation_start_date: str = '2023-01-01'
    validation_end_date: str = '2024-12-31'
    
    # Package ecosystems to analyze
    ecosystems: List[str] = None
    
    # Data collection limits
    max_packages_per_ecosystem: int = 10000
    max_dependencies_depth: int = 3
    api_rate_limit_delay: float = 1.0
    
    # Risk thresholds
    high_risk_threshold: float = 0.8
    medium_risk_threshold: float = 0.5
    
    def __post_init__(self):
        if self.ecosystems is None:
            self.ecosystems = ['npm', 'pypi', 'maven', 'nuget', 'rubygems']

@dataclass
class PredictionTargets:
    """Definition of what incidents we're trying to predict"""
    incident_types: List[str] = None
    severity_levels: List[str] = None
    prediction_horizon_days: int = 180  # Predict 6 months ahead
    
    def __post_init__(self):
        if self.incident_types is None:
            self.incident_types = [
                'security_vulnerability',
                'malicious_package',
                'maintainer_abandonment',
                'breaking_changes',
                'license_issues',
                'dependency_confusion'
            ]
        
        if self.severity_levels is None:
            self.severity_levels = ['critical', 'high', 'medium', 'low']

class CassandraConfig:
    """Main configuration class for CassandraSec"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.db = DatabaseConfig()
        self.api = APIConfig()
        self.ml = MLConfig()
        self.data = DataConfig()
        self.targets = PredictionTargets()
        
        # Load custom config if provided
        if config_file and Path(config_file).exists():
            self._load_config_file(config_file)
        
        # Validate configuration
        self._validate_config()
    
    def _load_config_file(self, config_file: str):
        """Load configuration from YAML file"""
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)
        
        # Update configurations with file data
        for section, data in config_data.items():
            if hasattr(self, section):
                config_obj = getattr(self, section)
                for key, value in data.items():
                    if hasattr(config_obj, key):
                        setattr(config_obj, key, value)
    
    def _validate_config(self):
        """Validate configuration settings"""
        # Check required API keys
        if not self.api.github_token:
            raise ValueError("GitHub token is required for data collection")
        
        # Validate date ranges
        from datetime import datetime
        train_start = datetime.strptime(self.data.training_start_date, '%Y-%m-%d')
        train_end = datetime.strptime(self.data.training_end_date, '%Y-%m-%d')
        val_start = datetime.strptime(self.data.validation_start_date, '%Y-%m-%d')
        
        if train_start >= train_end:
            raise ValueError("Training start date must be before end date")
        
        if val_start <= train_end:
            raise ValueError("Validation period must be after training period")
        
        # Validate ML parameters
        if not (0 < self.ml.learning_rate < 1):
            raise ValueError("Learning rate must be between 0 and 1")
        
        if sum(self.ml.ensemble_weights) != 1.0:
            raise ValueError("Ensemble weights must sum to 1.0")
    
    def save_config(self, output_file: str):
        """Save current configuration to YAML file"""
        config_dict = {
            'db': self.db.__dict__,
            'api': {k: v for k, v in self.api.__dict__.items() if not k.endswith('_token')},
            'ml': self.ml.__dict__,
            'data': self.data.__dict__,
            'targets': self.targets.__dict__
        }
        
        with open(output_file, 'w') as f:
            yaml.dump(config_dict, f, default_flow_style=False, indent=2)
    
    def get_model_path(self, model_name: str) -> str:
        """Get path for saving/loading models"""
        model_dir = Path('models')
        model_dir.mkdir(exist_ok=True)
        return str(model_dir / f"{model_name}.pkl")
    
    def get_data_path(self, data_type: str) -> str:
        """Get path for saving/loading data"""
        data_dir = Path('data')
        data_dir.mkdir(exist_ok=True)
        return str(data_dir / f"{data_type}.parquet")

# Global configuration instance
config = CassandraConfig()

# Feature engineering configuration
RISK_FEATURES = {
    'maintainer_health': [
        'avg_response_time_trend',
        'commit_frequency_decline',
        'inactive_days_count',
        'maintainer_count',
        'bus_factor_score'
    ],
    'community_signals': [
        'issue_resolution_time_trend',
        'pr_acceptance_rate',
        'contributor_diversity_index',
        'community_activity_score',
        'documentation_quality_score'
    ],
    'code_quality': [
        'test_coverage_trend',
        'code_complexity_trend',
        'security_scan_score',
        'dependency_staleness',
        'breaking_change_frequency'
    ],
    'dependency_patterns': [
        'dependency_count_growth',
        'circular_dependency_count',
        'outdated_dependency_ratio',
        'high_risk_dependency_count',
        'dependency_churn_rate'
    ],
    'security_posture': [
        'vulnerability_response_time',
        'security_advisory_count',
        'cve_severity_distribution',
        'patch_adoption_speed',
        'security_best_practices_score'
    ]
}

# Logging configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
        'detailed': {
            'format': '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s'
        }
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'standard'
        },
        'file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logs/cassandra_sec.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5,
            'formatter': 'detailed'
        }
    },
    'loggers': {
        'cassandra_sec': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False
        }
    }
}