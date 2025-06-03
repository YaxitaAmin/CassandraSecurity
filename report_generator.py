import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from jinja2 import Template
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import base64
from io import BytesIO
import warnings
warnings.filterwarnings('ignore')

@dataclass
class RiskPackage:
    name: str
    version: str
    risk_score: float
    risk_level: str
    primary_concerns: List[str]
    recommendation: str
    impact_score: float
    confidence: float

@dataclass
class ReportMetrics:
    total_packages: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    avg_risk_score: float
    critical_packages: List[str]
    model_accuracy: float
    last_updated: datetime

class RiskReportGenerator:
    def __init__(self, config_path: str = "config.py"):
        self.setup_logging()
        self.load_config(config_path)
        self.risk_thresholds = {
            'high': 0.7,
            'medium': 0.4,
            'low': 0.0
        }
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
    def load_config(self, config_path: str):
        try:
            with open(config_path, 'r') as f:
                # Simple config loading - adjust based on your config format
                self.config = {}
        except FileNotFoundError:
            self.logger.warning(f"Config file {config_path} not found, using defaults")
            self.config = {}
    
    def generate_comprehensive_report(self, 
                                    predictions_df: pd.DataFrame,
                                    model_metrics: Dict,
                                    output_dir: str = "./reports") -> Dict[str, str]:
        """Generate comprehensive risk assessment report package."""
        
        self.logger.info("Starting comprehensive report generation...")
        
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Process predictions data
        processed_data = self._process_predictions(predictions_df)
        report_metrics = self._calculate_metrics(processed_data, model_metrics)
        
        # Generate different report formats
        reports = {}
        
        # 1. Executive Summary (JSON)
        exec_summary = self._generate_executive_summary(report_metrics, processed_data)
        exec_path = f"{output_dir}/executive_summary_{timestamp}.json"
        with open(exec_path, 'w') as f:
            json.dump(exec_summary, f, indent=2, default=str)
        reports['executive_summary'] = exec_path
        
        # 2. Detailed Technical Report (HTML)
        html_report = self._generate_html_report(report_metrics, processed_data, model_metrics)
        html_path = f"{output_dir}/detailed_report_{timestamp}.html"
        with open(html_path, 'w') as f:
            f.write(html_report)
        reports['detailed_html'] = html_path
        
        # 3. Risk Register (CSV)
        risk_register = self._generate_risk_register(processed_data)
        csv_path = f"{output_dir}/risk_register_{timestamp}.csv"
        risk_register.to_csv(csv_path, index=False)
        reports['risk_register'] = csv_path
        
        # 4. Action Items (JSON)
        action_items = self._generate_action_items(processed_data)
        actions_path = f"{output_dir}/action_items_{timestamp}.json"
        with open(actions_path, 'w') as f:
            json.dump(action_items, f, indent=2)
        reports['action_items'] = actions_path
        
        self.logger.info(f"Reports generated successfully in {output_dir}")
        return reports
    
    def _process_predictions(self, df: pd.DataFrame) -> List[RiskPackage]:
        """Process raw predictions into structured risk packages."""
        
        processed = []
        
        for _, row in df.iterrows():
            # Extract risk level
            risk_score = float(row.get('risk_score', row.get('composite_risk_score', 0.5)))
            risk_level = self._determine_risk_level(risk_score)
            
            # Identify primary concerns
            concerns = self._identify_concerns(row)
            
            # Generate recommendation
            recommendation = self._generate_recommendation(risk_score, concerns, row)
            
            # Calculate impact score
            impact_score = self._calculate_impact_score(row)
            
            # Calculate confidence
            confidence = self._calculate_confidence(row)
            
            package = RiskPackage(
                name=row.get('package_name', 'Unknown'),
                version=row.get('version', 'latest'),
                risk_score=risk_score,
                risk_level=risk_level,
                primary_concerns=concerns,
                recommendation=recommendation,
                impact_score=impact_score,
                confidence=confidence
            )
            processed.append(package)
        
        return sorted(processed, key=lambda x: x.risk_score, reverse=True)
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level based on score."""
        if score >= self.risk_thresholds['high']:
            return 'HIGH'
        elif score >= self.risk_thresholds['medium']:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _identify_concerns(self, row: pd.Series) -> List[str]:
        """Identify primary risk concerns for a package."""
        concerns = []
        
        # Maintainer health concerns
        if row.get('maintenance_risk', 0) > 0.6:
            concerns.append("Poor maintainer responsiveness")
        if row.get('days_since_update', 365) > 180:
            concerns.append("Stale package - no recent updates")
        
        # Security concerns
        if row.get('security_history_risk', 0) > 0.5:
            concerns.append("History of security vulnerabilities")
        if row.get('total_historical_vulns', 0) > 2:
            concerns.append("Multiple past vulnerabilities")
        
        # Community concerns
        if row.get('community_risk', 0) > 0.6:
            concerns.append("Weak community support")
        if row.get('maintainer_count', 1) < 2:
            concerns.append("Single maintainer dependency")
        
        # Dependency concerns
        if row.get('dependency_risk', 0) > 0.5:
            concerns.append("Complex dependency chain")
        if row.get('total_dependencies', 0) > 50:
            concerns.append("High dependency count")
        
        # Age concerns
        if row.get('package_age_days', 0) < 90:
            concerns.append("Very new package - limited track record")
        
        return concerns[:5]  # Limit to top 5 concerns
    
    def _generate_recommendation(self, risk_score: float, concerns: List[str], row: pd.Series) -> str:
        """Generate specific recommendation based on risk profile."""
        
        if risk_score >= 0.8:
            return "CRITICAL: Immediate replacement required. Consider alternative packages or vendor solutions."
        elif risk_score >= 0.7:
            return "HIGH PRIORITY: Schedule replacement within 30 days. Implement additional monitoring."
        elif risk_score >= 0.5:
            return "MEDIUM PRIORITY: Review within 90 days. Consider alternatives and monitor closely."
        elif risk_score >= 0.3:
            return "LOW PRIORITY: Monitor quarterly. Acceptable for continued use with standard precautions."
        else:
            return "ACCEPTABLE: Package shows low risk indicators. Continue standard monitoring."
    
    def _calculate_impact_score(self, row: pd.Series) -> float:
        """Calculate business impact score."""
        
        # Base impact on download count (popularity)
        downloads = row.get('log_download_count', 0)
        base_impact = min(downloads / 10.0, 1.0)  # Normalize to 0-1
        
        # Adjust for dependency count (how many other packages depend on this)
        deps_factor = min(row.get('total_dependencies', 0) / 20.0, 0.5)
        
        # Adjust for security sensitivity
        if row.get('is_security_related', False):
            security_factor = 0.3
        else:
            security_factor = 0.0
        
        return min(base_impact + deps_factor + security_factor, 1.0)
    
    def _calculate_confidence(self, row: pd.Series) -> float:
        """Calculate prediction confidence."""
        
        # Base confidence on data completeness
        total_features = 41
        non_null_features = sum(1 for col in row.index if pd.notna(row[col]))
        data_completeness = non_null_features / total_features
        
        # Adjust for package maturity (more data = higher confidence)
        age_days = row.get('package_age_days', 0)
        maturity_factor = min(age_days / 365.0, 0.2)  # Up to 20% bonus for mature packages
        
        # Adjust for community size (more contributors = more reliable signals)
        contributors = row.get('log_contributors', 0)
        community_factor = min(contributors / 10.0, 0.1)  # Up to 10% bonus
        
        return min(data_completeness + maturity_factor + community_factor, 1.0)
    
    def _calculate_metrics(self, packages: List[RiskPackage], model_metrics: Dict) -> ReportMetrics:
        """Calculate overall report metrics."""
        
        high_risk = [p for p in packages if p.risk_level == 'HIGH']
        medium_risk = [p for p in packages if p.risk_level == 'MEDIUM']
        low_risk = [p for p in packages if p.risk_level == 'LOW']
        
        critical_packages = [p.name for p in packages if p.risk_score >= 0.8]
        avg_risk = np.mean([p.risk_score for p in packages])
        
        return ReportMetrics(
            total_packages=len(packages),
            high_risk_count=len(high_risk),
            medium_risk_count=len(medium_risk),
            low_risk_count=len(low_risk),
            avg_risk_score=avg_risk,
            critical_packages=critical_packages,
            model_accuracy=model_metrics.get('test_auc', 0.0),
            last_updated=datetime.now()
        )
    
    def _generate_executive_summary(self, metrics: ReportMetrics, packages: List[RiskPackage]) -> Dict:
        """Generate executive summary for leadership."""
        
        # Calculate business impact
        high_impact_high_risk = [p for p in packages 
                                if p.risk_level == 'HIGH' and p.impact_score > 0.6]
        
        # Risk trend analysis
        risk_distribution = {
            'critical': len([p for p in packages if p.risk_score >= 0.8]),
            'high': metrics.high_risk_count,
            'medium': metrics.medium_risk_count,
            'low': metrics.low_risk_count
        }
        
        # Priority actions
        immediate_actions = len([p for p in packages if p.risk_score >= 0.8])
        short_term_actions = len([p for p in packages if 0.7 <= p.risk_score < 0.8])
        
        return {
            "report_summary": {
                "scan_date": metrics.last_updated.isoformat(),
                "total_packages_analyzed": metrics.total_packages,
                "model_accuracy": f"{metrics.model_accuracy:.1%}",
                "overall_risk_score": f"{metrics.avg_risk_score:.2f}"
            },
            "key_findings": {
                "critical_risk_packages": len([p for p in packages if p.risk_score >= 0.8]),
                "high_business_impact_risks": len(high_impact_high_risk),
                "packages_requiring_immediate_action": immediate_actions,
                "packages_requiring_short_term_action": short_term_actions
            },
            "risk_distribution": risk_distribution,
            "top_risk_packages": [
                {
                    "name": p.name,
                    "risk_score": f"{p.risk_score:.2f}",
                    "impact_score": f"{p.impact_score:.2f}",
                    "primary_concern": p.primary_concerns[0] if p.primary_concerns else "Unknown"
                }
                for p in packages[:10]
            ],
            "recommended_immediate_actions": [
                f"Replace {p.name} - {p.primary_concerns[0] if p.primary_concerns else 'High risk'}"
                for p in packages if p.risk_score >= 0.8
            ][:5]
        }
    
    def _generate_html_report(self, metrics: ReportMetrics, packages: List[RiskPackage], model_metrics: Dict) -> str:
        """Generate detailed HTML report."""
        
        # Create visualizations
        risk_dist_chart = self._create_risk_distribution_chart(packages)
        top_risks_chart = self._create_top_risks_chart(packages[:20])
        
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>CassandraSec Risk Assessment Report</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .header { background: #2c3e50; color: white; padding: 20px; margin: -40px -40px 20px -40px; }
        .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }
        .metric-card { background: #f8f9fa; padding: 15px; border-left: 4px solid #007bff; }
        .metric-value { font-size: 2em; font-weight: bold; color: #007bff; }
        .risk-high { color: #dc3545; font-weight: bold; }
        .risk-medium { color: #fd7e14; font-weight: bold; }
        .risk-low { color: #28a745; font-weight: bold; }
        .package-list { margin: 20px 0; }
        .package-item { background: #f8f9fa; margin: 10px 0; padding: 15px; border-left: 4px solid #ccc; }
        .package-item.high { border-left-color: #dc3545; }
        .package-item.medium { border-left-color: #fd7e14; }
        .package-item.low { border-left-color: #28a745; }
        .concerns { margin: 10px 0; }
        .concern-item { background: #fff3cd; padding: 5px 10px; margin: 3px 0; border-radius: 3px; }
        .chart-container { margin: 30px 0; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>CassandraSec Risk Assessment Report</h1>
        <p>Generated: {{ report_date }} | Model Accuracy: {{ model_accuracy }}%</p>
    </div>
    
    <div class="metrics">
        <div class="metric-card">
            <div class="metric-value">{{ total_packages }}</div>
            <div>Total Packages</div>
        </div>
        <div class="metric-card">
            <div class="metric-value risk-high">{{ high_risk_count }}</div>
            <div>High Risk</div>
        </div>
        <div class="metric-card">
            <div class="metric-value risk-medium">{{ medium_risk_count }}</div>
            <div>Medium Risk</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{{ avg_risk_score }}</div>
            <div>Avg Risk Score</div>
        </div>
    </div>
    
    <div class="chart-container">
        {{ risk_distribution_chart }}
    </div>
    
    <div class="chart-container">
        {{ top_risks_chart }}
    </div>
    
    <h2>High Risk Packages - Immediate Action Required</h2>
    <div class="package-list">
        {% for package in high_risk_packages %}
        <div class="package-item high">
            <h3>{{ package.name }} ({{ package.version }})</h3>
            <p><strong>Risk Score:</strong> {{ "%.2f"|format(package.risk_score) }} | 
               <strong>Impact:</strong> {{ "%.2f"|format(package.impact_score) }} | 
               <strong>Confidence:</strong> {{ "%.0f"|format(package.confidence * 100) }}%</p>
            <p><strong>Recommendation:</strong> {{ package.recommendation }}</p>
            <div class="concerns">
                <strong>Primary Concerns:</strong>
                {% for concern in package.primary_concerns %}
                <div class="concern-item">{{ concern }}</div>
                {% endfor %}
            </div>
        </div>
        {% endfor %}
    </div>
    
    <h2>Model Performance Metrics</h2>
    <div class="metrics">
        <div class="metric-card">
            <div class="metric-value">{{ model_metrics.get('test_auc', 0) | round(4) }}</div>
            <div>Test AUC</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{{ model_metrics.get('high_risk_precision', 0) }}%</div>
            <div>High-Risk Precision</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{{ total_features }}</div>
            <div>Features Used</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{{ model_metrics.get('training_samples', 0) }}</div>
            <div>Training Samples</div>
        </div>
    </div>
</body>
</html>
        """
        
        template = Template(html_template)
        return template.render(
            report_date=metrics.last_updated.strftime("%Y-%m-%d %H:%M"),
            model_accuracy=f"{metrics.model_accuracy * 100:.1f}",
            total_packages=metrics.total_packages,
            high_risk_count=metrics.high_risk_count,
            medium_risk_count=metrics.medium_risk_count,
            avg_risk_score=f"{metrics.avg_risk_score:.2f}",
            high_risk_packages=[p for p in packages if p.risk_level == 'HIGH'],
            model_metrics=model_metrics,
            total_features=41,
            risk_distribution_chart=risk_dist_chart,
            top_risks_chart=top_risks_chart
        )
    
    def _generate_risk_register(self, packages: List[RiskPackage]) -> pd.DataFrame:
        """Generate risk register CSV for tracking."""
        
        data = []
        for pkg in packages:
            data.append({
                'Package_Name': pkg.name,
                'Version': pkg.version,
                'Risk_Score': pkg.risk_score,
                'Risk_Level': pkg.risk_level,
                'Impact_Score': pkg.impact_score,
                'Confidence': pkg.confidence,
                'Primary_Concerns': '; '.join(pkg.primary_concerns),
                'Recommendation': pkg.recommendation,
                'Date_Assessed': datetime.now().strftime('%Y-%m-%d'),
                'Status': 'Open',
                'Owner': '',
                'Target_Resolution_Date': '',
                'Notes': ''
            })
        
        return pd.DataFrame(data)
    
    def _generate_action_items(self, packages: List[RiskPackage]) -> Dict:
        """Generate prioritized action items."""
        
        immediate = [p for p in packages if p.risk_score >= 0.8]
        short_term = [p for p in packages if 0.7 <= p.risk_score < 0.8]
        medium_term = [p for p in packages if 0.5 <= p.risk_score < 0.7]
        
        return {
            "immediate_actions": [
                {
                    "priority": "CRITICAL",
                    "package": p.name,
                    "action": f"Replace {p.name}",
                    "reason": p.primary_concerns[0] if p.primary_concerns else "High risk",
                    "timeline": "Within 7 days",
                    "risk_score": p.risk_score
                }
                for p in immediate
            ],
            "short_term_actions": [
                {
                    "priority": "HIGH",
                    "package": p.name,
                    "action": f"Evaluate alternatives for {p.name}",
                    "reason": p.primary_concerns[0] if p.primary_concerns else "Elevated risk",
                    "timeline": "Within 30 days",
                    "risk_score": p.risk_score
                }
                for p in short_term
            ],
            "medium_term_actions": [
                {
                    "priority": "MEDIUM",
                    "package": p.name,
                    "action": f"Monitor {p.name} closely",
                    "reason": p.primary_concerns[0] if p.primary_concerns else "Moderate risk",
                    "timeline": "Within 90 days",
                    "risk_score": p.risk_score
                }
                for p in medium_term[:10]  # Limit to top 10
            ]
        }
    
    def _create_risk_distribution_chart(self, packages: List[RiskPackage]) -> str:
        """Create risk distribution chart."""
        
        risk_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for p in packages:
            risk_counts[p.risk_level] += 1
        
        fig = go.Figure(data=[
            go.Bar(
                x=list(risk_counts.keys()),
                y=list(risk_counts.values()),
                marker_color=['#dc3545', '#fd7e14', '#28a745']
            )
        ])
        
        fig.update_layout(
            title="Risk Distribution",
            xaxis_title="Risk Level",
            yaxis_title="Number of Packages"
        )
        
        return fig.to_html(include_plotlyjs='cdn')
    
    def _create_top_risks_chart(self, packages: List[RiskPackage]) -> str:
        """Create top risks chart."""
        
        names = [p.name[:20] + '...' if len(p.name) > 20 else p.name for p in packages]
        scores = [p.risk_score for p in packages]
        
        fig = go.Figure(data=[
            go.Bar(
                y=names,
                x=scores,
                orientation='h',
                marker_color='red'
            )
        ])
        
        fig.update_layout(
            title="Top 20 Risk Packages",
            xaxis_title="Risk Score",
            yaxis_title="Package Name",
            height=600
        )
        
        return fig.to_html(include_plotlyjs='cdn')

# Example usage
if __name__ == "__main__":
    # Sample usage
    generator = RiskReportGenerator()
    
    # Mock predictions data - replace with your actual predictions
    sample_data = pd.DataFrame({
        'package_name': ['vulnerable-pkg-1', 'risky-lib-2', 'safe-package-3'],
        'composite_risk_score': [0.85, 0.65, 0.25],
        'maintenance_risk': [0.8, 0.5, 0.2],
        'security_history_risk': [0.7, 0.6, 0.1],
        'days_since_update': [400, 60, 15],
        'total_historical_vulns': [3, 1, 0],
        'maintainer_count': [1, 2, 5]
    })
    
    model_metrics = {
        'test_auc': 0.7276,
        'high_risk_precision': 86.67,
        'training_samples': 2825
    }
    
    reports = generator.generate_comprehensive_report(sample_data, model_metrics)
    print("Generated reports:", reports)