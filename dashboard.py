import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
from datetime import datetime, timedelta
import logging
from pathlib import Path
import time
from typing import Dict, List, Optional
import warnings
warnings.filterwarnings('ignore')

# Page configuration
st.set_page_config(
    page_title="CassandraSec Risk Dashboard",
    page_icon="🔮",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional styling
st.markdown("""
<style>
    .main-header {
        padding: 1rem 0;
        background: linear-gradient(90deg, #2c3e50, #3498db);
        color: white;
        margin: -1rem -1rem 2rem -1rem;
        text-align: center;
    }
    .metric-card {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #007bff;
        margin: 0.5rem 0;
    }
    .risk-high { color: #dc3545; font-weight: bold; }
    .risk-medium { color: #fd7e14; font-weight: bold; }
    .risk-low { color: #28a745; font-weight: bold; }
    .alert-critical {
        background: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

class RiskDashboard:
    def __init__(self):
        self.setup_logging()
        self.data_cache = {}
        self.last_refresh = None
        
    def setup_logging(self):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    @st.cache_data
    def load_predictions_data(_self, file_path: str = None) -> pd.DataFrame:
        """Load predictions data with caching."""
        try:
            if file_path and Path(file_path).exists():
                return pd.read_csv(file_path)
            else:
                # Generate sample data for demo
                return _self._generate_sample_data()
        except Exception as e:
            st.error(f"Error loading data: {e}")
            return _self._generate_sample_data()

    def _generate_sample_data(self) -> pd.DataFrame:
        """Generate realistic sample data for demonstration."""
        np.random.seed(42)
        n_packages = 100
        
        # Package names with realistic distribution
        package_names = [
            f"package-{i:03d}" for i in range(1, 21)
        ] + [
            f"lib-{i:03d}" for i in range(1, 21)
        ] + [
            f"framework-{i:03d}" for i in range(1, 21)
        ] + [
            f"util-{i:03d}" for i in range(1, 21)
        ] + [
            f"component-{i:03d}" for i in range(1, 21)
        ]
        
        # Create realistic risk distribution
        high_risk_count = 15
        medium_risk_count = 35
        low_risk_count = 50
        
        risk_scores = (
            list(np.random.uniform(0.7, 1.0, high_risk_count)) +
            list(np.random.uniform(0.4, 0.7, medium_risk_count)) +
            list(np.random.uniform(0.0, 0.4, low_risk_count))
        )
        np.random.shuffle(risk_scores)
        
        data = {
            'package_name': np.random.choice(package_names, n_packages),
            'version': np.random.choice(['1.0.0', '2.1.0', '3.2.1', '0.9.5'], n_packages),
            'composite_risk_score': risk_scores,
            'maintenance_risk': np.random.uniform(0, 1, n_packages),
            'security_history_risk': np.random.uniform(0, 1, n_packages),
            'community_risk': np.random.uniform(0, 1, n_packages),
            'dependency_risk': np.random.uniform(0, 1, n_packages),
            'package_age_days': np.random.randint(30, 2000, n_packages),
            'days_since_update': np.random.randint(1, 500, n_packages),
            'total_historical_vulns': np.random.poisson(0.5, n_packages),
            'log_download_count': np.random.uniform(3, 12, n_packages),
            'maintainer_count': np.random.randint(1, 10, n_packages),
            'log_contributors': np.random.uniform(0, 4, n_packages),
            'ecosystem_npm': np.random.choice([0, 1], n_packages, p=[0.6, 0.4]),
            'ecosystem_pypi': np.random.choice([0, 1], n_packages, p=[0.4, 0.6])
        }
        
        return pd.DataFrame(data)

    def render_header(self):
        """Render dashboard header."""
        st.markdown("""
        <div class="main-header">
            <h1>🔮 CassandraSec Risk Assessment Dashboard</h1>
            <p>Real-time Dependency Risk Monitoring & Prediction</p>
        </div>
        """, unsafe_allow_html=True)

    def render_sidebar(self, df: pd.DataFrame):
        """Render sidebar with filters and controls."""
        st.sidebar.title("Dashboard Controls")
        
        # Data refresh
        if st.sidebar.button("🔄 Refresh Data", type="primary"):
            st.cache_data.clear()
            st.rerun()
        
        # Filters
        st.sidebar.subheader("Filters")
        
        # Risk level filter
        risk_levels = st.sidebar.multiselect(
            "Risk Levels",
            options=["HIGH", "MEDIUM", "LOW"],
            default=["HIGH", "MEDIUM", "LOW"]
        )
        
        # Ecosystem filter
        ecosystems = []
        if df['ecosystem_npm'].sum() > 0:
            ecosystems.append("NPM")
        if df['ecosystem_pypi'].sum() > 0:
            ecosystems.append("PyPI")
        
        selected_ecosystems = st.sidebar.multiselect(
            "Ecosystems",
            options=ecosystems,
            default=ecosystems
        )
        
        # Risk score range
        min_risk, max_risk = st.sidebar.slider(
            "Risk Score Range",
            min_value=0.0,
            max_value=1.0,
            value=(0.0, 1.0),
            step=0.05
        )
        
        # Package age filter
        max_age = st.sidebar.slider(
            "Maximum Package Age (days)",
            min_value=30,
            max_value=int(df['package_age_days'].max()),
            value=int(df['package_age_days'].max())
        )
        
        return {
            'risk_levels': risk_levels,
            'ecosystems': selected_ecosystems,
            'risk_range': (min_risk, max_risk),
            'max_age': max_age
        }
    def apply_filters(self, df: pd.DataFrame, filters: Dict) -> pd.DataFrame:
        """Apply selected filters to dataframe."""
        filtered_df = df.copy()
        
        # Risk level filter
        risk_mapping = {
            "HIGH": (0.7, 1.0),
            "MEDIUM": (0.4, 0.7),
            "LOW": (0.0, 0.4)
        }
        
        if filters['risk_levels']:
            risk_mask = pd.Series([False] * len(filtered_df), index=filtered_df.index)
            for level in filters['risk_levels']:
                min_score, max_score = risk_mapping[level]
                risk_mask |= (
                    (filtered_df['composite_risk_score'] >= min_score) & 
                    (filtered_df['composite_risk_score'] < max_score)
                )
            filtered_df = filtered_df[risk_mask]
        
        # Ecosystem filter
        if filters['ecosystems']:
            ecosystem_mask = pd.Series([False] * len(filtered_df), index=filtered_df.index)
            if "NPM" in filters['ecosystems']:
                ecosystem_mask |= filtered_df['ecosystem_npm'] == 1
            if "PyPI" in filters['ecosystems']:
                ecosystem_mask |= filtered_df['ecosystem_pypi'] == 1
            filtered_df = filtered_df[ecosystem_mask]
        
        # Risk score range
        min_risk, max_risk = filters['risk_range']
        filtered_df = filtered_df[
            (filtered_df['composite_risk_score'] >= min_risk) &
            (filtered_df['composite_risk_score'] <= max_risk)
        ]
        
        # Age filter
        filtered_df = filtered_df[filtered_df['package_age_days'] <= filters['max_age']]
        
        return filtered_df

    def render_key_metrics(self, df: pd.DataFrame):
        """Render key metrics cards."""
        col1, col2, col3, col4, col5 = st.columns(5)
        
        # Calculate metrics
        total_packages = len(df)
        high_risk = len(df[df['composite_risk_score'] >= 0.7])
        medium_risk = len(df[(df['composite_risk_score'] >= 0.4) & (df['composite_risk_score'] < 0.7)])
        critical_packages = len(df[df['composite_risk_score'] >= 0.8])
        avg_risk = df['composite_risk_score'].mean()
        
        with col1:
            st.metric(
                label="Total Packages",
                value=f"{total_packages:,}",
                delta=None
            )
        
        with col2:
            st.metric(
                label="High Risk",
                value=f"{high_risk:,}",
                delta=f"{high_risk/total_packages*100:.1f}%"
            )
        
        with col3:
            st.metric(
                label="Critical Risk",
                value=f"{critical_packages:,}",
                delta=f"{critical_packages/total_packages*100:.1f}%"
            )
        
        with col4:
            st.metric(
                label="Medium Risk",
                value=f"{medium_risk:,}",
                delta=f"{medium_risk/total_packages*100:.1f}%"
            )
        
        with col5:
            st.metric(
                label="Avg Risk Score",
                value=f"{avg_risk:.3f}",
                delta=f"{'High' if avg_risk > 0.5 else 'Moderate'}"
            )

    def render_critical_alerts(self, df: pd.DataFrame):
        """Render critical risk alerts."""
        critical_packages = df[df['composite_risk_score'] >= 0.8].sort_values(
            'composite_risk_score', ascending=False
        )
        
        if len(critical_packages) > 0:
            st.markdown("""
            <div class="alert-critical">
                <h4>⚠️ Critical Risk Packages Requiring Immediate Action</h4>
            </div>
            """, unsafe_allow_html=True)
            
            for _, pkg in critical_packages.head(5).iterrows():
                col1, col2, col3 = st.columns([3, 1, 2])
                with col1:
                    st.write(f"**{pkg['package_name']}** v{pkg['version']}")
                with col2:
                    st.write(f"Risk: **{pkg['composite_risk_score']:.3f}**")
                with col3:
                    if pkg['days_since_update'] > 180:
                        st.write("🔴 Stale package")
                    elif pkg['total_historical_vulns'] > 2:
                        st.write("🔴 Multiple vulnerabilities")
                    else:
                        st.write("🔴 High risk indicators")

    def render_risk_distribution(self, df: pd.DataFrame):
        """Render risk distribution charts."""
        col1, col2 = st.columns(2)
        
        with col1:
            # Risk level distribution
            risk_counts = {
                'High (≥0.7)': len(df[df['composite_risk_score'] >= 0.7]),
                'Medium (0.4-0.7)': len(df[(df['composite_risk_score'] >= 0.4) & (df['composite_risk_score'] < 0.7)]),
                'Low (<0.4)': len(df[df['composite_risk_score'] < 0.4])
            }
            
            fig_pie = px.pie(
                values=list(risk_counts.values()),
                names=list(risk_counts.keys()),
                title="Risk Distribution",
                color_discrete_map={
                    'High (≥0.7)': '#dc3545',
                    'Medium (0.4-0.7)': '#fd7e14',
                    'Low (<0.4)': '#28a745'
                }
            )
            fig_pie.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig_pie, use_container_width=True)
        
        with col2:
            # Risk score histogram
            fig_hist = px.histogram(
                df,
                x='composite_risk_score',
                nbins=20,
                title="Risk Score Distribution",
                labels={'composite_risk_score': 'Risk Score', 'count': 'Package Count'}
            )
            fig_hist.update_layout(bargap=0.1)
            st.plotly_chart(fig_hist, use_container_width=True)

    def render_top_risks_analysis(self, df: pd.DataFrame):
        """Render top risks analysis."""
        st.subheader("🎯 Top Risk Packages Analysis")
        
        top_risks = df.nlargest(20, 'composite_risk_score')
        
        # Top risks bar chart
        fig_bar = px.bar(
            top_risks,
            y='package_name',
            x='composite_risk_score',
            orientation='h',
            title="Top 20 Highest Risk Packages",
            labels={'composite_risk_score': 'Risk Score', 'package_name': 'Package'},
            color='composite_risk_score',
            color_continuous_scale='Reds'
        )
        fig_bar.update_layout(height=600)
        st.plotly_chart(fig_bar, use_container_width=True)

    def render_risk_factors_analysis(self, df: pd.DataFrame):
        """Render risk factors correlation analysis."""
        st.subheader("🔍 Risk Factors Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Risk factors correlation
            risk_factors = [
                'maintenance_risk', 'security_history_risk', 
                'community_risk', 'dependency_risk'
            ]
            
            correlation_data = []
            for factor in risk_factors:
                corr = df['composite_risk_score'].corr(df[factor])
                correlation_data.append({
                    'Factor': factor.replace('_', ' ').title().replace(' Risk', ''),
                    'Correlation': corr
                })
            
            corr_df = pd.DataFrame(correlation_data)
            fig_corr = px.bar(
                corr_df,
                x='Correlation',
                y='Factor',
                orientation='h',
                title="Risk Factor Correlations",
                color='Correlation',
                color_continuous_scale='RdYlBu_r'
            )
            st.plotly_chart(fig_corr, use_container_width=True)
        
        with col2:
            # Package age vs risk scatter
            fig_scatter = px.scatter(
                df.sample(min(200, len(df))),  # Sample for performance
                x='package_age_days',
                y='composite_risk_score',
                size='log_download_count',
                color='maintainer_count',
                title="Package Age vs Risk Score",
                labels={
                    'package_age_days': 'Package Age (Days)',
                    'composite_risk_score': 'Risk Score',
                    'maintainer_count': 'Maintainers'
                }
            )
            st.plotly_chart(fig_scatter, use_container_width=True)

    def render_ecosystem_analysis(self, df: pd.DataFrame):
        """Render ecosystem-specific analysis."""
        st.subheader("🌐 Ecosystem Analysis")
        
        # Create ecosystem labels
        df_eco = df.copy()
        df_eco['ecosystem'] = 'Unknown'
        df_eco.loc[df_eco['ecosystem_npm'] == 1, 'ecosystem'] = 'NPM'
        df_eco.loc[df_eco['ecosystem_pypi'] == 1, 'ecosystem'] = 'PyPI'
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Average risk by ecosystem
            eco_stats = df_eco.groupby('ecosystem').agg({
                'composite_risk_score': ['mean', 'count'],
                'total_historical_vulns': 'mean'
            }).round(3)
            
            eco_stats.columns = ['Avg Risk Score', 'Package Count', 'Avg Vulnerabilities']
            st.write("**Ecosystem Risk Statistics**")
            st.dataframe(eco_stats)
        
        with col2:
            # Risk distribution by ecosystem
            fig_box = px.box(
                df_eco[df_eco['ecosystem'] != 'Unknown'],
                x='ecosystem',
                y='composite_risk_score',
                title="Risk Distribution by Ecosystem"
            )
            st.plotly_chart(fig_box, use_container_width=True)

    def render_detailed_package_table(self, df: pd.DataFrame):
        """Render detailed package information table."""
        st.subheader("📋 Detailed Package Information")
        
        # Sort by risk score
        df_display = df.sort_values('composite_risk_score', ascending=False)
        
        # Format for display
        df_display['Risk Level'] = df_display['composite_risk_score'].apply(
            lambda x: 'HIGH' if x >= 0.7 else 'MEDIUM' if x >= 0.4 else 'LOW'
        )
        
        df_display['Last Update'] = df_display['days_since_update'].apply(
            lambda x: f"{x} days ago"
        )
        
        df_display['Vulnerabilities'] = df_display['total_historical_vulns']
        
        # Select columns for display
        display_cols = [
            'package_name', 'version', 'composite_risk_score', 'Risk Level',
            'Last Update', 'Vulnerabilities', 'maintainer_count'
        ]
        
        # Color coding for risk levels
        def color_risk_level(val):
            if val == 'HIGH':
                return 'background-color: #ffebee'
            elif val == 'MEDIUM':
                return 'background-color: #fff3cd'
            else:
                return 'background-color: #d4edda'
        
        styled_df = df_display[display_cols].head(50).style.applymap(
            color_risk_level, subset=['Risk Level']
        ).format({
            'composite_risk_score': '{:.3f}'
        })
        
        st.dataframe(styled_df, use_container_width=True)

    def render_export_options(self, df: pd.DataFrame):
        """Render export options."""
        st.subheader("📤 Export Options")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📊 Export Risk Summary"):
                summary = {
                    'total_packages': len(df),
                    'high_risk_count': len(df[df['composite_risk_score'] >= 0.7]),
                    'critical_count': len(df[df['composite_risk_score'] >= 0.8]),
                    'avg_risk_score': df['composite_risk_score'].mean(),
                    'export_timestamp': datetime.now().isoformat()
                }
                st.download_button(
                    label="Download Summary JSON",
                    data=json.dumps(summary, indent=2),
                    file_name=f"risk_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
        
        with col2:
            if st.button("📋 Export Risk Register"):
                csv_data = df[['package_name', 'version', 'composite_risk_score']].to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv_data,
                    file_name=f"risk_register_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col3:
            if st.button("🔴 Export Critical Packages"):
                critical_df = df[df['composite_risk_score'] >= 0.8]
                if len(critical_df) > 0:
                    critical_data = critical_df[['package_name', 'version', 'composite_risk_score']].to_csv(index=False)
                    st.download_button(
                        label="Download Critical Packages CSV",
                        data=critical_data,
                        file_name=f"critical_packages_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
                else:
                    st.info("No critical packages found")

def main():
    """Main dashboard application."""
    dashboard = RiskDashboard()
    
    # Render header
    dashboard.render_header()
    
    # Load data
    with st.spinner("Loading risk assessment data..."):
        df = dashboard.load_predictions_data()
    
    if df.empty:
        st.error("No data available. Please check your data source.")
        return
    
    # Render sidebar and get filters
    filters = dashboard.render_sidebar(df)
    
    # Apply filters
    filtered_df = dashboard.apply_filters(df, filters)
    
    if filtered_df.empty:
        st.warning("No packages match the selected filters.")
        return
    
    # Main dashboard content
    dashboard.render_key_metrics(filtered_df)
    
    st.divider()
    
    dashboard.render_critical_alerts(filtered_df)
    
    st.divider()
    
    dashboard.render_risk_distribution(filtered_df)
    
    st.divider()
    
    dashboard.render_top_risks_analysis(filtered_df)
    
    st.divider()
    
    dashboard.render_risk_factors_analysis(filtered_df)
    
    st.divider()
    
    dashboard.render_ecosystem_analysis(filtered_df)
    
    st.divider()
    
    dashboard.render_detailed_package_table(filtered_df)
    
    st.divider()
    
    dashboard.render_export_options(filtered_df)
    
    # Footer
    st.markdown("---")
    st.markdown(
        "**CassandraSec Dashboard** - Predictive Dependency Risk Assessment | "
        f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

if __name__ == "__main__":
    main()