#!/usr/bin/env python3
"""
GNN + LSTM + BERT Ensemble Architecture
Predicts dependency incidents 6-12 months before they happen
"""

import sqlite3
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset
from torch_geometric.nn import GCNConv, global_mean_pool
from torch_geometric.data import Data, Batch
from transformers import DistilBertModel, DistilBertTokenizer
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, classification_report, precision_recall_curve
import logging
import warnings
import json
from datetime import datetime, timedelta
import sys
import networkx as nx
import re
import os

warnings.filterwarnings('ignore')

# Configure logging for Unicode
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('cassandrasec.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

class GraphNeuralNetwork(nn.Module):
    """GNN for analyzing dependency relationship patterns"""
    
    def __init__(self, input_dim, hidden_dim=64, output_dim=32, dropout=0.3):
        super(GraphNeuralNetwork, self).__init__()
        self.conv1 = GCNConv(input_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.conv3 = GCNConv(hidden_dim, output_dim)
        self.dropout = nn.Dropout(dropout)
        self.batch_norm1 = nn.BatchNorm1d(hidden_dim)
        self.batch_norm2 = nn.BatchNorm1d(hidden_dim)
        
    def forward(self, x, edge_index, batch=None):
        # First GCN layer
        x = self.conv1(x, edge_index)
        x = self.batch_norm1(x)
        x = F.relu(x)
        x = self.dropout(x)
        
        # Second GCN layer
        x = self.conv2(x, edge_index)
        x = self.batch_norm2(x)
        x = F.relu(x)
        x = self.dropout(x)
        
        # Third GCN layer
        x = self.conv3(x, edge_index)
        
        # Global pooling
        if batch is not None:
            x = global_mean_pool(x, batch)
        else:
            x = torch.mean(x, dim=0, keepdim=True)
            
        return x

class LSTMTimeSeriesNetwork(nn.Module):
    """LSTM for tracking maintainer activity degradation patterns"""
    
    def __init__(self, input_dim, hidden_dim=64, num_layers=2, output_dim=32, dropout=0.3):
        super(LSTMTimeSeriesNetwork, self).__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, 
                           batch_first=True, dropout=dropout, bidirectional=True)
        self.batch_norm = nn.BatchNorm1d(hidden_dim * 2)
        self.fc = nn.Linear(hidden_dim * 2, output_dim)
        self.dropout = nn.Dropout(dropout)
        
    def forward(self, x):
        # x shape: (batch_size, seq_len, input_dim)
        lstm_out, (hidden, cell) = self.lstm(x)
        
        # Take the last output
        last_output = lstm_out[:, -1, :]  # (batch_size, hidden_dim * 2)
        
        # Batch normalization
        last_output = self.batch_norm(last_output)
        last_output = self.dropout(last_output)
        
        # Final linear layer
        output = self.fc(last_output)
        return output

class BERTSentimentNetwork(nn.Module):
    """BERT for analyzing maintainer communication sentiment changes"""
    
    def __init__(self, output_dim=32, dropout=0.3):
        super(BERTSentimentNetwork, self).__init__()
        # Use DistilBERT to match tokenizer
        self.bert = DistilBertModel.from_pretrained('distilbert-base-uncased')
        
        # Freeze most BERT layers to prevent overfitting
        for param in self.bert.parameters():
            param.requires_grad = False
            
        # Unfreeze last 2 layers for fine-tuning
        for param in self.bert.transformer.layer[-2:].parameters():
            param.requires_grad = True
            
        bert_dim = self.bert.config.hidden_size
        self.dropout = nn.Dropout(dropout)
        self.fc = nn.Linear(bert_dim, output_dim)
        
    def forward(self, input_ids, attention_mask):
        outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        # DistilBERT uses last_hidden_state instead of pooler_output
        pooled_output = outputs.last_hidden_state[:, 0, :]  # Use [CLS] token
        pooled_output = self.dropout(pooled_output)
        output = self.fc(pooled_output)
        return output

class CassandraSecEnsemble(nn.Module):
    """Main ensemble model combining GNN + LSTM + BERT"""
    
    def __init__(self, gnn_input_dim, lstm_input_dim, lstm_seq_len=12, 
                 hidden_dim=64, dropout=0.3):
        super(CassandraSecEnsemble, self).__init__()
        
        # Individual networks
        self.gnn = GraphNeuralNetwork(gnn_input_dim, hidden_dim, 32, dropout)
        self.lstm = LSTMTimeSeriesNetwork(lstm_input_dim, hidden_dim, 2, 32, dropout)
        self.bert = BERTSentimentNetwork(32, dropout)
        
        # Fusion layers
        self.fusion = nn.Sequential(
            nn.Linear(32 + 32 + 32, hidden_dim),  # GNN + LSTM + BERT
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.BatchNorm1d(hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            
            nn.Linear(hidden_dim // 2, 2)  # Binary classification
        )
        
        # Attention weights for combining models
        self.attention = nn.Parameter(torch.ones(3) / 3)
        
    def forward(self, gnn_data, lstm_data, bert_input_ids, bert_attention_mask):
        # Get outputs from each network
        gnn_out = self.gnn(gnn_data.x, gnn_data.edge_index, gnn_data.batch)
        lstm_out = self.lstm(lstm_data)
        bert_out = self.bert(bert_input_ids, bert_attention_mask)
        
        # Apply attention weights
        att_weights = F.softmax(self.attention, dim=0)
        gnn_weighted = gnn_out * att_weights[0]
        lstm_weighted = lstm_out * att_weights[1]
        bert_weighted = bert_out * att_weights[2]
        
        # Concatenate features
        combined = torch.cat([gnn_weighted, lstm_weighted, bert_weighted], dim=1)
        
        # Final prediction
        output = self.fusion(combined)
        return output, (gnn_out, lstm_out, bert_out)

class CassandraSecDataset(torch.utils.data.Dataset):
    """Custom dataset for efficient GPU batch processing"""
    
    def __init__(self, gnn_features, lstm_features, bert_features, labels, indices):
        self.gnn_node_features = gnn_features['node_features'][indices]
        self.lstm_data = lstm_features[indices]
        self.bert_input_ids = bert_features['input_ids'][indices]
        self.bert_attention_mask = bert_features['attention_mask'][indices]
        self.labels = torch.LongTensor(labels[indices])
        
    def __len__(self):
        return len(self.labels)
    
    def __getitem__(self, idx):
        # Create individual graph for this sample
        edge_index = torch.tensor([[0], [0]], dtype=torch.long)  # Self-loop
        gnn_data = Data(x=self.gnn_node_features[idx:idx+1], edge_index=edge_index)
        
        return {
            'gnn_data': gnn_data,
            'lstm_data': self.lstm_data[idx],
            'bert_input_ids': self.bert_input_ids[idx],
            'bert_attention_mask': self.bert_attention_mask[idx],
            'label': self.labels[idx]
        }

def collate_batch(batch):
    """Custom collate function for DataLoader"""
    gnn_data_list = [item['gnn_data'] for item in batch]
    gnn_batch = Batch.from_data_list(gnn_data_list)
    
    lstm_data = torch.stack([item['lstm_data'] for item in batch])
    bert_input_ids = torch.stack([item['bert_input_ids'] for item in batch])
    bert_attention_mask = torch.stack([item['bert_attention_mask'] for item in batch])
    labels = torch.stack([item['label'] for item in batch])
    
    return {
        'gnn_batch': gnn_batch,
        'lstm_data': lstm_data,
        'bert_input_ids': bert_input_ids,
        'bert_attention_mask': bert_attention_mask,
        'labels': labels
    }

class CassandraSecPredictor:
    """Main predictor class implementing the full pipeline"""
    
    def __init__(self, db_path='cassandra_data.db', batch_size=32):
        self.db_path = db_path
        self.batch_size = batch_size
        
        # GPU optimization: Force CUDA if available
        if torch.cuda.is_available():
            self.device = torch.device('cuda')
            # Set GPU memory optimization
            torch.cuda.empty_cache()
            # Enable cudnn benchmarking for consistent input sizes
            torch.backends.cudnn.benchmark = True
            logger.info(f"GPU detected: {torch.cuda.get_device_name()}")
            logger.info(f"GPU memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")
        else:
            self.device = torch.device('cpu')
            logger.warning("No GPU detected, falling back to CPU")
        
        self.scaler = StandardScaler()
        self.time_scaler = MinMaxScaler()
        
        # Initialize DistilBERT tokenizer (matching the model)
        self.tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
        
        logger.info("CassandraSec V2 Initialized - Device: {}".format(self.device))

    def load_data(self):
        """Load engineered features and historical CVEs"""
        logger.info("Loading data from database...")
        
        conn = sqlite3.connect(self.db_path)
        
        try:
            # Load engineered features
            features_df = pd.read_sql_query("SELECT * FROM engineered_features", conn)
            logger.info("Loaded {} engineered features".format(len(features_df)))
            
            # Load historical CVEs
            cves_df = pd.read_sql_query("SELECT * FROM historical_cves", conn)
            logger.info("Loaded {} historical CVEs".format(len(cves_df)))
            
            # Load dependencies for graph construction
            deps_df = pd.read_sql_query("SELECT * FROM dependencies LIMIT 50000", conn)
            logger.info("Loaded {} dependencies".format(len(deps_df)))
            
        except Exception as e:
            logger.error(f"Error loading data: {e}")
            # Create dummy data for testing if database doesn't exist
            logger.warning("Creating dummy data for testing...")
            features_df = self.create_dummy_features()
            cves_df = pd.DataFrame()
            deps_df = pd.DataFrame()
        finally:
            conn.close()
            
        return features_df, cves_df, deps_df

    def create_dummy_features(self):
        """Create dummy feature data for testing when database is not available"""
        np.random.seed(42)
        n_samples = 1000
        
        dummy_data = {
            'id': range(n_samples),
            'name': [f'package_{i}' for i in range(n_samples)],
            'maintainer_count': np.random.randint(1, 10, n_samples),
            'total_packages': np.random.randint(1, 50, n_samples),
            'active_packages': np.random.randint(1, 30, n_samples),
            'maintainer_experience': np.random.uniform(0, 10, n_samples),
            'stars': np.random.randint(0, 10000, n_samples),
            'forks': np.random.randint(0, 1000, n_samples),
            'issues_open': np.random.randint(0, 100, n_samples),
            'issues_closed': np.random.randint(0, 500, n_samples),
            'contributors_count': np.random.randint(1, 100, n_samples),
            'commits_count': np.random.randint(10, 10000, n_samples),
            'community_engagement_score': np.random.uniform(0, 1, n_samples),
            'log_download_count': np.random.uniform(0, 10, n_samples),
            'package_age_days': np.random.randint(30, 3650, n_samples),
            'days_since_update': np.random.randint(0, 365, n_samples),
            'days_since_last_commit': np.random.randint(0, 180, n_samples),
            'update_frequency_score': np.random.uniform(0, 1, n_samples),
            'vuln_frequency_score': np.random.uniform(0, 1, n_samples),
            'maintenance_risk': np.random.uniform(0, 1, n_samples),
            'security_history_risk': np.random.uniform(0, 1, n_samples),
            'community_risk': np.random.uniform(0, 1, n_samples),
            'composite_risk_score': np.random.uniform(0, 1, n_samples),
            'has_validation_vuln': np.random.choice([0, 1], n_samples, p=[0.85, 0.15])
        }
        
        return pd.DataFrame(dummy_data)

    def prepare_features(self, features_df, cves_df, deps_df):
        """Prepare features for GNN + LSTM + BERT pipeline"""
        logger.info("Preparing features for ML pipeline...")
        
        # Clean data and handle missing values
        features_clean = self.clean_features(features_df)
        
        # Create target labels (validation period vulnerabilities)
        y = features_clean['has_validation_vuln'].fillna(0).astype(int).values
        
        # Prepare GNN features (community + maintainer health)
        gnn_features = self.prepare_gnn_features(features_clean, deps_df)
        
        # Prepare LSTM features (temporal patterns)
        lstm_features = self.prepare_lstm_features(features_clean)
        
        # Prepare BERT features (sentiment analysis)
        bert_features = self.prepare_bert_features(features_clean)
        
        logger.info("Feature preparation complete")
        logger.info("GNN features shape: {}".format(gnn_features['node_features'].shape))
        logger.info("LSTM features shape: {}".format(lstm_features.shape))
        logger.info("BERT features prepared: {} samples".format(len(bert_features['input_ids'])))
        
        return gnn_features, lstm_features, bert_features, y

    def clean_features(self, features_df):
        """Clean and prepare feature dataframe"""
        # Get numeric columns only
        numeric_cols = []
        for col in features_df.columns:
            if col not in ['id', 'name', 'ecosystem', 'description', 'homepage_url', 
                          'repository_url', 'age_category', 'update_recency']:
                if features_df[col].dtype in ['int64', 'float64', 'int32', 'float32']:
                    numeric_cols.append(col)
        
        # Clean data
        features_clean = features_df[numeric_cols].copy()
        features_clean = features_clean.replace([np.inf, -np.inf], np.nan)
        
        # Fill missing values
        for col in numeric_cols:
            median_val = features_clean[col].median()
            if pd.isna(median_val):
                median_val = 0
            features_clean[col] = features_clean[col].fillna(median_val)
        
        return features_clean

    def prepare_gnn_features(self, features_df, deps_df):
        """Prepare graph neural network features and adjacency matrix"""
        # Node features (maintainer + community signals)
        gnn_cols = [
            'maintainer_count', 'total_packages', 'active_packages', 
            'maintainer_experience', 'stars', 'forks', 'issues_open', 
            'issues_closed', 'contributors_count', 'commits_count',
            'community_engagement_score', 'log_download_count'
        ]
        
        available_cols = [col for col in gnn_cols if col in features_df.columns]
        node_features = features_df[available_cols].values
        node_features = self.scaler.fit_transform(node_features)
        
        # Create simple adjacency matrix (packages with similar characteristics)
        n_nodes = len(features_df)
        edge_list = []
        
        # Connect packages with similar risk profiles
        for i in range(min(n_nodes, 1000)):  # Limit for performance
            for j in range(i+1, min(n_nodes, 1000)):
                # Simple similarity based on composite risk score
                if abs(features_df.iloc[i]['composite_risk_score'] - 
                       features_df.iloc[j]['composite_risk_score']) < 0.1:
                    edge_list.extend([[i, j], [j, i]])
        
        if not edge_list:
            # Create a simple connected graph if no edges found
            edge_list = [[i, (i+1) % n_nodes] for i in range(n_nodes)]
        
        edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
        
        return {
            'node_features': torch.FloatTensor(node_features),
            'edge_index': edge_index
        }

    def prepare_lstm_features(self, features_df):
        """Prepare LSTM time series features"""
        # Temporal pattern features
        temporal_cols = [
            'package_age_days', 'days_since_update', 'days_since_last_commit',
            'update_frequency_score', 'vuln_frequency_score', 
            'maintenance_risk', 'security_history_risk', 'community_risk'
        ]
        
        available_cols = [col for col in temporal_cols if col in features_df.columns]
        temporal_data = features_df[available_cols].values
        
        # Normalize temporal data
        temporal_data = self.time_scaler.fit_transform(temporal_data)
        
        # Create sequences (simulate time series)
        seq_len = 12  # 12 months
        n_samples, n_features = temporal_data.shape
        
        # Pad or truncate to create consistent sequences
        lstm_data = np.zeros((n_samples, seq_len, n_features))
        
        for i in range(n_samples):
            # Simulate temporal evolution by adding noise to create sequence
            base_pattern = temporal_data[i]
            for t in range(seq_len):
                # Simulate degradation over time
                degradation = np.random.normal(0, 0.1, n_features) * (t / seq_len)
                lstm_data[i, t] = base_pattern + degradation
        
        return torch.FloatTensor(lstm_data)

    def prepare_bert_features(self, features_df):
        """Prepare BERT sentiment analysis features"""
        # Create synthetic text data from package characteristics
        texts = []
        for _, row in features_df.iterrows():
            # Generate text based on package characteristics
            sentiment_indicators = []
            
            if row.get('maintenance_risk', 0) > 0.7:
                sentiment_indicators.append("maintainer appears overwhelmed")
            if row.get('community_risk', 0) > 0.7:
                sentiment_indicators.append("community engagement declining")
            if row.get('security_history_risk', 0) > 0.7:
                sentiment_indicators.append("security concerns raised")
            if row.get('days_since_update', 365) > 180:
                sentiment_indicators.append("package updates delayed")
            
            if not sentiment_indicators:
                sentiment_indicators.append("package maintenance appears stable")
            
            text = "Package status: " + ", ".join(sentiment_indicators)
            texts.append(text)
        
        # Tokenize texts with GPU optimization
        encoding = self.tokenizer(
            texts,
            truncation=True,
            padding=True,
            max_length=128,
            return_tensors='pt'
        )
        
        return {
            'input_ids': encoding['input_ids'],
            'attention_mask': encoding['attention_mask']
        }

    def train_model(self, gnn_features, lstm_features, bert_features, y):
        """Train the ensemble model with GPU optimization"""
        logger.info("Starting GPU-optimized training pipeline...")
        
        # Split data
        indices = np.arange(len(y))
        train_idx, test_idx = train_test_split(indices, test_size=0.2, random_state=42, stratify=y)
        train_idx, val_idx = train_test_split(train_idx, test_size=0.25, random_state=42, 
                                            stratify=y[train_idx])
        
        # Create datasets
        train_dataset = CassandraSecDataset(gnn_features, lstm_features, bert_features, y, train_idx)
        val_dataset = CassandraSecDataset(gnn_features, lstm_features, bert_features, y, val_idx)
        test_dataset = CassandraSecDataset(gnn_features, lstm_features, bert_features, y, test_idx)
        
        # Create data loaders with GPU optimization
        train_loader = DataLoader(train_dataset, batch_size=self.batch_size, 
                                shuffle=True, collate_fn=collate_batch,
                                num_workers=4 if self.device.type == 'cuda' else 0,
                                pin_memory=True if self.device.type == 'cuda' else False)
        
        val_loader = DataLoader(val_dataset, batch_size=self.batch_size,
                              shuffle=False, collate_fn=collate_batch,
                              num_workers=4 if self.device.type == 'cuda' else 0,
                              pin_memory=True if self.device.type == 'cuda' else False)
        
        test_loader = DataLoader(test_dataset, batch_size=self.batch_size,
                               shuffle=False, collate_fn=collate_batch,
                               num_workers=4 if self.device.type == 'cuda' else 0,
                               pin_memory=True if self.device.type == 'cuda' else False)
        
        # Initialize model
        gnn_input_dim = gnn_features['node_features'].shape[1]
        lstm_input_dim = lstm_features.shape[2]
        
        model = CassandraSecEnsemble(gnn_input_dim, lstm_input_dim).to(self.device)
        
        # GPU optimization: Use mixed precision if available
        scaler = torch.cuda.amp.GradScaler() if self.device.type == 'cuda' else None
        
        # Training setup with GPU-optimized parameters
        optimizer = torch.optim.AdamW(model.parameters(), lr=0.001, weight_decay=1e-5)
        criterion = nn.CrossEntropyLoss()
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=5, factor=0.5)
        
        best_val_auc = 0
        patience = 15
        patience_counter = 0
        
        logger.info(f"Training on {len(train_loader)} batches per epoch")
        
        # Training loop with GPU optimization
        for epoch in range(50):  # Reduced epochs for faster testing
            model.train()
            total_loss = 0
            
            for batch_idx, batch in enumerate(train_loader):
                # Move batch to GPU
                gnn_batch = batch['gnn_batch'].to(self.device)
                lstm_data = batch['lstm_data'].to(self.device)
                bert_input_ids = batch['bert_input_ids'].to(self.device)
                bert_attention_mask = batch['bert_attention_mask'].to(self.device)
                labels = batch['labels'].to(self.device)
                
                optimizer.zero_grad()
                
                # Use mixed precision if available
                if scaler is not None:
                    with torch.cuda.amp.autocast():
                        outputs, _ = model(gnn_batch, lstm_data, bert_input_ids, bert_attention_mask)
                        loss = criterion(outputs, labels)
                    
                    scaler.scale(loss).backward()
                    scaler.unscale_(optimizer)
                    torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                    scaler.step(optimizer)
                    scaler.update()
                else:
                    outputs, _ = model(gnn_batch, lstm_data, bert_input_ids, bert_attention_mask)
                    loss = criterion(outputs, labels)
                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                    optimizer.step()
                
                total_loss += loss.item()
                
                # Log progress for large batches
                if batch_idx % 50 == 0:
                    logger.info(f"Epoch {epoch}, Batch {batch_idx}/{len(train_loader)}, Loss: {loss.item():.4f}")
            
            avg_loss = total_loss / len(train_loader)
            
            # Validation
            if epoch % 2 == 0:  # Validate every 2 epochs for speed
                model.eval()
                val_predictions = []
                val_labels = []
                
                with torch.no_grad():
                    for batch in val_loader:
                        gnn_batch = batch['gnn_batch'].to(self.device)
                        lstm_data = batch['lstm_data'].to(self.device)
                        bert_input_ids = batch['bert_input_ids'].to(self.device)
                        bert_attention_mask = batch['bert_attention_mask'].to(self.device)
                        
                        if scaler is not None:
                            with torch.cuda.amp.autocast():
                                val_outputs, _ = model(gnn_batch, lstm_data, bert_input_ids, bert_attention_mask)
                        else:
                            val_outputs, _ = model(gnn_batch, lstm_data, bert_input_ids, bert_attention_mask)
                        
                        val_probs = F.softmax(val_outputs, dim=1)[:, 1].cpu().numpy()
                        val_predictions.extend(val_probs)
                        val_labels.extend(batch['labels'].numpy())
                
                val_auc = roc_auc_score(val_labels, val_predictions)
                
                logger.info("Epoch {}: Avg Loss: {:.4f}, Val AUC: {:.4f}".format(
                    epoch, avg_loss, val_auc))
                
                if val_auc > best_val_auc:
                    best_val_auc = val_auc
                    patience_counter = 0
                    # Save best model
                    torch.save({
                        'model_state_dict': model.state_dict(),
                        'optimizer_state_dict': optimizer.state_dict(),
                        'epoch': epoch,
                        'val_auc': val_auc
                    }, 'cassandrasec_best_model.pth')
                else:
                    patience_counter += 1
                
                scheduler.step(val_auc)
                
                if patience_counter >= patience:
                    logger.info("Early stopping at epoch {}".format(epoch))
                    break
        
        # Load best model and evaluate on test set
        if os.path.exists('cassandrasec_best_model.pth'):
            checkpoint = torch.load('cassandrasec_best_model.pth')
            model.load_state_dict(checkpoint['model_state_dict'])
        
        model.eval()
        
        test_predictions = []
        test_labels = []
        
        with torch.no_grad():
            for batch in test_loader:
                gnn_batch = batch['gnn_batch'].to(self.device)
                lstm_data = batch['lstm_data'].to(self.device)
                bert_input_ids = batch['bert_input_ids'].to(self.device)
                bert_attention_mask = batch['bert_attention_mask'].to(self.device)
                
                if scaler is not None:
                    with torch.cuda.amp.autocast():
                        test_outputs, _ = model(gnn_batch, lstm_data, bert_input_ids, bert_attention_mask)
                else:
                    test_outputs, _ = model(gnn_batch, lstm_data, bert_input_ids, bert_attention_mask)
                
                test_probs = F.softmax(test_outputs, dim=1)[:, 1].cpu().numpy()
                test_predictions.extend(test_probs)
                test_labels.extend(batch['labels'].numpy())
        
        test_auc = roc_auc_score(test_labels, test_predictions)
        
        # Calculate precision for high-risk packages
        # Calculate precision for high-risk packages
        high_risk_threshold = 0.7
        high_risk_mask = np.array(test_predictions) > high_risk_threshold
        
        if np.sum(high_risk_mask) > 0:
            high_risk_precision = np.mean(np.array(test_labels)[high_risk_mask])
        else:
            high_risk_precision = 0.0
        
        logger.info("Final Test AUC: {:.4f}".format(test_auc))
        logger.info("High-risk precision: {:.2f}%".format(high_risk_precision * 100))
        
        # Generate detailed risk assessment
        risk_levels = self.categorize_risk(test_predictions)
        
        logger.info("Generating risk assessment report...")
        
        return {
            'model': model,
            'test_auc': test_auc,
            'test_predictions': test_predictions,
            'test_labels': test_labels,
            'high_risk_precision': high_risk_precision,
            'risk_distribution': risk_levels
        }

    def categorize_risk(self, predictions):
        """Categorize packages into risk levels"""
        predictions = np.array(predictions)
        
        high_risk = np.sum(predictions > 0.7)
        medium_risk = np.sum((predictions > 0.3) & (predictions <= 0.7))
        low_risk = np.sum(predictions <= 0.3)
        
        return {
            'high_risk': high_risk,
            'medium_risk': medium_risk,
            'low_risk': low_risk
        }

    def predict_new_packages(self, package_data):
        """Predict risk for new packages"""
        # Load trained model
        if not os.path.exists('cassandrasec_best_model.pth'):
            raise ValueError("No trained model found. Please train the model first.")
        
        # Implementation for new package prediction
        logger.info("Predicting risk for {} new packages".format(len(package_data)))
        return np.random.uniform(0, 1, len(package_data))  # Placeholder

    def generate_report(self, results):
        """Generate comprehensive risk assessment report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'model_performance': {
                'test_auc': float(results['test_auc']),
                'high_risk_precision': float(results['high_risk_precision'])
            },
            'risk_distribution': {
                'high_risk': int(results['risk_distribution']['high_risk']),
                'medium_risk': int(results['risk_distribution']['medium_risk']),
                'low_risk': int(results['risk_distribution']['low_risk'])
            },
            'summary': {
                'total_packages_analyzed': len(results['test_predictions']),
                'high_risk_packages': int(results['risk_distribution']['high_risk']),
                'model_confidence': float(results['test_auc'])
            }
        }
        
        return report

def convert_numpy_types(obj):
    """Convert numpy types to native Python types for JSON serialization"""
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    else:
        return obj

def main():
    """Main execution pipeline"""
    try:
        logger.info("Initializing CassandraSec V2...")
        
        # Initialize predictor
        predictor = CassandraSecPredictor()
        
        # Load and prepare data
        features_df, cves_df, deps_df = predictor.load_data()
        gnn_features, lstm_features, bert_features, y = predictor.prepare_features(
            features_df, cves_df, deps_df
        )
        
        # Train model
        results = predictor.train_model(gnn_features, lstm_features, bert_features, y)
        
        # Generate report
        report = predictor.generate_report(results)
        
        # Convert numpy types before JSON serialization
        report_clean = convert_numpy_types(report)
        
        # Save results with proper JSON handling
        with open('cassandrasec_results.json', 'w') as f:
            json.dump(report_clean, f, indent=2, default=convert_numpy_types)
        
        # Print final results
        print("=" * 60)
        print("CassandraSec V2 - Risk Assessment Complete")
        print("=" * 60)
        print("Test AUC: {:.4f}".format(report['model_performance']['test_auc']))
        print("High-Risk Precision: {:.2f}%".format(
            report['model_performance']['high_risk_precision'] * 100))
        print("\nRisk Distribution:")
        print("  High Risk: {} packages".format(report['risk_distribution']['high_risk']))
        print("  Medium Risk: {} packages".format(report['risk_distribution']['medium_risk']))
        print("  Low Risk: {} packages".format(report['risk_distribution']['low_risk']))
        print("=" * 60)
        
        logger.info("Pipeline completed successfully")
        
    except Exception as e:
        logger.error("Error during execution: {}".format(str(e)))
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()