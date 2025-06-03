#!/usr/bin/env python3
"""
Database Schema Inspector
Check the actual structure of cassandra_data.db
"""

import sqlite3
import sys

def inspect_database(db_path='cassandra_data.db'):
    """Inspect the database schema and show table structures"""
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print(f"=== Database Schema Inspector ===")
        print(f"Database: {db_path}")
        print()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        print(f"Found {len(tables)} tables:")
        for table in tables:
            print(f"  - {table[0]}")
        print()
        
        # Inspect each table
        for table in tables:
            table_name = table[0]
            print(f"=== Table: {table_name} ===")
            
            # Get table info
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()
            
            print("Columns:")
            for col in columns:
                col_id, name, col_type, not_null, default_val, pk = col
                null_str = "NOT NULL" if not_null else "NULL"
                pk_str = "PRIMARY KEY" if pk else ""
                default_str = f"DEFAULT {default_val}" if default_val else ""
                print(f"  {name} ({col_type}) {null_str} {default_str} {pk_str}")
            
            # Get row count
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                count = cursor.fetchone()[0]
                print(f"Row count: {count}")
            except Exception as e:
                print(f"Error counting rows: {e}")
            
            # Show sample data for vulnerabilities table
            if table_name == 'vulnerabilities' and count > 0:
                print("Sample rows:")
                cursor.execute(f"SELECT * FROM {table_name} LIMIT 3")
                rows = cursor.fetchall()
                for row in rows:
                    print(f"  {row}")
            
            print()
        
        # Check for foreign key constraints
        print("=== Foreign Key Constraints ===")
        for table in tables:
            table_name = table[0]
            cursor.execute(f"PRAGMA foreign_key_list({table_name})")
            fks = cursor.fetchall()
            if fks:
                print(f"{table_name}:")
                for fk in fks:
                    print(f"  {fk}")
        
        conn.close()
        
    except Exception as e:
        print(f"Error inspecting database: {e}")
        return False
    
    return True

def show_vulnerabilities_details(db_path='cassandra_data.db'):
    """Show detailed info about vulnerabilities table"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("=== Vulnerabilities Table Details ===")
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerabilities'")
        if not cursor.fetchone():
            print("vulnerabilities table does not exist!")
            return
        
        # Get schema
        cursor.execute("PRAGMA table_info(vulnerabilities)")
        columns = cursor.fetchall()
        
        print("Current schema:")
        column_names = []
        for col in columns:
            col_id, name, col_type, not_null, default_val, pk = col
            column_names.append(name)
            print(f"  {name}: {col_type}")
        
        print(f"\nColumn names: {column_names}")
        
        # Try to add base_score if missing
        if 'base_score' not in column_names:
            print("\nAttempting to add base_score column...")
            try:
                cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN base_score REAL DEFAULT 5.0")
                conn.commit()
                print("✓ Successfully added base_score column")
            except Exception as e:
                print(f"✗ Failed to add base_score: {e}")
        else:
            print("✓ base_score column already exists")
        
        # Try to add last_modified if missing  
        if 'last_modified' not in column_names:
            print("\nAttempting to add last_modified column...")
            try:
                cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN last_modified TEXT DEFAULT CURRENT_TIMESTAMP")
                conn.commit()
                print("✓ Successfully added last_modified column")
            except Exception as e:
                print(f"✗ Failed to add last_modified: {e}")
        else:
            print("✓ last_modified column already exists")
        
        # Show updated schema
        print("\nUpdated schema:")
        cursor.execute("PRAGMA table_info(vulnerabilities)")
        columns = cursor.fetchall()
        for col in columns:
            col_id, name, col_type, not_null, default_val, pk = col
            print(f"  {name}: {col_type}")
        
        conn.close()
        
    except Exception as e:
        print(f"Error working with vulnerabilities table: {e}")

if __name__ == "__main__":
    db_path = 'cassandra_data.db'
    if len(sys.argv) > 1:
        db_path = sys.argv[1]
    
    print("Running database inspection...")
    inspect_database(db_path)
    
    print("\n" + "="*50)
    show_vulnerabilities_details(db_path)