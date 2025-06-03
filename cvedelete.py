#!/usr/bin/env python3
"""
Clear CVE Data - Removes all vulnerabilities from the database
"""

import sqlite3
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def clear_cve_data(db_path: str = "cassandra_data.db"):
    """Clear all CVE data from the database"""
    
    if not os.path.exists(db_path):
        logger.error(f"Database file '{db_path}' not found!")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get current count
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        current_count = cursor.fetchone()[0]
        
        print(f"Current CVE count: {current_count}")
        
        # Confirm deletion
        response = input(f"Are you sure you want to delete all {current_count} CVEs? (yes/no): ")
        
        if response.lower() in ['yes', 'y']:
            # Delete all vulnerabilities
            cursor.execute("DELETE FROM vulnerabilities")
            deleted_count = cursor.rowcount
            
            # Reset auto-increment counter (optional)
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='vulnerabilities'")
            
            conn.commit()
            conn.close()
            
            logger.info(f"Successfully deleted {deleted_count} CVEs from database")
            return True
        else:
            print("Operation cancelled.")
            conn.close()
            return False
            
    except Exception as e:
        logger.error(f"Error clearing CVE data: {e}")
        return False

def verify_empty_database(db_path: str = "cassandra_data.db"):
    """Verify that the vulnerabilities table is empty"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM packages")
        package_count = cursor.fetchone()[0]
        
        conn.close()
        
        print(f"\nDatabase Status:")
        print(f"- CVEs: {count}")
        print(f"- Packages: {package_count}")
        
        if count == 0:
            print("✅ Database is ready for fresh CVE collection!")
        else:
            print("⚠️ Database still contains CVE data")
            
    except Exception as e:
        logger.error(f"Error verifying database: {e}")

if __name__ == "__main__":
    print("="*60)
    print("CVE DATA CLEANER")
    print("="*60)
    
    if clear_cve_data():
        verify_empty_database()
        print("\nNow you can run: python cve_collector.py")
    else:
        print("CVE data was not cleared.")