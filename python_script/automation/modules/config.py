"""
Simple configuration module for security rules automation system.
Contains essential settings and configuration parameters.
"""
import os

class Config:
    def __init__(self):
        # Elasticsearch settings
        self.es_host = 'http://192.168.0.109:9200'
        self.es_request_timeout = 30  # seconds
        self.es_max_retries = 3
        self.es_retry_on_timeout = True
        self.es_scroll_size = 1000  # documents per scroll
        
        # File paths
        self.custom_rules_file = "custom_rules.conf"
        self.security_rules_file = "../REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
        
        # Rule settings
        self.min_paranoia_level = 3
        
        # Email settings
        self.smtp_server = 'smtp.gmail.com'
        self.sender_email = os.getenv('SENDER_EMAIL', 'sender@example.com')
        self.sender_password = os.getenv('SENDER_PASSWORD', 'password')
        self.recipient_email = os.getenv('RECIPIENT_EMAIL', 'recipient@example.com')
        
        # Alert threshold
        self.attack_threshold = 50.0  # Percentage threshold for attack traffic