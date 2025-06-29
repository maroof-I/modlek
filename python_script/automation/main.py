import re
import json
import os
import logging
from elasticsearch import Elasticsearch
from collections import Counter
from datetime import datetime, timezone
from modules.rule_processor import extract_paranoia_rules
from modules.file_operations import save_rules_to_file, get_existing_rules, load_rules_from_file
from modules.elasticsearch_client import analyze_elasticsearch_data
from modules.metadata_processor import target_metadata, rules_metadata, calculate_averages
from modules.visualization import create_target_distribution_plot, create_anomaly_weight_plot
from modules.email_sender import send_attack_notification
from modules.modsec_rule_updater import ModSecRuleUpdater
from modules.config import Config

def main():
    """Entry point of the application."""
    # Initialize logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('automation.log'),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger(__name__)
    
    # Initialize configuration
    config = Config()
    
    # Get current date-based index
    date_hour_utc = datetime.now(timezone.utc).strftime("%Y.%m.%d.%H")
    es_response = analyze_elasticsearch_data(index_name=f"classified_{date_hour_utc}")
    
    # create/update rules.conf file
    extracted_rules = extract_paranoia_rules(config.security_rules_file)
    if not os.path.exists("rules.conf"):
        save_rules_to_file(extracted_rules, "rules.conf")
    
    if not es_response:
        logger.error("Failed to get Elasticsearch data")
        return
        
    # Analyze metadata
    target_results = target_metadata(es_response)
    if not target_results:
        logger.error("Failed to analyze target metadata")
        return
    
    # Process if attack percentage is higher than threshold
    if target_results["attack_percentage"] > config.attack_threshold:
        # Get existing rules and analyze new ones
        existing_rules = get_existing_rules()
        sorted_rules = rules_metadata(es_response)
                
        # Create visualizations
        target_dist_img = create_target_distribution_plot(
            target_results['normal_percentage'],
            target_results['attack_percentage']
        )
        
        # Calculate and visualize averages
        avg_anomaly, avg_weight = calculate_averages(es_response)
        anomaly_weight_img = create_anomaly_weight_plot(
            avg_anomaly,
            avg_weight
        )
        
        # Find and add new rules
        new_rule_added = False
        added_rule_info = None
        
        # Check for existing rule IDs in custom_rules.conf
        try:
            with open(config.custom_rules_file, "r") as f:
                current_content = f.read()
                # Extract existing rule IDs using regex
                existing_rule_ids = set(re.findall(r'id:(\d+)', current_content))
        except FileNotFoundError:
            existing_rule_ids = set()
            current_content = ""
        
        for rule_info in sorted_rules:
            matched_id = rule_info["rule_id"]
            if matched_id not in existing_rules and matched_id in extracted_rules:
                # Check if rule ID already exists in the file
                if matched_id not in existing_rule_ids:
                    logger.info(f"Adding new rule ID: {matched_id} (triggered {rule_info['count']} times)")
                    with open(config.custom_rules_file, "a") as output_file:
                        output_file.write(extracted_rules[matched_id] + "\n\n")
                    new_rule_added = True
                    added_rule_info = rule_info
                else:
                    logger.info(f"Rule ID {matched_id} already exists in custom_rules.conf, skipping...")
                break
        
        # Update ModSecurity rules if new rules were added
        if new_rule_added:
            logger.info("New rules added, updating ModSecurity configuration...")
            modsec_updater = ModSecRuleUpdater(custom_rules_path=config.custom_rules_file)
            if not modsec_updater.update_rules():
                logger.error("Failed to update ModSecurity rules")
        
        # Send email notification
        send_attack_notification(
            config,
            config.recipient_email,
            target_results,
            added_rule_info,
            target_dist_img,
            anomaly_weight_img
        )
        
        if not new_rule_added:
            logger.info("No new eligible rules found to add.")

if __name__ == "__main__":
    main()
