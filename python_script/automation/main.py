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
    logger.info("Extracting rules from security rules file...")
    extracted_rules = extract_paranoia_rules(config.security_rules_file)
    logger.info(f"Found {len(extracted_rules)} rules in security rules file")
    logger.debug(f"Extracted rule IDs: {list(extracted_rules.keys())}")
    
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
        logger.info("Checking existing rules...")
        existing_rules = get_existing_rules()
        logger.info(f"Found {len(existing_rules)} existing rules")
        logger.debug(f"Existing rule IDs: {list(existing_rules)}")
        
        sorted_rules = rules_metadata(es_response)
        logger.info(f"Found {len(sorted_rules)} rules from Elasticsearch data")
                
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
        added_rules_info = []  # Track all added rules
        
        # Initialize ModSecRuleUpdater first
        modsec_updater = ModSecRuleUpdater(custom_rules_path=config.custom_rules_file)
        
        # Ensure custom_rules.conf exists
        if not os.path.exists(config.custom_rules_file):
            with open(config.custom_rules_file, "w") as f:
                f.write("")  # Create empty file
            logger.info(f"Created new custom rules file: {config.custom_rules_file}")
        
        logger.info("\nStarting rule processing:")
        logger.info("=" * 50)
        
        for rule_info in sorted_rules:
            original_id = rule_info["rule_id"]
            custom_id = rule_info["custom_id"]
            
            logger.info(f"\nProcessing rule: {original_id}")
            logger.info(f"Custom ID: {custom_id}")
            logger.info(f"Paranoia Level: {rule_info.get('paranoia_level')}")
            logger.info(f"Severity: {rule_info.get('severity')}")
            logger.info(f"Trigger Count: {rule_info.get('count')}")
            
            # Debug checks
            logger.info("Checking conditions:")
            logger.info(f"1. Rule in extracted_rules: {original_id in extracted_rules}")
            logger.info(f"2. Custom ID not in existing_rules: {custom_id not in existing_rules}")
            
            # Check if the rule exists in extracted rules and not in existing rules
            if original_id in extracted_rules and custom_id not in existing_rules:
                logger.info(f"✓ Adding new rule ID: {custom_id} (triggered {rule_info['count']} times)")
                
                # Add the rule to custom_rules.conf
                with open(config.custom_rules_file, "a") as output_file:
                    rule_content = extracted_rules[original_id]
                    # Add a marker comment for better organization
                    output_file.write(f"\n# Rule {custom_id} (Original: {original_id})\n")
                    output_file.write(rule_content + "\n")
                
                new_rule_added = True
                added_rules_info.append(rule_info)
                logger.info(f"✓ Successfully added rule {custom_id}")
            else:
                logger.info("✗ Rule not added - Conditions not met")
        
        logger.info("\nRule processing summary:")
        logger.info("=" * 50)
        logger.info(f"Total rules processed: {len(sorted_rules)}")
        logger.info(f"Rules added: {len(added_rules_info)}")
        if added_rules_info:
            logger.info("Added rules:")
            for rule in added_rules_info:
                logger.info(f"- {rule['rule_id']} (Custom: {rule['custom_id']})")
        
        # Add end marker if rules were added
        if new_rule_added:
            with open(config.custom_rules_file, "a") as output_file:
                output_file.write('\nSecMarker "END-REQUEST-942-APPLICATION-ATTACK-SQLI"\n')
        
        # Update ModSecurity rules if new rules were added
        if new_rule_added:
            logger.info(f"Added {len(added_rules_info)} new rules, updating ModSecurity configuration...")
            if not modsec_updater.update_rules():
                logger.error("Failed to update ModSecurity rules")
        
        # Send email notification with the last added rule info
        send_attack_notification(
            config,
            config.recipient_email,
            target_results,
            added_rules_info[-1] if added_rules_info else None,
            target_dist_img,
            anomaly_weight_img
        )
        
        if not new_rule_added:
            logger.info("No new eligible rules found to add.")

if __name__ == "__main__":
    main()
