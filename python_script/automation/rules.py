import re
import json
from elasticsearch import Elasticsearch
from collections import Counter
from datetime import datetime, timezone

def extract_paranoia_rules(input_text):
    # Normalize line breaks and combine multiline SecRule blocks
    lines = input_text.splitlines() # return lists
    rules = []
    buffer = []
    
    for line in lines:
        line = line.strip()
        if line.startswith("#") or not line:
            continue  # Skip comments and empty lines

        if line.startswith("SecRule"):
            if buffer:
                rules.append("\n".join(buffer))
                buffer = []
        if line.startswith("SecRule") or buffer:
            buffer.append(line)
    if buffer:
        rules.append("\n".join(buffer))

    result = {}

    for rule in rules:
        
        if re.search(r"tag:'paranoia-level/[34]'", rule):
            id_match = re.search(r"id\s*:\s*(\d+)", rule)
            if id_match:
                rule_id = id_match.group(1)
                result[rule_id] = rule
                
    return result

def save_rules_to_file(rules, filename):
    """Save extracted rules to a file."""
    with open(filename, 'w') as file:
        for rule_id, rule in rules.items():
            file.write(f"{rule}\n\n")
            
            
def load_rules_from_file(filename):
    """Load rules from a file."""
    rules = {}
    with open(filename, "r") as file:
        content = file.read()
        for rule in content.split("\n\n"):
            if rule.strip():
                id_match = re.search(r"id\s*:\s*(\d+)", rule)
                if id_match:
                    rule_id = id_match.group(1)
                    rules[rule_id] = rule.strip()
    return rules

def analyze_elasticsearch_data(es_host='http://192.168.0.109:9200', index_name='classified'):
    """
    Fetch data from Elasticsearch and calculate the percentage of attacks vs normal traffic.
    
    Args:
        es_host (str): Elasticsearch host URL
        index_name (str): Name of the index to query
        
    Returns:
        dict: elasticsearch response
    """
    try:
        # Initialize Elasticsearch client
        es = Elasticsearch([es_host])
        
        # Query to fetch all documents with the target field
        query = {
            "query": {
                "match_all": {}
            },
            "size": 10000 
        }
        
        response = es.search(
            index=index_name,
            body=query
        )
        
        return response
        
    except Exception as e:
        print(f"Error in fetching Elasticsearch data: {str(e)}")
        return None

def target_metadata(response):
    """
    Extract metadata from Elasticsearch response.
    
    Args:
        response (dict): Elasticsearch response
        
    Returns:
        dict: Dictionary containing total records, attack count, normal count, and their percentages
    """
    try:
     # Extract target values
        targets = [int(hit["_source"]["target"]) for hit in response["hits"]["hits"]]
        
        # Count occurrences
        target_counts = Counter(targets)
        total = len(targets)
        
        # Calculate percentages
        attack_percentage = (target_counts.get(1, 0) / total) * 100 if total > 0 else 0
        normal_percentage = (target_counts.get(0, 0) / total) * 100 if total > 0 else 0
        
        results = {
            'total_records': total,
            'attack_count': target_counts.get(1, 0),
            'normal_count': target_counts.get(0, 0),
            'attack_percentage': round(attack_percentage, 2),
            'normal_percentage': round(normal_percentage, 2)
        }
        
        return results
    except Exception as e:
        print(f"Error in processing Elasticsearch response: {str(e)}")
        return None
    
def rules_metadata(response):
    """
    Extract metadata from Elasticsearch response for rules.
    Find and return information about the most frequently triggered rule.
    
    Args:
        response (dict): Elasticsearch response
        
    returns:
        dict: Information about the most frequently triggered rule
    """
    
    rules_triggered = [hit["_source"]["rules"] for hit in response["hits"]["hits"]]
    
    targeted_rule = {}
    rule_counts = {}
    
    # Count occurrences of each rule
    for rule in rules_triggered:
        for rule_data in rule:
            # print(rule_data)
            rule_id = rule_data["rule_id"]
            # Increment the count for this rule_id
            if int(rule_data.get("paranoia_level", 0)) >= 3:
                if rule_id in rule_counts:
                    rule_counts[rule_id] += 1
                else:
                    rule_counts[rule_id] = 1
            
            # Store or update the rule metadata
            if int(rule_data.get("paranoia_level", 0)) >= 3:
                if rule_id not in targeted_rule:
                    targeted_rule[rule_id] = {
                        "rule_id": rule_id,
                        "paranoia_level": rule_data.get("paranoia_level", ""),
                        "severity": rule_data.get("severity", ""),
                        "audit_data": rule_data.get("audit_data", ""),
                        "count": rule_counts.get(rule_id, 0)
                    }
                else:
                    targeted_rule[rule_id]["count"] = rule_counts[rule_id]
    
    # Find the rule_id with the highest count
    if rule_counts:
        most_triggered_rule_id = max(rule_counts.items(), key=lambda x: x[1])[0]
        # Return only the information for the most triggered rule
        return targeted_rule[most_triggered_rule_id]
    
    return None  # Return None if no rules were found

if __name__ == "__main__":
    
    date_hour_utc = datetime.now(timezone.utc).strftime("%Y.%m.%d.%H")
    
    es_response = analyze_elasticsearch_data(index_name=f"scripting_{date_hour_utc}")
    es_target_results = target_metadata(es_response)
    
    es_rules_triggered = rules_metadata(es_response)
    # print(f"Most triggered rule: {es_rules_triggered}")
    matched_id = es_rules_triggered["rule_id"]
    
    print(es_target_results["attack_percentage"])
    print(es_target_results["normal_percentage"])
    
    if es_target_results["attack_percentage"] > es_target_results["normal_percentage"]:
    
        with open("../REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "r") as file:
            input_text = file.read()

        extracted_rules = extract_paranoia_rules(input_text)
        save_rules_to_file(extracted_rules, "rules.conf")
        load_rules_from_file("rules.conf")

        with open("custom_rules.conf", "a") as output_file:
            if matched_id in extracted_rules:
                output_file.write(extracted_rules[matched_id] + "\n\n")
            else:
                print(f"Rule with ID {matched_id} not found in extracted rules.")
