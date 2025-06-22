from collections import Counter

def target_metadata(response):
    """
    Extract metadata from Elasticsearch response.
    
    Args:
        response (dict): Elasticsearch response
        
    Returns:
        dict: Dictionary containing total records, attack count, normal count, and their percentages
    """
    try:
        targets = [int(hit["_source"]["target"]) for hit in response["hits"]["hits"]]
        
        target_counts = Counter(targets)
        total = len(targets)
        
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
    Return all rules sorted by trigger count.
    
    Args:
        response (dict): Elasticsearch response
        
    returns:
        list: List of rule information sorted by trigger count
    """
    try:
        rules_triggered = [hit["_source"]["rules"] for hit in response["hits"]["hits"]]
    except KeyError:
        print("No rules found in the Elasticsearch response.")
        return []
    
    targeted_rules = {}
    rule_counts = {}
    
    for rule in rules_triggered:
        for rule_data in rule:
            rule_id = rule_data["rule_id"]
            if int(rule_data.get("paranoia_level", 0)) >= 3:
                if rule_id in rule_counts:
                    rule_counts[rule_id] += 1
                else:
                    rule_counts[rule_id] = 1
            
            if int(rule_data.get("paranoia_level", 0)) >= 3:
                if rule_id not in targeted_rules:
                    targeted_rules[rule_id] = {
                        "rule_id": rule_id,
                        "paranoia_level": rule_data.get("paranoia_level", ""),
                        "severity": rule_data.get("severity", ""),
                        "audit_data": rule_data.get("audit_data", ""),
                        "count": rule_counts.get(rule_id, 0)
                    }
                else:
                    targeted_rules[rule_id]["count"] = rule_counts[rule_id]

    sorted_rules = sorted(
        targeted_rules.values(),
        key=lambda x: x["count"],
        reverse=True
    )
    
    return sorted_rules if sorted_rules else []

