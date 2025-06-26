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

def calculate_averages(response):
    """
    Calculate average anomaly scores and weights from Elasticsearch response.
    
    Args:
        response (dict): Elasticsearch response
        
    Returns:
        tuple: (avg_anomaly_score, avg_weight) or (0, 0) if no valid data
    """
    try:
        anomaly_scores = []
        weights = []
        
        for hit in response.get("hits", {}).get("hits", []):
            source = hit.get("_source", {})
            
            # Get anomaly score and weight directly from the document
            anomaly_score = source.get("anomaly_score", 0)
            weight = source.get("wieght", 0)  # Note: 'wieght' is the actual field name in your data
            
            # Only include non-zero values
            if anomaly_score > 0:
                anomaly_scores.append(anomaly_score)
            if weight > 0:
                weights.append(weight)
        
        # Calculate averages
        avg_anomaly = sum(anomaly_scores) / len(anomaly_scores) if anomaly_scores else 0
        avg_weight = sum(weights) / len(weights) if weights else 0
        
        return round(avg_anomaly, 2), round(avg_weight, 2)
        
    except Exception as e:
        print(f"Error calculating averages: {str(e)}")
        return 0, 0

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

