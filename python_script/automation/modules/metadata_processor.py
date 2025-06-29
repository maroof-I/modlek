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

def generate_custom_rule_id(original_id):
    """Generate a custom rule ID that won't conflict with CRS rules."""
    # If the ID already starts with 999, it's already a custom rule
    if str(original_id).startswith('999'):
        return str(original_id)
    return f"999{original_id}"

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
        # Debug information
        print("\nDebugging rules extraction:")
        if not response or "hits" not in response or "hits" not in response["hits"]:
            print("Invalid response structure")
            return []
            
        hits = response["hits"]["hits"]
        if not hits:
            print("No hits found in response")
            return []
            
        # Debug first document structure
        print(f"\nTotal documents to process: {len(hits)}")
        if hits:
            print("\nFirst document structure:")
            source = hits[0].get("_source", {})
            print("Available fields:", list(source.keys()))
            if "rules" in source:
                print("Rules field type:", type(source["rules"]))
                print("First document rules:", source["rules"])
            else:
                print("'rules' field not found in document")
        
        rules_triggered = []
        for hit in hits:
            source = hit.get("_source", {})
            rules = source.get("rules", [])
            if rules:  # Only append if rules exist
                rules_triggered.append(rules)
        
        if not rules_triggered:
            print("\nNo rules found in any documents")
            return []
            
        print(f"\nFound rules in {len(rules_triggered)} documents")
        
        # Initialize dictionaries to store rule information
        rule_info_dict = {}  # Store rule information
        rule_counts = Counter()
        
        # First pass: Count rule occurrences and store rule information
        for rules in rules_triggered:
            for rule_data in rules:
                try:
                    rule_id = rule_data["rule_id"]
                    paranoia_level = int(rule_data.get("paranoia_level", 0))
                    
                    if paranoia_level >= 3:
                        # Count the rule occurrence
                        rule_counts[rule_id] += 1
                        
                        # Store or update rule information
                        if rule_id not in rule_info_dict:
                            custom_id = generate_custom_rule_id(rule_id)
                            rule_info_dict[rule_id] = {
                                "rule_id": rule_id,
                                "custom_id": custom_id,
                                "paranoia_level": rule_data.get("paranoia_level", ""),
                                "severity": rule_data.get("severity", ""),
                                "audit_data": rule_data.get("audit_data", "")
                            }
                            
                except (KeyError, ValueError) as e:
                    print(f"\nError processing rule: {e}")
                    print("Problematic rule_data:", rule_data)
                    continue
        
        # Second pass: Create final list with accurate counts
        sorted_rules = []
        for rule_id, count in rule_counts.most_common():
            if rule_id in rule_info_dict:
                rule_info = rule_info_dict[rule_id].copy()
                rule_info["count"] = count
                sorted_rules.append(rule_info)
        
        print(f"\nProcessed rules summary:")
        print(f"Total unique rules found: {len(sorted_rules)}")
        print(f"Rules with paranoia level >= 3: {len(sorted_rules)}")
        if sorted_rules:
            print("Top rules:", [f"{r['rule_id']}(count: {r['count']})" for r in sorted_rules[:3]])
        
        return sorted_rules
        
    except Exception as e:
        print(f"\nError in processing rules metadata: {str(e)}")
        import traceback
        print("Traceback:", traceback.format_exc())
        return []

