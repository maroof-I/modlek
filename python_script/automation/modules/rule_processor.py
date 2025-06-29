import re

def adjust_anomaly_score(rule):
    """
    Adjust the anomaly score based on rule severity level.
    
    Args:
        rule (str): The rule text to adjust
        
    Returns:
        str: Rule with adjusted anomaly score
    """
    severity_match = re.search(r"severity:'(\w+)", rule)
    pl_match = re.search(r"tag:'paranoia-level/([34])'", rule)
    
    if severity_match and pl_match:
        severity = severity_match.group(1).lower()
        pl_value = pl_match.group(1)
        pattern = r"setvar:'tx\.inbound_anomaly_score_pl[34]=\+(%\{tx\..*?_anomaly_score\})'"
        
        if severity == "critical":
            rule = re.sub(pattern, f"setvar:'tx.inbound_anomaly_score_pl{pl_value}=+2'", rule)
        elif severity in ["warning", "error"]:
            rule = re.sub(pattern, f"setvar:'tx.inbound_anomaly_score_pl{pl_value}=+1'", rule)
        elif severity == "notice":
            rule = re.sub(pattern, f"setvar:'tx.inbound_anomaly_score_pl{pl_value}=+0'", rule)
    return rule

def generate_custom_rule_id(original_id):
    """
    Generate a custom rule ID that won't conflict with CRS rules.
    We'll use the 9XXXXX range for our custom rules.
    
    Args:
        original_id (str): The original CRS rule ID
        
    Returns:
        str: A new rule ID in the 9XXXXX range
    """
    return f"999{original_id}"

def extract_paranoia_rules(input_text):
    """
    Extract rules with paranoia level 3 or 4 from the input file.
    Store both original and custom IDs for each rule.
    """
    try:
        with open(input_text, 'r') as file:
            content = file.read()
        
        lines = content.splitlines()
        rules = []
        buffer = []
        
        for line in lines:
            line = line.strip()
            if line.startswith("#") or not line:
                continue

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
                    original_id = id_match.group(1)
                    custom_id = generate_custom_rule_id(original_id)
                    # Replace the original ID with our custom ID
                    adjusted_rule = re.sub(r'id:\d+', f'id:{custom_id}', rule)
                    adjusted_rule = adjust_anomaly_score(adjusted_rule)
                    # Store rule under both original and custom IDs
                    result[original_id] = adjusted_rule
                    result[custom_id] = adjusted_rule
                    
        return result
    except Exception as e:
        print(f"Error extracting rules: {str(e)}")
        return {}
