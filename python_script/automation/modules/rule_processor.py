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
    if severity_match:
        severity = severity_match.group(1).lower()
        pl = re.search(r"tag:'paranoia-level/([34])'", rule)
        pattern = r"setvar:'tx\.inbound_anomaly_score_pl[34]=\+(%\{tx\..*?_anomaly_score\})'"
        
        if severity == "critical":
            rule = re.sub(pattern, f"setvar:'tx.inbound_anomaly_score_pl{pl.group(1)}=+2'", rule)
        elif severity in ["warning", "error"]:
            rule = re.sub(pattern, f"setvar:'tx.inbound_anomaly_score_pl{pl.group(1)}=+1'", rule)
        elif severity == "notice":
            rule = re.sub(pattern, f"setvar:'tx.inbound_anomaly_score_pl{pl.group(1)}=+0'", rule)
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
                result[custom_id] = adjusted_rule
                
    return result
