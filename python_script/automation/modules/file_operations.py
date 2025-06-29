import re
import os

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

def get_existing_rules(filename=None):
    """Read existing rules from custom_rules.conf and return their IDs."""
    if filename is None:
        # Use absolute path relative to this script's location
        filename = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "custom_rules.conf"
        )
    
    existing_rule_ids = set()
    try:
        with open(filename, "r") as file:
            content = file.read()
            # Extract both original and custom rule IDs
            for id_match in re.finditer(r"id\s*:\s*(\d+)", content):
                rule_id = id_match.group(1)
                existing_rule_ids.add(rule_id)
                # If it's not already a custom ID (doesn't start with 999),
                # also add its potential custom ID version
                if not rule_id.startswith('999'):
                    existing_rule_ids.add(f"999{rule_id}")
    except FileNotFoundError:
        pass
    return existing_rule_ids
