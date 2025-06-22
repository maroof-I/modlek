import re

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

def get_existing_rules(filename="custom_rules.conf"):
    """Read existing rules from custom_rules.conf and return their IDs."""
    existing_rule_ids = set()
    try:
        with open(filename, "r") as file:
            content = file.read()
            for id_match in re.finditer(r"id\s*:\s*(\d+)", content):
                existing_rule_ids.add(id_match.group(1))
    except FileNotFoundError:
        pass
    return existing_rule_ids
