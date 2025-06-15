import re
import json

def extract_paranoia_rules(input_text):
    # Normalize line breaks and combine multiline SecRule blocks
    lines = input_text.splitlines() # return lists
    rules = []
    buffer = []
    
    for line in lines:
        line = line.strip()
        if line.startswith("#") or not line:
            continue  # Skip comments and empty lines
        # if line
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




# Example usage
if __name__ == "__main__":
    matched_id = "942251"
    with open("REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "r") as file:
        input_text = file.read()

    extracted_rules = extract_paranoia_rules(input_text)

    with open("custom_rules.conf", "a") as output_file:
        if matched_id in extracted_rules:
            output_file.write(extracted_rules[matched_id] + "\n\n")
        else:
            print(f"Rule with ID {matched_id} not found in extracted rules.")
    
    # Output as pretty JSON
    print(json.dumps(extracted_rules, indent=2))
