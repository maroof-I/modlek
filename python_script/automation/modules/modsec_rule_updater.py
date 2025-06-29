import subprocess
import logging
import os
import re
from pathlib import Path

class ModSecRuleUpdater:
    def __init__(self, container_name="modsecurity", custom_rules_path=None):
        """
        Initialize the ModSecurity rule updater.
        
        Args:
            container_name (str): Name of the ModSecurity container
            custom_rules_path (str): Path to the custom rules file
        """
        self.container_name = container_name
        self.custom_rules_path = custom_rules_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "custom_rules.conf"
        )
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("ModSecRuleUpdater")

    def extract_rule_ids(self, rule_content):
        """
        Extract rule IDs from rule content using regex.
        Returns both original and custom (999-prefixed) rule IDs.
        """
        rule_ids = set()
        pattern = r'id:(\d+)'
        matches = re.finditer(pattern, rule_content)
        for match in matches:
            rule_id = match.group(1)
            rule_ids.add(rule_id)
            # If it's an original rule ID (not starting with 999), add its custom version too
            if not rule_id.startswith('999'):
                rule_ids.add(f"999{rule_id}")
        return list(rule_ids)

    def check_rule_id_conflicts(self, rule_ids):
        """
        Check for rule ID conflicts between original and custom rules.
        Returns True if no conflicts found, False otherwise.
        """
        original_ids = set()
        custom_ids = set()
        
        for rule_id in rule_ids:
            if rule_id.startswith('999'):
                custom_ids.add(rule_id)
                # Get the original ID by removing '999' prefix
                original_id = rule_id[3:]
                if original_id in original_ids:
                    self.logger.error(f"Conflict found: Rule {original_id} exists with both original and custom (999) prefix")
                    return False
            else:
                original_ids.add(rule_id)
                # Check if custom version exists
                custom_id = f"999{rule_id}"
                if custom_id in custom_ids:
                    self.logger.error(f"Conflict found: Rule {rule_id} exists with both original and custom (999) prefix")
                    return False
        return True

    def add_rule_exclusions(self, rule_ids):
        """Add rule exclusions to the exclusions file."""
        try:
            exclusions_file = os.path.join(os.path.dirname(self.custom_rules_path), "../modsec-config/rule-exclusions.conf")
            
            # Read current content to check for existing exclusions
            with open(exclusions_file, 'r') as f:
                content = f.read()
            
            # Add new exclusions if they don't exist
            new_exclusions = []
            for rule_id in rule_ids:
                # If it's a custom rule ID (starts with 999), get the original rule ID
                original_rule_id = rule_id[3:] if rule_id.startswith('999') else rule_id
                if f"SecRuleRemoveById {original_rule_id}" not in content:
                    new_exclusions.append(f"SecRuleRemoveById {original_rule_id}")
            
            if new_exclusions:
                # Append new exclusions to the file
                with open(exclusions_file, 'a') as f:
                    f.write("\n" + "\n".join(new_exclusions) + "\n")
                
                self.logger.info(f"Added {len(new_exclusions)} rule exclusions")
                return True
            
            return True  # No new exclusions needed
        except Exception as e:
            self.logger.error(f"Failed to add rule exclusions: {str(e)}")
            return False

    def check_container_running(self):
        """Check if the ModSecurity container is running."""
        try:
            result = subprocess.run(
                ["docker", "container", "inspect", "-f", "{{.State.Running}}", self.container_name],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip().lower() == "true"
        except subprocess.CalledProcessError:
            self.logger.error(f"Container {self.container_name} not found")
            return False

    def reload_apache(self):
        """Reload Apache configuration in the container."""
        try:
            subprocess.run(
                ["docker", "exec", self.container_name, "apachectl", "graceful"],
                check=True
            )
            self.logger.info("Successfully reloaded Apache configuration")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to reload Apache configuration: {str(e)}")
            return False

    def rule_exists(self, rule_id):
        """Check if a rule ID already exists in the custom rules file."""
        try:
            with open(self.custom_rules_path, 'r') as f:
                content = f.read()
            return f"id:{rule_id}" in content
        except Exception as e:
            self.logger.error(f"Error checking for existing rule: {str(e)}")
            return False

    def update_rules(self):
        """Main method to update ModSecurity rules."""
        if not self.check_container_running():
            self.logger.error("ModSecurity container is not running")
            return False

        try:
            # Debug: Print file path
            self.logger.info(f"Reading custom rules from: {self.custom_rules_path}")
            
            # Read the custom rules file to extract rule IDs
            with open(self.custom_rules_path, 'r') as f:
                rule_content = f.read()
            
            # Extract and check rule IDs
            rule_ids = self.extract_rule_ids(rule_content)
            self.logger.info(f"Found rule IDs in custom_rules.conf: {rule_ids}")
            
            # Check for rule ID conflicts
            if not self.check_rule_id_conflicts(rule_ids):
                return False
            
            # Debug: Check container file
            try:
                result = subprocess.run(
                    ["docker", "exec", self.container_name, "cat", "/etc/modsecurity.d/custom_rules.conf"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                container_rule_ids = self.extract_rule_ids(result.stdout)
                self.logger.info(f"Rule IDs in container: {container_rule_ids}")

                # Check for conflicts in container rules
                if not self.check_rule_id_conflicts(container_rule_ids):
                    return False

            except Exception as e:
                self.logger.error(f"Failed to read container file: {str(e)}")

            if not self.add_rule_exclusions(rule_ids):
                return False

            # Since we're using Docker volumes, files are automatically synced
            # Just need to reload Apache
            success = self.reload_apache()

            if success:
                self.logger.info("ModSecurity rules update completed successfully")
            else:
                self.logger.error("ModSecurity rules update failed")

            return success
            
        except Exception as e:
            self.logger.error(f"Error during rules update: {str(e)}")
            return False

if __name__ == "__main__":
    updater = ModSecRuleUpdater()
    updater.update_rules() 