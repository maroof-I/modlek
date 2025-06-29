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
        """Extract rule IDs from rule content using regex."""
        rule_ids = []
        pattern = r'id:(\d+)'
        matches = re.finditer(pattern, rule_content)
        for match in matches:
            rule_ids.append(match.group(1))
        return rule_ids

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
                if f"SecRuleRemoveById {rule_id}" not in content:
                    new_exclusions.append(f"SecRuleRemoveById {rule_id}")
            
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
            
            # Debug: Print found rule IDs
            rule_ids = self.extract_rule_ids(rule_content)
            self.logger.info(f"Found rule IDs in custom_rules.conf: {rule_ids}")
            
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