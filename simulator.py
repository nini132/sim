# simulator.py
# Suggestion: Install Faker for realistic data -> pip install Faker

import json
import uuid
import requests # Although not sending yet, keep for future use
import random
import time
from datetime import datetime, timedelta
from faker import Faker
from typing import Any, Dict, Optional, List
from pathlib import Path
import logging
import re
import os

# Configure logging for the application
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

fake = Faker()  # Initialize Faker

DEFAULT_CONFIG_PATH = Path(__file__).parent / "default_config.json"

class ConfigManager:
    """Handles loading, saving, and validating configuration for the simulator."""
    def __init__(self, config_file: str = "config.json"):
        self.config_file = Path(config_file)
        self.default_config = self.load_default_config()
        self.config: Dict[str, Any] = self.load_config()

    def load_default_config(self) -> Dict[str, Any]:
        if DEFAULT_CONFIG_PATH.exists():
            with open(DEFAULT_CONFIG_PATH, "r") as f:
                return json.load(f)
        # fallback to hardcoded defaults
        return {
            "SIEM_Alert": {"default_severity": "Medium"},
            "Login_Alert": {"default_status": "Success"},
            "Smart_Fence_Alert": {"default_status": "Breached"},
            "Location_Based_Alert": {"default_user": "Unknown"},
            "Motion_Sensor_Alert": {"default_status": "Detected"},
            "IR_Sensor_Alert": {"default_status": "Detected"},
            "sensor_types": {},
            "items": {}
        }

    def load_config(self) -> Dict[str, Any]:
        try:
            if self.config_file.exists():
                with self.config_file.open("r") as f:
                    loaded_config = json.load(f)
                # Merge loaded config with defaults
                for k, v in self.default_config.items():
                    if k not in loaded_config:
                        loaded_config[k] = v
                return loaded_config
            else:
                logging.warning(f"Config file '{self.config_file}' not found. Using default configuration.")
                return self.default_config
        except Exception as e:
            logging.error(f"Error loading config: {e}. Using default configuration.")
            return self.default_config

    def save_config(self) -> None:
        try:
            with self.config_file.open("w") as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving config: {e}")

    def get(self, key: str, default: Optional[Any] = None) -> Any:
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.config[key] = value
        self.save_config()

class CRCSimulator:
    def __init__(self, crc_api_base_url: Optional[str] = None, config_file: str = "config.json") -> None:
        """Initialize the simulator with an optional API base URL and configuration file."""
        self.crc_api_base_url = crc_api_base_url
        self.config_manager = ConfigManager(config_file)
        self.config = self.config_manager.config
        # Refactored: all alert source data (fields, thresholds, settings, items) under self.alert_sources
        self.alert_sources = self.config.get("alert_sources", {})
        if not self.alert_sources:
            # Migrate from old structure if needed
            default_fields = {
                "SIEM_Alert": ["severity", "description", "affectedUser", "sourceIP", "destinationIP", "protocol", "sourcePort", "destinationPort", "deviceAction", "targetResource"],
                "Login_Alert": ["loginStatus", "username", "sourceIP", "userAgent", "authenticationMethod", "failureReason", "loginTimestamp"],
                "Smart_Fence_Alert": ["fenceId", "segmentId", "alertType", "status", "detectionTimestamp", "sensorData"],
                "Location_Based_Alert": ["userId", "deviceId", "locationDescription", "latitude", "longitude", "trigger", "speed", "altitude", "accuracy"],
                "Motion_Sensor_Alert": ["itemId", "location", "status", "detectionTimestamp", "sensitivityLevel"],
                "IR_Sensor_Alert": ["itemId", "location", "status", "beamStatusTimestamp", "beamStrength"]
            }
            for event_type in get_valid_event_types():
                self.alert_sources[event_type] = {
                    "fields": default_fields.get(event_type, []),
                    "thresholds": {},
                    "settings": {},
                    "items": []
                }
            # Migrate old items if exist
            old_items = self.config.get("items", {})
            for k, v in old_items.items():
                if k in self.alert_sources:
                    self.alert_sources[k]["items"] = v
            # Migrate old thresholds/settings if exist
            for k in self.alert_sources:
                if k in self.config and isinstance(self.config[k], dict):
                    if "thresholds" in self.config[k]:
                        self.alert_sources[k]["thresholds"] = self.config[k]["thresholds"]
                    for setting_key, setting_val in self.config[k].items():
                        if setting_key not in ("thresholds", "fields", "items"):
                            self.alert_sources[k]["settings"][setting_key] = setting_val
            self.save_config()
        logging.info(f"CRCSimulator initialized. Target API URL: {self.crc_api_base_url if self.crc_api_base_url else 'Not set (printing only)' }.")

    def save_config(self) -> None:
        """Save the current alert sources configuration to the config file."""
        self.config["alert_sources"] = self.alert_sources
        self.config_manager.save_config()

    def list_alert_sources(self) -> List[str]:
        """Return a list of all alert source names."""
        return list(self.alert_sources.keys())

    def add_alert_source(self, name: str, fields: List[str]) -> None:
        """Add a new alert source with the given fields."""
        if name in self.alert_sources:
            logging.warning(f"Alert Source '{name}' already exists.")
            raise ValueError(f"Alert Source '{name}' already exists.")
        self.alert_sources[name] = {"fields": fields, "thresholds": {}, "settings": {}, "items": []}
        self.save_config()
        logging.info(f"Alert Source '{name}' added.")

    def remove_alert_source(self, name: str) -> None:
        """Remove an alert source and all its items."""
        if name not in self.alert_sources:
            logging.warning(f"Alert Source '{name}' not found.")
            raise ValueError(f"Alert Source '{name}' not found.")
        del self.alert_sources[name]
        self.save_config()
        logging.info(f"Alert Source '{name}' and its items removed.")

    def manage_alert_sources(self) -> None:
        """Interactive menu to manage alert sources (add, remove, list)."""
        while True:
            print("\n--- Manage Alert Sources ---")
            print("1. List Alert Sources")
            print("2. Add Alert Source")
            print("3. Remove Alert Source")
            print("4. Back to Main Menu")
            choice = input("Enter your choice: ").strip()
            if choice == '1':
                sources = self.list_alert_sources()
                if not sources:
                    print("No alert sources defined.")
                else:
                    print("\nAlert Sources:")
                    for i, src in enumerate(sources):
                        print(f"{i+1}. {src}")
            elif choice == '2':
                name = input("Enter new alert source name: ").strip()
                if not name:
                    print("Name cannot be empty.")
                    continue
                if name in self.alert_sources:
                    print("Alert source already exists.")
                    continue
                fields = input("Enter field names (comma separated): ").strip()
                field_list = [f.strip() for f in fields.split(',') if f.strip()]
                if not field_list:
                    print("At least one field is required.")
                    continue
                try:
                    self.add_alert_source(name, field_list)
                    print(f"Alert source '{name}' added.")
                except Exception as e:
                    print(f"Error: {e}")
            elif choice == '3':
                name = input("Enter alert source name to remove: ").strip()
                if name not in self.alert_sources:
                    print("Alert source not found.")
                    continue
                try:
                    self.remove_alert_source(name)
                    print(f"Alert source '{name}' removed.")
                except Exception as e:
                    print(f"Error: {e}")
            elif choice == '4':
                break
            else:
                print("Invalid choice. Please try again.")

    def manage_settings_for_alert_source(self) -> None:
        """Interactive menu to manage settings for a selected alert source."""
        sources = self.list_alert_sources()
        if not sources:
            print("No alert sources available. Please add an alert source first.")
            return
        for i, src in enumerate(sources):
            print(f"{i+1}. {src}")
        choice = input("Select alert source (number or name, or 'back'): ").strip()
        if choice.lower() == 'back':
            return
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(sources):
                selected = sources[idx]
            else:
                print("Invalid number.")
                return
        except ValueError:
            if choice in sources:
                selected = choice
            else:
                print("Invalid alert source name.")
                return
        settings = self.alert_sources[selected]["settings"]
        while True:
            print(f"\n--- Settings for '{selected}' ---")
            if settings:
                for i, (k, v) in enumerate(settings.items()):
                    print(f"{i+1}. {k}: {v}")
            else:
                print("No settings defined.")
            print("a. Add Setting")
            print("e. Edit Setting")
            print("d. Delete Setting")
            print("b. Back to Alert Source Management")
            action = input("Choose action: ").strip().lower()
            if action == 'a':
                key = input("Enter setting name: ").strip()
                if not key:
                    print("Setting name cannot be empty.")
                    continue
                value = input("Enter setting value: ").strip()
                settings[key] = value
                self.save_config()
                print("Setting added.")
            elif action == 'e':
                key = input("Enter setting name to edit: ").strip()
                if key not in settings:
                    print("Setting not found.")
                    continue
                value = input(f"Enter new value for '{key}': ").strip()
                settings[key] = value
                self.save_config()
                print("Setting updated.")
            elif action == 'd':
                key = input("Enter setting name to delete: ").strip()
                if key in settings:
                    del settings[key]
                    self.save_config()
                    print("Setting deleted.")
                else:
                    print("Setting not found.")
            elif action == 'b':
                break
            else:
                print("Invalid action.")

    def manage_items_for_module(self) -> None:
        """Interactive menu to manage items for a selected alert source."""
        sources = self.list_alert_sources()
        if not sources:
            print("No alert sources available. Please add an alert source first.")
            return
        for i, src in enumerate(sources):
            print(f"{i+1}. {src}")
        choice = input("Select alert source (number or name, or 'back'): ").strip()
        if choice.lower() == 'back':
            return
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(sources):
                selected = sources[idx]
            else:
                print("Invalid number.")
                return
        except ValueError:
            if choice in sources:
                selected = choice
            else:
                print("Invalid alert source name.")
                return
        while True:
            print(f"\n--- Manage Items for '{selected}' ---")
            print("1. Add Item")
            print("2. Edit Item")
            print("3. Remove Item")
            print("4. List Items")
            print("5. Search Items")
            print("6. Back to Alert Source Management")
            action = input("Enter your choice: ").strip()
            if action == '1':
                self.add_item_to_source(selected)
            elif action == '2':
                self.edit_item_in_source(selected)
            elif action == '3':
                self.remove_item_from_source(selected)
            elif action == '4':
                self.list_items_by_module(selected)
            elif action == '5':
                self.search_items_in_source(selected)
            elif action == '6':
                break
            else:
                print("Invalid choice. Please try again.")

    def add_item_to_source(self, source: str) -> None:
        """Add a new item to the given alert source."""
        fields = self.alert_sources[source]["fields"]
        item_details = {}
        for field in fields:
            value = input(f"Enter {field.replace('_', ' ').title()}: ").strip()
            try:
                self.validate_field_value(source, field, value)
            except Exception as e:
                print(f"Error: {e}")
                return
            item_details[field] = value
        item_id_prefix = source[:3].upper()
        existing_ids = [int(item["id"].split("-")[1]) for item in self.alert_sources[source]["items"] if item["id"].startswith(item_id_prefix)]
        new_item_id = f"{item_id_prefix}-{max(existing_ids) + 1:03d}" if existing_ids else f"{item_id_prefix}-001"
        new_item = {"id": new_item_id, **item_details}
        self.alert_sources[source]["items"].append(new_item)
        self.save_config()
        print(f"Item added: {new_item}")

    def edit_item_in_source(self, source: str) -> None:
        """Edit an existing item in the given alert source."""
        items = self.alert_sources[source]["items"]
        if not items:
            print("No items to edit.")
            return
        for i, item in enumerate(items):
            print(f"{i+1}. ID: {item['id']}, " + ", ".join(f"{k}: {v}" for k, v in item.items() if k != "id"))
        idx = input("Select item to edit (number or 'back'): ").strip()
        if idx.lower() == 'back':
            return
        try:
            idx = int(idx) - 1
            if 0 <= idx < len(items):
                item = items[idx]
            else:
                print("Invalid number.")
                return
        except ValueError:
            print("Invalid input.")
            return
        for field in self.alert_sources[source]["fields"]:
            old_val = item.get(field, "")
            value = input(f"Enter new value for {field} (leave empty to keep '{old_val}'): ").strip()
            if value:
                try:
                    self.validate_field_value(source, field, value)
                except Exception as e:
                    print(f"Error: {e}")
                    return
                item[field] = value
        self.save_config()
        print("Item updated.")

    def remove_item_from_source(self, source: str) -> None:
        """Remove an item from the given alert source."""
        items = self.alert_sources[source]["items"]
        if not items:
            print("No items to remove.")
            return
        for i, item in enumerate(items):
            print(f"{i+1}. ID: {item['id']}, " + ", ".join(f"{k}: {v}" for k, v in item.items() if k != "id"))
        idx = input("Select item to remove (number or 'back'): ").strip()
        if idx.lower() == 'back':
            return
        try:
            idx = int(idx) - 1
            if 0 <= idx < len(items):
                removed = items.pop(idx)
                self.save_config()
                print(f"Item removed: {removed}")
            else:
                print("Invalid number.")
        except ValueError:
            print("Invalid input.")

    def list_items_by_module(self, source: str) -> None:
        """List all items for the given alert source."""
        items = self.alert_sources[source]["items"]
        if not items:
            print(f"No items found for alert source '{source}'.")
            return
        print(f"\n--- Items for '{source}' ---")
        for item in items:
            print(f"  ID: {item['id']}, " + ", ".join(f"{k.replace('_', ' ').title()}: {v}" for k, v in item.items() if k != "id"))

    def search_items_in_source(self, source: str) -> None:
        """Search for items by ID or name in a given alert source."""
        items = self.alert_sources[source]["items"]
        if not items:
            print(f"No items found for alert source '{source}'.")
            return
        query = input("Enter search term (ID or part of name): ").strip().lower()
        results = [item for item in items if query in item.get("id", "").lower() or query in str(item).lower()]
        if not results:
            print("No matching items found.")
        else:
            print(f"Found {len(results)} matching items:")
            for item in results:
                print(f"  ID: {item['id']}, " + ", ".join(f"{k.replace('_', ' ').title()}: {v}" for k, v in item.items() if k != "id"))

    def validate_field_value(self, alert_source: str, field: str, value: str) -> bool:
        """Validate a value for a field according to its threshold (if exists) or basic rules."""
        thresholds = self.alert_sources[alert_source]["thresholds"]
        if field in thresholds:
            threshold = thresholds[field]
            # Range threshold
            if isinstance(threshold, dict) and "min" in threshold and "max" in threshold:
                try:
                    num_val = float(value)
                except ValueError:
                    logging.error(f"{field} must be a number.")
                    raise ValueError(f"{field} must be a number.")
                if not (threshold["min"] <= num_val <= threshold["max"]):
                    logging.error(f"{field} must be between {threshold['min']} and {threshold['max']}.")
                    raise ValueError(f"{field} must be between {threshold['min']} and {threshold['max']}.")
            # List threshold
            elif isinstance(threshold, list):
                if value not in threshold:
                    logging.error(f"{field} must be one of: {', '.join(threshold)}.")
                    raise ValueError(f"{field} must be one of: {', '.join(threshold)}.")
            # Single value threshold
            else:
                if str(value) != str(threshold):
                    logging.error(f"{field} must be exactly: {threshold}.")
                    raise ValueError(f"{field} must be exactly: {threshold}.")
        else:
            if not value:
                logging.error(f"{field} cannot be empty.")
                raise ValueError(f"{field} cannot be empty.")
        return True

    def simulate_event(self, event_type: str, manual: bool = False) -> None:
        """Simulate an event of the given type, with optional manual input."""
        event_data = None
        if event_type == "SIEM_Alert":
            event_data = self._get_siem_alert_details(manual)
        elif event_type == "Login_Alert":
            event_data = self._get_login_alert_details(manual)
        elif event_type == "Smart_Fence_Alert":
            event_data = self._get_smart_fence_alert_details(manual)
        elif event_type == "Location_Based_Alert":
            event_data = self._get_location_based_alert_details(manual)
        elif event_type == "Motion_Sensor_Alert":
            event_data = self.get_motion_sensor_alert_details(manual)
        elif event_type == "IR_Sensor_Alert":
            event_data = self._get_ir_sensor_alert_details(manual)
        else:
            logging.error(f"Unknown event type '{event_type}'")
            print(f"Error: Unknown event type '{event_type}'")
            return
        if event_data:
            self.send_event(event_type, event_data)
            self.cleanup_simulation_items()

    def send_event(self, event_type: str, event_data: Dict[str, Any]) -> None:
        """Format and 'send' (print) an event, and handle auto-generated items."""
        full_event = self._convert_to_crc_format(event_type, event_data)
        print("-" * 20 + f" Event Generated ({event_type}) " + "-" * 20)
        print(json.dumps(full_event, indent=2))
        print("-" * (42 + len(event_type)))
        # If a CRC API base URL is set, attempt to send the event to the API.
        if self.crc_api_base_url:
            url = f"{self.crc_api_base_url}/events" # Assuming an '/events' endpoint
            headers = {"Content-Type": "application/json"}
            try:
                # Note: Sending is disabled by default, enable if needed
                # response = requests.post(url, headers=headers, json=full_event, timeout=10)
                # response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
                # print(f"--> Event successfully sent to CRC API: {url} (Status Code: {response.status_code})")
                logging.info(f"--> NOTE: Sending to API ({url}) is currently disabled in the code.")
                pass # Comment out pass and uncomment requests.post above to enable sending
            except requests.exceptions.RequestException as e:#
                logging.error(f"Error sending event to CRC API ({url}): {e}")
            except Exception as e:
                 logging.error(f"An unexpected error occurred during sending to {url}: {e}")
        else:
            logging.warning("--> API URL not set. Event printed to console only.")
        # Ask user if they want to save auto-generated item as permanent
        if event_type in self.alert_sources:
            for item in self.alert_sources[event_type]["items"]:
                if item.get("auto_generated"):
                    print(f"\nA temporary item was auto-generated for '{event_type}': {item}")
                    save = input("Do you want to save this item as permanent? (y/n): ").strip().lower()
                    if save == 'y':
                        item.pop("auto_generated", None)
                        print("Item saved as permanent.")
                    else:
                        item["_remove_after_simulation"] = True
                        print("Item will be removed after simulation.")
            self.save_config()

    def cleanup_simulation_items(self) -> None:
        """Remove all items marked for deletion after simulation."""
        for module_data in self.alert_sources.values():
            module_data["items"] = [item for item in module_data["items"] if not item.get("_remove_after_simulation")]
        self.save_config()

    def _convert_to_crc_format(self, event_type: str, event_data: dict) -> dict:
        """
        Converts the event data to the CRC event format (adds eventId, eventType, eventTimestamp, etc).
        """
        return {
            "eventId": str(uuid.uuid4()),
            "eventType": event_type,
            "eventTimestamp": datetime.now().isoformat() + "Z",
            "data": event_data
        }

    def _get_siem_alert_details(self, manual: bool = False) -> dict:
        """Generates details for a SIEM alert event."""
        default_severity = self.alert_sources["SIEM_Alert"]["settings"].get("default_severity", "Medium")
        possible_severities = ["Low", "Medium", "High", "Critical"]
        if manual:
            severity = input(f"Enter severity ({', '.join(possible_severities)}) [default: {default_severity}]: ").capitalize().strip()
            if not severity or severity not in possible_severities:
                logging.warning(f"Invalid or empty severity. Using default: {default_severity}.")
                severity = default_severity
            description = input("Enter description: ").strip() or f"Manual SIEM event on {datetime.now().isoformat()}"
            user = input("Enter user: ").strip() or fake.user_name()
            ip = input("Enter source IP address: ").strip() or fake.ipv4()
            target_resource = input("Enter target resource: ").strip() or f"/api/v1/{fake.uri_path()}"
        else:
            severity = random.choice(possible_severities)
            description = fake.sentence(nb_words=10) + f" (Rule: {random.choice(['FW-Policy-Violation', 'Malware-Detected', 'Anomalous-Login', 'Data-Exfiltration'])})"
            user = fake.user_name()
            ip = fake.ipv4()
            target_resource = f"/api/v1/{fake.uri_path()}/{random.choice(['users','data','config'])}"
        return {
            "source": "SIEM",
            "alertName": f"{severity} severity alert detected",
            "severity": severity,
            "description": description,
            "affectedUser": user,
            "sourceIP": ip,
            "destinationIP": fake.ipv4(),
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "sourcePort": random.randint(1024, 65535),
            "destinationPort": random.choice([80, 443, 22, 3389, 53, random.randint(1024, 65535)]),
            "deviceAction": random.choice(["Allowed", "Blocked", "Logged", "Alerted"]),
            "targetResource": target_resource,
            "additionalInfo": {"rule_id": f"SIEM-{random.randint(1000,9999)}", "threat_score": round(random.uniform(0.1, 1.0), 2)}
        }

    def _get_login_alert_details(self, manual: bool = False) -> dict:
        """Generates details for a login alert event."""
        default_status = self.alert_sources["Login_Alert"]["settings"].get("default_status", "Success")
        possible_statuses = ["Success", "Failure"]
        if manual:
            status = input(f"Enter status ({', '.join(possible_statuses)}) [default: {default_status}]: ").capitalize().strip()
            if not status or status not in possible_statuses:
                logging.warning(f"Invalid or empty status. Using default: {default_status}.")
                status = default_status
            user = input("Enter user: ").strip() or fake.user_name()
            ip = input("Enter source IP address: ").strip() or fake.ipv4()
            auth_method = input("Enter auth method (Password, MFA, SSO): ").strip() or "Password"
        else:
            status = random.choices(possible_statuses, weights=[85, 15], k=1)[0]
            user = fake.user_name()
            ip = fake.ipv4()
            auth_method = random.choice(["Password", "MFA", "SSO", "API Key"])
        return {
            "source": "Authentication Service",
            "loginStatus": status,
            "username": user,
            "sourceIP": ip,
            "userAgent": fake.user_agent(),
            "authenticationMethod": auth_method,
            "failureReason": fake.sentence(nb_words=5) if status == "Failure" else None,
            "loginTimestamp": (datetime.now() - timedelta(seconds=random.randint(1, 300))).isoformat() + "Z"
        }

    def _get_smart_fence_alert_details(self, manual: bool = False) -> dict:
        """Generates details for a smart fence alert event."""
        default_status = self.alert_sources["Smart_Fence_Alert"]["settings"].get("default_status", "Breached")
        possible_statuses = ["Breached", "Secure", "Tamper Detected", "Low Battery"]
        if manual:
            location = input("Enter fence location/segment ID: ").strip() or f"Segment-{random.randint(100,999)}"
            type_alert = input("Enter alert type (e.g., Climb, Cut, Tamper): ").strip() or "Climb"
            status = input(f"Enter status ({', '.join(possible_statuses)}) [default: {default_status}]: ").strip() or default_status
            if status not in possible_statuses: status = default_status
        else:
            location = f"{random.choice(['North Perimeter', 'East Gate', 'Warehouse Sector', 'Restricted Zone'])} Segment-{random.randint(100,999)}"
            type_alert = random.choice(["Climb Attempt", "Fence Cut", "Tamper Detected", "Impact Detected", "Zone Entry"])
            status = random.choices(possible_statuses, weights=[60, 30, 5, 5], k=1)[0]
        return {
            "source": "Smart Fence Controller",
            "fenceId": f"FNC-{random.randint(10,99)}",
            "segmentId": location,
            "alertType": type_alert,
            "status": status,
            "detectionTimestamp": (datetime.now() - timedelta(seconds=random.randint(1, 120))).isoformat() + "Z",
            "sensorData": {"vibration": round(random.uniform(0, 5.0), 2) if "Impact" in type_alert or "Tamper" in type_alert else 0,
                           "voltage": round(random.uniform(11.5, 12.5), 2) if status != "Low Battery" else round(random.uniform(10.0, 11.0), 2)}
        }

    def _get_location_based_alert_details(self, manual: bool = False) -> dict:
        """Generates details for a location-based alert event."""
        default_user = self.alert_sources["Location_Based_Alert"]["settings"].get("default_user", fake.user_name())
        if manual:
            user = input(f"Enter user [default: {default_user}]: ").strip() or default_user
            location_desc = input("Enter location description (e.g., Warehouse Floor): ").strip() or "Main Office"
            latitude = input("Enter latitude: ").strip() or str(fake.latitude())
            longitude = input("Enter longitude: ").strip() or str(fake.longitude())
            event_trigger = input("Enter event trigger (e.g., Geofence Entry, Panic Button): ").strip() or "Geofence Entry"
        else:
            user = fake.user_name()
            location_desc = f"{random.choice(['Building', 'Site', 'Area'])} {fake.word().capitalize()}"
            latitude = str(fake.latitude())
            longitude = str(fake.longitude())
            event_trigger = random.choice(["Geofence Entry", "Geofence Exit", "Panic Button", "Man Down Alert", "Asset Movement"])
        return {
            "source": "Personnel Tracking System",
            "userId": user,
            "deviceId": f"DEV-{random.randint(10000, 99999)}",
            "locationDescription": location_desc,
            "latitude": latitude,
            "longitude": longitude,
            "trigger": event_trigger,
            "speed": round(random.uniform(0, 5.0), 1) if "Movement" in event_trigger else 0,
            "altitude": round(random.uniform(50, 150), 1),
            "accuracy": round(random.uniform(5, 50), 1)
        }

    def get_motion_sensor_alert_details(self, manual: bool = False) -> dict:
        """Generates details for a motion sensor alert event."""
        default_status = self.alert_sources["Motion_Sensor_Alert"]["settings"].get("default_status", "Detected")
        possible_statuses = ["Detected", "Clear"]
        if manual:
            location = input("Enter sensor location: ").strip() or f"Room {random.randint(101, 599)}"
            status = input(f"Enter status ({', '.join(possible_statuses)}) [default: {default_status}]: ").capitalize().strip()
            if not status or status not in possible_statuses: status = default_status
            timestamp_str = input("Enter timestamp (YYYY-MM-DDTHH:MM:SSZ): ").strip() or (datetime.now() - timedelta(seconds=random.randint(1, 180))).isoformat() + "Z"
        else:
            location = f"{random.choice(['Corridor', 'Office', 'Entrance', 'Storage'])} {random.randint(1, 50)}"
            status = random.choices(possible_statuses, weights=[70, 30], k=1)[0]
            timestamp_str = (datetime.now() - timedelta(seconds=random.randint(1, 180))).isoformat() + "Z"
        items = self.alert_sources["Motion_Sensor_Alert"]["items"]
        item = next((item for item in items if item.get("location") == location), None)
        if item:
            item["value"] = status
        else:
            item_id_prefix = "MOT"
            existing_ids = [int(item["id"].split("-")[1]) for item in items if item["id"].startswith(item_id_prefix)]
            if existing_ids:
                new_item_id = f"{item_id_prefix}-{max(existing_ids) + 1:03d}"
            else:
                new_item_id = f"{item_id_prefix}-001"
            item = {"id": new_item_id, "name": f"Motion Sensor at {location}", "location": location, "value": status, "auto_generated": True}
            items.append(item)
        return {
            "source": "PIR Motion Sensor",
            "itemId": item["id"],
            "location": item["location"],
            "status": item["value"],
            "detectionTimestamp": timestamp_str,
            "sensitivityLevel": random.choice(["Low", "Medium", "High"])
        }

    def _get_ir_sensor_alert_details(self, manual: bool = False) -> dict:
        """Generates details for an IR sensor alert event."""
        default_status = self.alert_sources["IR_Sensor_Alert"]["settings"].get("default_status", "Detected")
        possible_statuses = ["Detected", "Clear", "Obscured"]
        if manual:
            location = input("Enter sensor location: ").strip() or f"Doorway {random.randint(1, 20)}"
            status = input(f"Enter status ({', '.join(possible_statuses)}) [default: {default_status}]: ").capitalize().strip()
            if not status or status not in possible_statuses: status = default_status
            timestamp_str = input("Enter timestamp (YYYY-MM-DDTHH:MM:SSZ): ").strip() or (datetime.now() - timedelta(seconds=random.randint(1, 180))).isoformat() + "Z"
        else:
            location = f"{random.choice(['Main Gate', 'Window', 'Passageway', 'Secure Entry'])} {random.randint(1, 10)}"
            status = random.choices(possible_statuses, weights=[65, 30, 5], k=1)[0]
            timestamp_str = (datetime.now() - timedelta(seconds=random.randint(1, 180))).isoformat() + "Z"
        items = self.alert_sources["IR_Sensor_Alert"]["items"]
        item = next((item for item in items if item.get("location") == location), None)
        if item:
            item["value"] = status
        else:
            item_id_prefix = "IR"
            existing_ids = [int(item["id"].split("-")[1]) for item in items if item["id"].startswith(item_id_prefix)]
            if existing_ids:
                new_item_id = f"{item_id_prefix}-{max(existing_ids) + 1:03d}"
            else:
                new_item_id = f"{item_id_prefix}-001"
            item = {"id": new_item_id, "name": f"IR Sensor at {location}", "location": location, "value": status, "auto_generated": True}
            items.append(item)
        return {
            "source": "IR Beam Sensor",
            "itemId": item["id"],
            "location": item["location"],
            "status": item["value"],
            "beamStatusTimestamp": timestamp_str,
            "beamStrength": round(random.uniform(70.0, 100.0), 1) if status != "Obscured" else round(random.uniform(10.0, 50.0), 1)
        }

def get_valid_event_types() -> List[str]:
    """Returns a list of valid event types based on simulator methods."""
    return [
        "SIEM_Alert", "Login_Alert", "Smart_Fence_Alert",
        "Location_Based_Alert", "Motion_Sensor_Alert", "IR_Sensor_Alert"
    ]

class SimulatorCLI:
    """Handles all CLI (user interface) logic for the simulator."""
    def __init__(self, simulator: CRCSimulator) -> None:
        self.simulator = simulator

    def main_menu(self) -> None:
        while True:
            print("\n--- CRC Event Simulator ---")
            print("1. Manage Alert Sources")
            print("2. Manage Items")
            print("3. Manage Thresholds")
            print("4. Manage Settings")
            print("5. Simulate Event")
            print("6. Run Automation")
            print("7. Exit")
            choice = input("Enter your choice: ").strip()
            if choice == '1':
                self.simulator.manage_alert_sources()
            elif choice == '2':
                self.simulator.manage_items_for_module()
            elif choice == '3':
                self.simulator.manage_thresholds_for_module()
            elif choice == '4':
                self.simulator.manage_settings_for_alert_source()
            elif choice == '5':
                self.simulate_event_menu()
            elif choice == '6':
                self.run_automation_menu()
            elif choice == '7':
                print("Exiting. Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")

    def simulate_event_menu(self) -> None:
        sources = self.simulator.list_alert_sources()
        print("\n--- Simulate Event ---")
        for i, src in enumerate(sources):
            print(f"{i+1}. {src}")
        choice = input("Select event type (number or name, or 'back'): ").strip()
        if choice.lower() == 'back':
            return
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(sources):
                event_type = sources[idx]
            else:
                print("Invalid number.")
                return
        except ValueError:
            if choice in sources:
                event_type = choice
            else:
                print("Invalid event type.")
                return
        manual = input("Manual input? (y/n): ").strip().lower() == 'y'
        self.simulator.simulate_event(event_type, manual)

    def run_automation_menu(self) -> None:
        print("\n--- Run Automation ---")
        try:
            num_events = int(input("Number of events to generate: ").strip())
            delay = float(input("Delay between events (seconds): ").strip())
        except ValueError:
            print("Invalid input.")
            return
        mode = input("Mode (random/type): ").strip().lower()
        event_type = None
        if mode == 'type':
            sources = self.simulator.list_alert_sources()
            for i, src in enumerate(sources):
                print(f"{i+1}. {src}")
            choice = input("Select event type (number or name): ").strip()
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(sources):
                    event_type = sources[idx]
                else:
                    print("Invalid number.")
                    return
            except ValueError:
                if choice in sources:
                    event_type = choice
                else:
                    print("Invalid event type.")
                    return
        for i in range(num_events):
            et = event_type if event_type else random.choice(self.simulator.list_alert_sources())
            print(f"\n[Automation Event {i+1}/{num_events}]")
            self.simulator.simulate_event(et, manual=False)
            if delay > 0:
                time.sleep(delay)
        print("\nAutomation finished.")

def main() -> None:
    """Main function to run the event simulator console interface."""
    crc_api_url_input = input("Enter the CRC API base URL (e.g., http://localhost:8080, leave empty to print only): ").strip()
    simulator = CRCSimulator(crc_api_base_url=crc_api_url_input or None)
    cli = SimulatorCLI(simulator)
    cli.main_menu()

if __name__ == "__main__":
    main()
