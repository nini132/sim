# simulator.py
# Suggestion: Install Faker for realistic data -> pip install Faker

import json
import uuid
import requests # Although not sending yet, keep for future use
import random
import time
from datetime import datetime, timedelta
from faker import Faker

fake = Faker() # Initialize Faker

class CRCSimulator:
    def __init__(self, crc_api_base_url=None, config_file="config.json"):
        """
        Initializes the CRC Simulator.

        Args:
            crc_api_base_url (str, optional): The base URL of the CRC API. Defaults to None.
            config_file (str, optional): Path to the configuration file. Defaults to "config.json".
        """
        self.crc_api_base_url = crc_api_base_url
        self.config = self.load_config(config_file)
        self.sensor_types = {}  # Initialize sensor types dictionary
        print(f"CRCSimulator initialized. Target API URL: {self.crc_api_base_url if self.crc_api_base_url else 'Not set (printing only)'}")

    def load_config(self, config_file):
        """
        Loads configuration from a JSON file.
        Provides default values if the file or specific settings are missing.
        """
        default_config = {
            "SIEM_Alert": {"default_severity": "Medium"},
            "Login_Alert": {"default_status": "Success"},
            "Smart_Fence_Alert": {"default_status": "Breached"},
            "Location_Based_Alert": {"default_user": "Unknown"},
            "Motion_Sensor_Alert": {"default_status": "Detected"},
            "IR_Sensor_Alert": {"default_status": "Detected"}
        }
        try:
            with open(config_file, "r") as f:
                loaded_config = json.load(f)
                # Merge loaded config with defaults to ensure all keys exist
                for event_type, defaults in default_config.items():
                    if event_type not in loaded_config:
                        loaded_config[event_type] = defaults
                    else:
                        for key, value in defaults.items():
                            loaded_config[event_type].setdefault(key, value)
                print(f"Configuration loaded from '{config_file}'")
                return loaded_config
        except FileNotFoundError:
            print(f"Warning: Config file '{config_file}' not found. Using default configuration.")
            return default_config
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON format in '{config_file}'. Using default configuration.")
            return default_config
        except Exception as e:
            print(f"Error loading config file '{config_file}': {e}. Using default configuration.")
            return default_config

    def save_config(self, config_file="config.json"):
        """Saves the current configuration to a JSON file."""
        try:
            with open(config_file, "w") as f:
                json.dump(self.config, f, indent=2)
            print(f"Configuration saved to '{config_file}'")
        except Exception as e:
            print(f"Error saving config file '{config_file}': {e}")

    def add_sensor_type(self, name, fields):
        """
        Adds a new sensor type.

        Args:
            name (str): The name of the sensor type.
            fields (list): A list of data fields for the sensor type.

        Raises:
            ValueError: If the sensor type already exists.
        """
        if name in self.sensor_types:
            raise ValueError(f"Sensor type '{name}' already exists.")
        self.sensor_types[name] = {"fields": fields}
        print(f"Sensor type '{name}' added with fields: {fields}")

    def remove_sensor_type(self, name):
        """
        Removes a sensor type.

        Args:
            name (str): The name of the sensor type.

        Raises:
            ValueError: If the sensor type does not exist.
        """
        if name not in self.sensor_types:
            raise ValueError(f"Sensor type '{name}' not found.")
        del self.sensor_types[name]
        print(f"Sensor type '{name}' removed.")

    def get_sensor_type(self, name):
        """
        Retrieves information about a sensor type.
        """
        if name not in self.sensor_types:
            raise ValueError(f"Sensor type '{name}' not found.")
        return self.sensor_types[name]

    def list_sensor_types(self):
        """
        Lists all available sensor types.
        """
        return list(self.sensor_types.keys())

    def convert_to_crc_format(self, event_type, event_data):
        """Formats the event data into the expected CRC structure."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat() + "Z" # Adding Z for UTC indication common in APIs
        full_event = {
            "crcEventId": event_id,
            "crcTimestamp": timestamp,
            "crcEventType": event_type,
            "crcEventData": event_data # The specific details for this event type
        }
        return full_event

    def send_event(self, event_type, event_data):
        """Formats and 'sends' the event (currently prints it)."""
        full_event = self.convert_to_crc_format(event_type, event_data)
        print("-" * 20 + f" Event Generated ({event_type}) " + "-" * 20)
        print(json.dumps(full_event, indent=2))
        print("-" * (42 + len(event_type))) # Match the line length above

        if self.crc_api_base_url:
            url = f"{self.crc_api_base_url}/events" # Assuming an '/events' endpoint
            headers = {"Content-Type": "application/json"}
            try:
                # Note: Sending is disabled by default, enable if needed
                # response = requests.post(url, headers=headers, json=full_event, timeout=10)
                # response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
                # print(f"--> Event successfully sent to CRC API: {url} (Status Code: {response.status_code})")
                print(f"--> NOTE: Sending to API ({url}) is currently disabled in the code.")
                pass # Comment out pass and uncomment requests.post above to enable sending
            except requests.exceptions.RequestException as e:
                print(f"Error sending event to CRC API ({url}): {e}")
            except Exception as e:
                 print(f"An unexpected error occurred during sending to {url}: {e}")
        else:
            print("--> API URL not set. Event printed to console only.")


    # --- Detail Generation Functions ---

    def get_siem_alert_details(self, manual=False):
        default_severity = self.config.get("SIEM_Alert", {}).get("default_severity", "Medium")
        possible_severities = ["Low", "Medium", "High", "Critical"]
        if manual:
            severity = input(f"Enter severity ({', '.join(possible_severities)}) [default: {default_severity}]: ").capitalize().strip()
            if not severity or severity not in possible_severities:
                print(f"Invalid or empty severity. Using default: {default_severity}.")
                severity = default_severity
            description = input("Enter description: ").strip() or f"Manual SIEM event on {datetime.now()}"
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
            "destinationIP": fake.ipv4(), # Add a destination IP
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "sourcePort": random.randint(1024, 65535),
            "destinationPort": random.choice([80, 443, 22, 3389, 53, random.randint(1024, 65535)]),
            "deviceAction": random.choice(["Allowed", "Blocked", "Logged", "Alerted"]),
            "targetResource": target_resource,
            "additionalInfo": {"rule_id": f"SIEM-{random.randint(1000,9999)}", "threat_score": round(random.uniform(0.1, 1.0), 2)}
        }

    def get_login_alert_details(self, manual=False):
        default_status = self.config.get("Login_Alert", {}).get("default_status", "Success")
        possible_statuses = ["Success", "Failure"]
        if manual:
            status = input(f"Enter status ({', '.join(possible_statuses)}) [default: {default_status}]: ").capitalize().strip()
            if not status or status not in possible_statuses:
                print(f"Invalid or empty status. Using default: {default_status}.")
                status = default_status
            user = input("Enter user: ").strip() or fake.user_name()
            ip = input("Enter source IP address: ").strip() or fake.ipv4()
            auth_method = input("Enter auth method (Password, MFA, SSO): ").strip() or "Password"
        else:
            status = random.choices(possible_statuses, weights=[85, 15], k=1)[0] # More successes
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

    def get_smart_fence_alert_details(self, manual=False):
        default_status = self.config.get("Smart_Fence_Alert", {}).get("default_status", "Breached")
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

    def get_location_based_alert_details(self, manual=False):
        default_user = self.config.get("Location_Based_Alert", {}).get("default_user", fake.user_name())
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
            "speed": round(random.uniform(0, 5.0), 1) if "Movement" in event_trigger else 0, # km/h
            "altitude": round(random.uniform(50, 150), 1), # meters
            "accuracy": round(random.uniform(5, 50), 1) # meters
        }

    def get_motion_sensor_alert_details(self, manual=False):
        default_status = self.config.get("Motion_Sensor_Alert", {}).get("default_status", "Detected")
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

        return {
            "source": "PIR Motion Sensor",
            "sensorId": f"MOT-{random.randint(1000, 9999)}",
            "location": location,
            "status": status,
            "detectionTimestamp": timestamp_str,
            "sensitivityLevel": random.choice(["Low", "Medium", "High"])
        }

    def get_ir_sensor_alert_details(self, manual=False):
        default_status = self.config.get("IR_Sensor_Alert", {}).get("default_status", "Detected")
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

        return {
            "source": "IR Beam Sensor",
            "sensorId": f"IR-{random.randint(100, 999)}",
            "location": location,
            "status": status, # Beam broken (Detected) or clear
            "beamStatusTimestamp": timestamp_str,
            "beamStrength": round(random.uniform(70.0, 100.0), 1) if status != "Obscured" else round(random.uniform(10.0, 50.0), 1)
        }

    # --- Simulation Logic ---

    def simulate_event(self, event_type, manual=False):
        """Simulates a single event of the specified type."""
        event_data = None
        if event_type == "SIEM_Alert":
            event_data = self.get_siem_alert_details(manual)
        elif event_type == "Login_Alert":
            event_data = self.get_login_alert_details(manual)
        elif event_type == "Smart_Fence_Alert":
            event_data = self.get_smart_fence_alert_details(manual)
        elif event_type == "Location_Based_Alert":
            event_data = self.get_location_based_alert_details(manual)
        elif event_type == "Motion_Sensor_Alert":
            event_data = self.get_motion_sensor_alert_details(manual)
        elif event_type == "IR_Sensor_Alert":
            event_data = self.get_ir_sensor_alert_details(manual)
        else:
            print(f"Error: Unknown event type '{event_type}'")
            return

        if event_data:
            # Check for thresholds and trigger alerts if necessary
            thresholds = self.config.get(event_type, {}).get("thresholds", {})
            for field, threshold_value in thresholds.items():
                if field in event_data:
                    value = event_data[field]
                    if isinstance(threshold_value, dict):
                        # Range-based threshold
                        min_val = threshold_value.get("min")
                        max_val = threshold_value.get("max")
                        if (min_val is not None and value < min_val) or \
                           (max_val is not None and value > max_val):
                            print(f"!!! ALERT: {event_type} - '{field}' ({value}) breaches threshold: {threshold_value}")
                    elif isinstance(threshold_value, list):
                        # List-based threshold (e.g., specific values trigger alert)
                        if value in threshold_value:
                            print(f"!!! ALERT: {event_type} - '{field}' ({value}) breaches threshold: {threshold_value}")
                    # Add more threshold types (e.g., regex, greater_than) as needed
            self.send_event(event_type, event_data)

# --- Main Execution / User Interface ---

def run_automation(simulator):
    """Runs the event simulator in automation mode."""
    while True:
        try:
            num_events_str = input("Enter the number of events to generate: ").strip()
            if not num_events_str: raise ValueError("Input cannot be empty.")
            num_events = int(num_events_str)
            if num_events <= 0: raise ValueError("Number of events must be positive.")
            break
        except ValueError as e:
            print(f"Invalid input: {e}. Please enter a positive integer.")

    while True:#
        try:
            delay_str = input("Enter the delay between events in seconds (e.g., 0.5): ").strip()
            if not delay_str: raise ValueError("Input cannot be empty.")
            delay = float(delay_str)
            if delay < 0: raise ValueError("Delay cannot be negative.")
            break
        except ValueError as e:
            print(f"Invalid input: {e}. Please enter a non-negative number.")

    event_mode = ""
    while event_mode not in ["random", "type"]:
        event_mode = input("Run automation on random mode or select specific event type? (random/type): ").strip().lower()
        if event_mode not in ["random", "type"]:
            print("Invalid input, please choose 'random' or 'type'.")

    specific_event_type = None
    if event_mode == "type":
        valid_event_types = get_valid_event_types()
        while True:
            print("""\nAvailable event types:""")
            for i, etype in enumerate(valid_event_types):
                print(f"{i+1}. {etype}")
            event_type_choice = input(f"Enter the number or name of the event type to simulate: ").strip()

            try:
                choice_index = int(event_type_choice) - 1
                if 0 <= choice_index < len(valid_event_types):
                    specific_event_type = valid_event_types[choice_index]
                    break
                else:
                    print("Invalid number.")
            except ValueError:
                # Check if input matches a type name (case-insensitive)
                matched_type = next((etype for etype in valid_event_types if etype.lower() == event_type_choice.lower()), None)
                if matched_type:
                    specific_event_type = matched_type
                    break
                else:
                    print("Invalid event type name.")
    print(f"\nStarting automation: Generating {num_events} event(s) with {delay}s delay...")
    print("Mode:", event_mode.capitalize() + (", Type:" + specific_event_type if specific_event_type else ""))
    print("Press Ctrl+C to stop early.")
    try:
        for i in range(num_events):
            event_to_simulate = specific_event_type if specific_event_type else random.choice(get_valid_event_types())
            if not event_to_simulate:
                print("No valid event types found. Please add a sensor type first.")
                break
            print(f"\n[Automation Event {i+1}/{num_events}]")
            simulator.simulate_event(event_to_simulate, manual=False) # Automation always uses generated data#
            if delay > 0:
                time.sleep(delay)
        print("\nAutomation finished.")
    except KeyboardInterrupt:#
        print("\nAutomation stopped by user.")

def change_crc_api_url(simulator):
    """Allows the user to change the CRC API URL."""
    print(
        f"\nCurrent CRC API Base URL: {simulator.crc_api_base_url if simulator.crc_api_base_url else 'Not set (printing only)'}")
    new_url = input("Enter the new CRC API base URL (leave empty to disable sending, 'back' to cancel): ").strip()#
    if new_url.lower() == "back":
        return
    if not new_url:
        simulator.crc_api_base_url = None
        print("CRC API URL cleared. Events will only be printed.")
    else:
        # Basic validation (can be improved)
        if not new_url.startswith(("http://", "https://")):
             print("Warning: URL does not start with http:// or https://. Make sure it's correct.")#
        simulator.crc_api_base_url = new_url
        print(f"CRC API base URL updated to: {simulator.crc_api_base_url}")

def change_config(simulator):
    """Allows the user to change the default configuration settings."""
    config_changed = False
    while True:
        print("\nCurrent Default Configuration Settings:")
        valid_event_types = get_valid_event_types()
        for i, event_type in enumerate(valid_event_types):
            print(f"\n{i+1}. {event_type}:")
            self.display_event_type_settings(simulator.config, event_type)

        type_choice = input("\nEnter the number or name of the event type to modify (or 'back' to return): ").strip()
        if type_choice.lower() == "back":
            break

        selected_type = self.get_selected_event_type(valid_event_types, type_choice)
        if not selected_type:
            continue

        if "thresholds" in simulator.config.get(selected_type, {}):
            if self.manage_thresholds(simulator, selected_type):
                config_changed = True
        else:
            print(f"No thresholds found for {selected_type}.")
            if self.manage_other_settings(simulator, selected_type):
                config_changed = True

    if config_changed:
        self.save_configuration_changes(simulator)

    def display_event_type_settings(self, config, event_type):
        settings = config.get(event_type, {})
        if not settings:
            print("  (No specific defaults)")
            return

        for key, value in settings.items():
            if key == "thresholds":
                print("  - Thresholds:")
                self.display_thresholds(value)
            else:
                print(f"  - {key}: {value}")

    def display_thresholds(self, thresholds):
        for field, threshold_value in thresholds.items():
            print(f"    - {field}: {threshold_value}")

    def get_selected_event_type(self, valid_event_types, type_choice):
        try:
            choice_index = int(type_choice) - 1
            if 0 <= choice_index < len(valid_event_types):
                return valid_event_types[choice_index]
        except ValueError:
            matched_type = next((etype for etype in valid_event_types if etype.lower() == type_choice.lower()), None)
            if matched_type:
                return matched_type
        print("Invalid event type name.")
        return None

    def manage_thresholds(self, simulator, selected_type):
        while True:
            print(f"\nThresholds for {selected_type}:")
            thresholds = simulator.config[selected_type]["thresholds"]
            available_thresholds = list(thresholds.keys())
            for i, threshold_name in enumerate(available_thresholds):
                print(f"{i + 1}. {threshold_name}: {thresholds[threshold_name]}")

            threshold_choice = input(
                f"Enter the number or name of the threshold to modify (or 'back'): ").strip()
            if threshold_choice.lower() == "back":
                return False

            selected_threshold = self.get_selected_threshold(available_thresholds, threshold_choice)
            if not selected_threshold:
                continue

            if self.modify_threshold(simulator, selected_type, selected_threshold):
                return True

    def get_selected_threshold(self, available_thresholds, threshold_choice):
        try:
            choice_index = int(threshold_choice) - 1
            if 0 <= choice_index < len(available_thresholds):
                return available_thresholds[choice_index]
        except ValueError:
            matched_threshold = next(
                (tname for tname in available_thresholds if tname.lower() == threshold_choice.lower()), None)
            if matched_threshold:
                return matched_threshold
        print("Invalid threshold name.")
        return None

    def modify_threshold(self, simulator, selected_type, selected_threshold):
        threshold_value = simulator.config[selected_type]["thresholds"][selected_threshold]

        if isinstance(threshold_value, dict):
            # Range-based threshold (min/max)
            min_val = threshold_value.get("min")
            max_val = threshold_value.get("max")
            if min_val is not None:
                new_min = input(f"Enter new minimum value for {selected_threshold} (current: {min_val}, or 'keep'): ").strip()
                if new_min.lower() != "keep":
                    try:
                        simulator.config[selected_type]["thresholds"][selected_threshold]["min"] = float(new_min)
                    except ValueError:
                        print("Invalid input. Please enter a number or 'keep'.")
            if max_val is not None:
                new_max = input(f"Enter new maximum value for {selected_threshold} (current: {max_val}, or 'keep'): ").strip()
                if new_max.lower() != "keep":
                    try:
                        simulator.config[selected_type]["thresholds"][selected_threshold]["max"] = float(new_max)
                    except ValueError:
                        print("Invalid input. Please enter a number or 'keep'.")
        elif isinstance(threshold_value, list):
            # List-based threshold (allowed values)
            print(f"Current allowed values: {threshold_value}")
            new_values_str = input(
                "Enter new allowed values, comma-separated (or 'keep'): ").strip()
            if new_values_str.lower() != "keep":
                new_values = [v.strip() for v in new_values_str.split(',')]
                simulator.config[selected_type]["thresholds"][selected_threshold] = new_values
        else:
            # Single value threshold
            new_threshold = input(f"Enter new value for {selected_threshold} (current: {threshold_value}): ").strip()
            try:
                simulator.config[selected_type]["thresholds"][selected_threshold] = type(threshold_value)(new_threshold)
            except ValueError:
                print(f"Invalid input for this threshold type. Please enter a value of type {type(threshold_value).__name__}.")
                return False
        print(f"Threshold '{selected_threshold}' for '{selected_type}' updated.")
        return True

    def manage_other_settings(self, simulator, selected_type):
        print(f"\nSettings for {selected_type}:")
        available_settings = list(simulator.config[selected_type].keys())
        while True:
            for j, setting_key in enumerate(available_settings):
                print(str(j + 1) + ". " + setting_key + ": " + str(simulator.config[selected_type][setting_key]))

            setting_choice = input(f"Enter the number or name of the setting to modify (or 'back'): ").strip()
            if setting_choice.lower() == "back":
                return False

            selected_setting = self.get_selected_setting(available_settings, setting_choice)
            if not selected_setting:
                continue

            if self.modify_setting(simulator, selected_type, selected_setting):
                return True

    def get_selected_setting(self, available_settings, setting_choice):
        try:
            setting_index = int(setting_choice) - 1
            if 0 <= setting_index < len(available_settings):
                return available_settings[setting_index]
        except ValueError:
            matched_setting = next(
                (skey for skey in available_settings if skey.lower() == setting_choice.lower()), None)
            if matched_setting:
                return matched_setting
        print("Invalid setting name.")
        return None

    def modify_setting(self, simulator, selected_type, selected_setting):
        current_value = simulator.config[selected_type][selected_setting]
        new_value = input(
            f"Enter the new value for '{selected_setting}' (currently: '{current_value}'): ").strip()

        if not new_value:
            print("Value cannot be empty. No change made.")
            return False

        original_type = type(current_value)
        try:
            if original_type == bool:
                new_value = new_value.lower() in ['true', '1', 't', 'y', 'yes']
            elif original_type == int:
                new_value = int(new_value)
            elif original_type == float:
                new_value = float(new_value)
        except ValueError:
            print(
                f"Could not convert '{new_value}' to the expected type ({original_type.__name__}). Setting as string.")
            new_value = str(new_value)  # Fallback to string

        simulator.config[selected_type][selected_setting] = new_value
        print(f"Setting '{selected_setting}' for '{selected_type}' updated to '{new_value}'.")
        return True

    def save_configuration_changes(self, simulator):
        save_conf = input("Configuration changed. Save to config.json? (y/n): ").strip().lower()
        if save_conf == 'y':
            simulator.save_config()

def get_valid_event_types():
     """Returns a list of valid event types based on simulator methods."""
     # Dynamically find methods starting with 'get_' and ending with '_details'
     # Or keep a static list for simplicity:
     return [
         "SIEM_Alert", "Login_Alert", "Smart_Fence_Alert",
         "Location_Based_Alert", "Motion_Sensor_Alert", "IR_Sensor_Alert"
     ]

def manage_sensor_types(simulator):
    """Manages sensor types: add, remove, list, get details."""
    while True:
        print("\n--- Manage Sensor Types ---")
        print("1. Add Sensor Type")
        print("2. Remove Sensor Type")
        print("3. Get Sensor Type Details")
        print("4. List Sensor Types")
        print("5. Back to Main Menu")
        choice = input("Enter your choice: ").strip()

        try:
            if choice == '1':  # Add Sensor Type
                name = input("Enter the name of the new sensor type: ").strip()
                fields_str = input("Enter the data fields (comma-separated): ").strip()
                fields = [f.strip() for f in fields_str.split(',')]
                simulator.add_sensor_type(name, fields)
            elif choice == '2':  # Remove Sensor Type
                name = input("Enter the name of the sensor type to remove: ").strip()
                simulator.remove_sensor_type(name)
            elif choice == '3':  # Get Sensor Type Details
                name = input("Enter the name of the sensor type: ").strip()
                details = simulator.get_sensor_type(name)
                print("Sensor Details:", details)
            elif choice == '4':  # List Sensor Types
                sensor_types = simulator.list_sensor_types()
                print("Available Sensor Types:", sensor_types)
            elif choice == '5':
                break  # Back to Main Menu
            else:
                print("Invalid choice.")
        except ValueError as e:
            print(f"Error: {e}")
def main():
    """Main function to run the event simulator console interface."""
    # Ask for API URL at the start
    crc_api_url_input = input("Enter the CRC API base URL (e.g., http://localhost:8080, leave empty to print only): ").strip()
    simulator = CRCSimulator(crc_api_base_url=crc_api_url_input or None)

    valid_event_types = get_valid_event_types()

    while True:
        print("---" + " CRC Event Simulator ---")
        print("Options:")
        # Dynamically generate options for simulating events
        for i, event_type in enumerate(valid_event_types):
            print(f"{i+1}. Simulate {event_type}")

        print("-" * 20)
        print(f"{len(valid_event_types)+1}. Manage Sensor Types")
        print(f"{len(valid_event_types)+2}. Run Automation")
        print(f"{len(valid_event_types)+3}. Change Configuration Defaults")
        print(f"{len(valid_event_types)+1}. Run Automation")
        print(f"{len(valid_event_types)+2}. Change Configuration Defaults")
        print(f"{len(valid_event_types)+3}. Change CRC API URL")
        print(f"{len(valid_event_types)+4}. Exit")
        print("-" * 20)
#
        choice = input("Enter your choice: ").strip()

        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(valid_event_types):
                selected_event_type = valid_event_types[choice_num-1]
                manual_input = input(f"Simulate '{selected_event_type}' - Enter details manually? (y/n) [default: n]: ").lower().strip() == 'y'
                simulator.simulate_event(selected_event_type, manual_input)
            elif choice_num == len(valid_event_types) + 1:
                run_automation(simulator)
            elif choice_num == len(valid_event_types) + 2:
                 change_config(simulator)
            elif choice_num == len(valid_event_types) + 3:  # Manage Sensor Types
                change_crc_api_url(simulator)
            elif choice_num == len(valid_event_types) + 4:
                manage_sensor_types(simulator)
            elif choice_num == len(valid_event_types) + 5:
                print("Exiting simulator.")
                return  # End the program
            else:
                print("Invalid choice number.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}") # Catch other potential errors

if __name__ == "__main__":
    main()
