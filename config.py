# config.py
import json
import os

# Define the path to the configuration file relative to this file's location.
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.json')

def load_config():
    """
    Loads the configuration from the config.json file.
    Returns:
        A dictionary with the configuration settings.
    """
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        raise Exception(f"Configuration file not found at {CONFIG_FILE}")
    except json.JSONDecodeError as e:
        raise Exception(f"Error parsing the configuration file: {e}")

# Load configuration at module import for global access.
CONFIG = load_config()

if __name__ == "__main__":
    # For testing purposes, print out the configuration.
    print("Current Configuration:")
    print(json.dumps(CONFIG, indent=4))
