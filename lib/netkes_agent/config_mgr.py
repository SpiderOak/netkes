"""
config_mgr.py

Provides an API to control the virtual machine's NetKES and directory agent configuration.
"""

import json
import os
import os.path
import subprocess

_SERVICE_NAME = 'openmanage'

class ConfigManager(object):
    """
    Provides an easy interface to get and set openmanage configuration
    
    Assumes you have r/w access to the configuration file, and ability to restart
    the openmanage service.
    """
    def __init__(self, filename):
        """
        Constructor. Give it a filename, and it will pull configuration from that file.

        @see default_config for a great place to start looking for the configuration file.
        """
        self._config_file = filename

        with open(self._config_file) as cf:
            self.config = json.load(cf)

    def new_cfg(self, new_filename, want_file_read=False):
        """
        Changes the config file we point at.

        If it exists, we can optionally read it
        """
        self._config_file = new_filename

        if want_file_read:
            with open(self._config_file) as cf:
                self.config = json.load(cf)

    def apply_config(self):
        """
        Saves the current configuration to the configuration file, and restarts services
        to apply the new configuration.
        """
        with open(self._config_file, 'w') as cf:
            json.dump(self.config, cf)

        self._kick_services()

    def _kick_services(self):
        command = "sv restart " + _SERVICE_NAME
        subprocess.call(command, shell=True)


def default_config():
    """
    Provides a sane place where the configuration file is normally kept.
    """
    conf_dir = os.environ.get('OPENMANAGE_CONFIGDIR', None)
    if conf_dir is None:
        return None

    return os.path.join(conf_dir, 'agent_config.json')
