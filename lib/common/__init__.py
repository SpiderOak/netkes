'''
__init__.py

Common settings for all of the OMVA applications.

(c) 2011 SpiderOak, Inc.
'''

import json
import logging
import os
import os.path

CONFIG_DIR = os.environ.get("OPENMANAGE_CONFIGDIR", 
                            "/opt/openmanage/etc")
DATA_DIR = os.environ.get("OPENMANAGE_DATADIR", 
                          "/var/lib/openmanage")
DEFAULT_RC = "agent_config.json"

_CONFIG = None

def set_config(config):
    global _CONFIG
    _CONFIG = config

def get_config():
    global _CONFIG
    return _CONFIG

def get_ssl_keys():
    log = logging.getLogger('get_ssl_keys')
    key_home = DATA_DIR
    key_fname = os.path.join(key_home, 'server.key')
    cert_fname = os.path.join(key_home, 'server.crt')

    print key_fname+" "+ cert_fname
    if os.path.exists(key_fname) and os.path.exists(cert_fname):
        log.info("Using SSL key/cert: %s %s"% (key_fname, cert_fname,))
        return key_fname, cert_fname

    log.warn("No SSL certs found at %s" % (DATA_DIR,))
    return None, None


def make_defaults():
    '''Provides default and sane configuration options
    
    Most users shouldn't need to change this.
    '''
    default_config = {'db_user': 'directory_agent',
                      'db_host': 'localhost',
                      'db_db': 'openmanage',
                      'api_root': 'https://spideroak.com/apis/partners/billing',
                      }

    return default_config

def read_config_file(cmdline_option=None):
    '''Reads the configuration file, optionally using an envar and/or command-line argument for the location.'''

    if cmdline_option is not None:
        config_file = cmdline_option
    else:
        config_file = os.path.join(CONFIG_DIR, DEFAULT_RC)

    # TODO: cleanup the configuration file path.
    if not os.path.exists(config_file):
        log = logging.getLogger("read_config_file")
        log.warn("Missing config file at %s" % (config_file,))
        return dict()

    with open(config_file) as json_fobj:
        fileconfig = json.load(json_fobj)

    for key in fileconfig.keys():
        if isinstance(fileconfig[key], unicode):
            fileconfig[key] = fileconfig[key].encode('utf_8')

    config = merge_config(make_defaults(), fileconfig)

    return config

def merge_config(config, cmdline_opts):
    '''Merges the command-line options with the configuration file.'''
    for key, value in cmdline_opts.iteritems():
        config[key] = value

    return config
