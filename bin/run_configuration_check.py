#!/usr/bin/env python

"""
run_configuration_check.py

Validates configuration for SpiderOak Blue configuration.

See https://github.com/SpiderOak/netkes/issues/21

(c) 2013 SpiderOak, Inc.
"""

import logging
import sys

from common import DATA_DIR, read_config_file, merge_config, set_config, configtest



class StartupException(Exception):
    pass

def _initialize_logging():
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        '%(levelname)-8s %(name)-20s: %(message)s')
    handler.setFormatter(formatter)
    logging.root.addHandler(handler)
    logging.root.setLevel(logging.DEBUG)


def process_config():
    config = read_config_file(None)
    
    if 'groups' not in config:
        raise StartupException("Lacking an LDAP mapping group in the config file.  Check your docs!")

    log = logging.getLogger('process_config')
    log.debug('%s' % config['api_root'])
    return config


def run_tests(config):
    # Begin by making sure our configuration contains all the fields we need.
    try:
        configtest.check_configuration(config)
    except configtest.ConfigError:
        return

def main():
    _initialize_logging()
    config = process_config
    run_tests(config)

    return 0

if __name__ == "__main__":
    sys.exit(main())
