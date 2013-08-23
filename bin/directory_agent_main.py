#!/usr/bin/env python

'''
directory_agent_main.py

Directory Agent main program.

(c) 2011 SpiderOak, Inc.
'''
import fcntl
import json
import logging
from optparse import OptionParser, OptionGroup
import os
import psycopg2
import sys

from common import DATA_DIR, read_config_file, merge_config, set_config
from account_mgr.user_source import group_manager

class StartupException(Exception):
    pass

def _initialize_logging():
    handler = logging.FileHandler(os.path.join(
        os.environ['OPENMANAGE_LOGS'],
        'directory_agent',
        'directory_agent'))

    formatter = logging.Formatter(
        '%(asctime)s %(levelname)-8s %(name)-20s: %(message)s')
    handler.setFormatter(formatter)
    logging.root.addHandler(handler)
    logging.root.setLevel(logging.DEBUG)

def parse_cmdline():
    parser = OptionParser()

    parser.add_option("--config", dest="config_file", default=None,
                      help="The location of the JSON configuration file.",
                      metavar="FILE")
    parser.add_option("--dir-uri", dest="dir_uri", 
                      help="The LDAP URI to the directory.",
                      metavar="URI")
    parser.add_option("--dir-base-dn", dest="dir_base_dn", 
                      help="The LDAP base DN to use for searches.",
                      metavar="DN")
    parser.add_option("--dir-user", dest="dir_user", 
                      help="The user to bind to LDAP as.",
                      metavar="USER")
    parser.add_option("--api-root", dest="api_root", 
                      help="API Root for SpiderOak.",
                      metavar="API_ROOT")
    parser.add_option("--api-code", dest="promo_code",
                      help="Promo code for SpiderOak plans.",
                      metavar="API_CODE")

    dangerous = OptionGroup(parser, "Dangerous Repair Commands",
                            "These commands should only be used to repair a broken instance, and should never be used normally.  Refer to documentation!")
    dangerous.add_option("--rebuild-db", dest="rebuild_database", default=False,
                      action="store_true",
                      help="Rebuild the local user DB.")
    parser.add_option_group(dangerous)
    options, _ = parser.parse_args()

    # Prune it up a bit and return it as a dict.
    optdict = vars(options)
    for key in optdict.keys():
        if optdict[key] is None:
            del optdict[key]

    return optdict

def process_config():
    cmdline_opts = parse_cmdline()

    config = read_config_file(cmdline_opts.get('config_file', None))
    config = merge_config(config, cmdline_opts)
    
    if 'groups' not in config:
        raise StartupException("Lacking an LDAP mapping group in the config file.  Check your docs!")

    log = logging.getLogger('process_config')
    log.debug('%s' % config['api_root'])
    return config

def get_lock():
    lockfile = open(os.path.join("%s/lock" % (DATA_DIR,)), 'w')
    fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return lockfile

def release_lock(lockfile):
    if lockfile is not None:
        fcntl.flock(lockfile, fcntl.LOCK_UN)
        lockfile.close()

    
def main():
    _initialize_logging()
    # Read our configuration, and process errors from it.
    log = logging.getLogger('main')
    try:
        config = process_config()
    except (IOError, ValueError,):
        log.error("Broken / missing agent_config,json file. Aborting!")
        return '''Cannot find, open, or understand your config file.  Lacking options 
otherwise, it should be at:

/home/openmanage/openmanage/conf/agent_config.json

Run %s -h for help.''' % (sys.argv[0],)
    except StartupException as e:
        log.error(str(e))
        return str(e)

    set_config(config)
    lockfile = get_lock()
    # Moving along, open the database
    db_conn = psycopg2.connect(database=config['db_db'],
                               user=config['db_user'],
                               password=config['db_pass'],
                               host=config['db_host'])

    if config['rebuild_database']:
        log.info("DB repair requested, beginning rebuild")
        group_manager.run_db_repair(config, db_conn)
        log.info("DB repair complete")

        
    log.info("LDAP -> SpiderOak sync starting")
    group_manager.run_group_management(config, db_conn)
    
    release_lock(lockfile)
    return 0

if __name__ == "__main__":
    sys.exit(main())
