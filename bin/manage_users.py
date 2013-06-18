#!/usr/bin/python
"""
manage_users

Command-line interface for managing user assignments for OpenManage.

(c) 2011 SpiderOak, Inc.
"""

import getpass
import logging
from optparse import OptionParser, OptionGroup
import os
import psycopg2
import sys

from account_mgr.cmdline_utils import run_command
from common import read_config_file, merge_config, set_config

class BadConfigOpts(Exception):
    pass

def _initialize_logging():
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)-8s %(name)-20s: %(message)s')
    handler.setFormatter(formatter)
    logging.root.addHandler(handler)

    if 'SPIDEROAK_AGENT_LOG_DEBUG' in os.environ:
        logging.root.setLevel(logging.DEBUG)
    else:
        logging.root.setLevel(logging.INFO)

def parse_cmdline():
    parser = OptionParser()
    parser.add_option("--config", dest="config_file", default=None,
                      help="The location of the JSON configuration file.",
                      metavar="FILE")
    parser.add_option("--force", dest="force", action="store_true", default=False,
                      help="Force setting user configuration, even with the presence of the LDAP agent.")

    reading = OptionGroup(parser, "User Listing",
                          "Selecting either of the two following options will return a list of the users you have, and ignore all other options.")
    reading.add_option("--users-json", dest="users_json", default=False,
                       action="store_true",
                       help="Returns the list of users for the enterprise as a machine-readable JSON string.")
    reading.add_option("--users-csv", dest="users_csv", default=None, metavar="CSV FILE",
                       help="Writes the users directory into a CSV file suitable for use elsewhere.")
    parser.add_option_group(reading)

    users = OptionGroup(parser, "User(s) Selection",
                        "The following options influence how we read users to manipulate into the system.  Either CSV OR singly-specified users are to be used; using both (or none!) will result in error.")
    users.add_option("--email-addr", dest="email_addr", default=None, metavar="EMAIL ADDRESS",
                      help="Email address for the user.")
    users.add_option("--csv-file", dest="csv_file", default=None, metavar="CSV FILE",
                      help="CSV file with list of users to manipulate and their options.  Please see the documentation!")
    parser.add_option_group(users)

    operations = OptionGroup(parser, "User Manipulations",
                             "These configure what we're going to do on the user(s).")
    operations.add_option("--setpw", dest="setpw", action="store_true", 
                          default=False,
                          help="Set the password for the selected user.")
    operations.add_option("--create", dest="create", action="store_true", 
                          default=False,
                          help="Create user(s).")
    operations.add_option("--enable", dest="enable", action="store_true", 
                          default=False,
                          help="Enable user(s).")
    operations.add_option("--disable", dest="disable", action="store_true", 
                          default=False,
                          help="Disable user(s).")
    operations.add_option("--set-group", dest="set_group", action="store_true", 
                          default=False,
                          help="Assign group ID(s) to user(s).")
    operations.add_option("--set-email", dest="set_email", action="store_true", 
                          default=False,
                          help="Change email address(es) for users(s).")
    parser.add_option_group(operations)

    new_config = OptionGroup(parser, "Changes",
                             "These provided the information required for the above actions.")
    new_config.add_option("--given-name", dest="given_name", default=None, 
                          metavar="GIVEN NAME",
                          help="Given name for the user.  Required for --create")
    new_config.add_option("--surname", dest="surname", default=None, 
                          metavar="SURNAME",
                          help="Surname for the user. Required for --create")
    new_config.add_option("--new-email", dest="new_email", default=None, 
                          metavar="EMAIL",
                          help="New email address for the user.  Required for --set-email (already set via '--email-addr' in --create)")
    new_config.add_option("--group-id", dest="group_id", default=None, 
                          metavar="GROUP ID",
                          help="Group ID to set for the user. Required for --create, --set-group")
    parser.add_option_group(new_config)
    options, _ = parser.parse_args()

    optdict = vars(options)
    for key in optdict.keys():
        if optdict[key] is None:
            del optdict[key]

    return optdict


def validate_options(optdict):
    """Determines the legality of the options set by the user."""
    log = logging.getLogger("validate_options")

    if ('users_csv' in optdict) or ('users_json' in optdict):
        # We don't care about anything else if we're given these options.
        return

    # Check to see if they've configured no or both email AND CSV file.
    if ('email_addr' in optdict) != ('csv_file' in optdict):
          raise BadConfigOpts("Needs exactly ONE of either '--email-addr' OR '--csv-file'")
    # We need exactly ONE action.
    ops = ['set_email', 'set_group', 'disable', 'enable', 'create', 'setpw']
    ops_counter = 0
    for op in ops:
        if op in optdict:
            ops_counter += 1

    if ops_counter != 1:
        raise BadConfigOpts("Needs exactly ONE action option!")

    # If we're using this here command-line, we need to verify the required options are set per action.
    if 'email_addr' in optdict:
        if 'set_email' in optdict:
            if 'new_email' not in optdict:
                raise BadConfigOpts("Need to specify the new email address!")
        elif 'create' in optdict:
            if ('given_name' not in optdict) or \
                    ('surname' not in optdict) or \
                    ('group_id' not in optdict):
                raise BadConfigOpts("Need to specify the required options for the create function")
        elif 'set_group' in optdict:
            if 'group_id' not in optdict:
                raise BadConfigOpts("Need to specify the group id to set")

    # Prune out extra options from optdict if we're using the CSV method.
    if 'csv_file' in optdict:
        options = ['new_email', 'given_name', 'surname', 'group_id']
        for option in options:
            if option in optdict:
                del optdict[option]
                log.warn('Pointless option given for CSV use: %s' % option)
    

def process_config():
    cmdline_opts = parse_cmdline()
    validate_options(cmdline_opts)

    config = read_config_file(cmdline_opts.get('config_file', None))
    config = merge_config(config, cmdline_opts)

    return config

def _try_new_password():
    """Tries up to 3 times to get a new password.

    :returns string or None: New password, or None if it can't be typed in reliably."""
    log = logging.getLogger('try_new_password')

    for i in range(1,4):
        password1 = getpass.getpass("New SpiderOak password: ")
        password2 = getpass.getpass("New SpiderOak password (again): ")

        if password1 == password2:
            return password1
        else:
            log.warn("Passwords do not match! Attempt %d of 3." % i)

    return None

def main():
    _initialize_logging()
    log = logging.getLogger("main")
    config = process_config()
    set_config(config)

    db_conn = psycopg2.connect(database=config['db_db'],
                               user=config['db_user'],
                               password=config['db_pass'],
                               host=config['db_host'])

    # Try and catch using this tool alongside the LDAP user_source.
    try:
        import account_mgr.user_source.ldap_source
    except ImportError:
        # This is fine; if we can't import LDAP, that's the expected behavior.
        pass
    else:
        log.warn("LDAP module available, this may produce inconsistent state.")
        if 'force' not in config:
            log.error("--force option not provided, aborting.")
            return 1

    # Make sure we grab the password if that's required!
    if config['setpw'] and 'csvfile' not in config:
        print "grabbing password"
        config['password'] = _try_new_password()
        if config['password'] is None:
            log.error("Failed setting password, aborting.")
            return 1

    results = run_command(db_conn, config)
    if results is None:
        print results

    return 0

if __name__ == "__main__":
    sys.exit(main())
