#!/usr/bin/python

'''
purge_old_users.py

Mass purges old users based on various criteria.

(c) 2014 SpiderOak, Inc.
'''
import datetime
import logging
import sys
from optparse import OptionParser, OptionGroup

from account_mgr.accounts_api import Api
from common import read_config_file, merge_config, set_config, validate_config, NetKesConfigError


class StartupException(Exception):
    pass

def _initialize_logging(verbose=False):
    handler = logging.StreamHandler()

    formatter = logging.Formatter(
        '%(asctime)s %(levelname)-8s %(name)-20s: %(message)s')
    handler.setFormatter(formatter)
    logging.root.addHandler(handler)
    if verbose:
        logging.root.setLevel(logging.DEBUG)
    else:
        logging.root.setLevel(logging.INFO)

def parse_cmdline():
    parser = OptionParser()

    config_group = OptionGroup(parser, "General Configuration Options",
                               "These control the configuration of the overall SpiderOak Blue system.")
    config_group.add_option("--config", dest="config_file", default=None, type="string",
                      help="The location of the JSON configuration file.",
                      metavar="FILE")
    config_group.add_option("--api-root", dest="api_root", type="string",
                      help="API Root for SpiderOak.",
                      metavar="API_ROOT")
    config_group.add_option("--api-user", dest="api_user", type="string",
                            help="API user for SpiderOak Blue",
                            metavar="USERNAME")
    config_group.add_option("--api-pass", dest="api_password", type="string",
                            help="Password to authenticate to the SpiderOak Blue API",
                            metavar="PASSWORD")
    config_group.add_option("--verbose", dest="verbose",
                            help="Additional debugging output",
                            action="store_true", default=False)
                               
    tool_group = OptionGroup(parser, "Tool configuration options",
                             "These specifically control the behavior of this tool.")
    tool_group.add_option("--older-than", dest="older_than", default=90, type="int",
                      help="Purge disabled accounts that have not been logged in for DAYS. "
                          "Defaults to 90 days.",
                      metavar="DAYS")
    tool_group.add_option("--purge-used-accounts", dest="only_empty", default=True, action="store_false",
                          help="Include accounts with backed-up data in the purge list.  "
                               "Default is to only purge accounts without backed up data.")
    tool_group.add_option("--dry-run", dest="dry_run", action="store_true", default=False,
                            help="Only display actions to be taken- do not actually perform purging.")
    tool_group.add_option("-y", dest="auto_confirm", action="store_true", default=False,
                            help="Do not ask for confirmation before removing users.")

    parser.add_option_group(config_group)
    parser.add_option_group(tool_group)

    options, _ = parser.parse_args()

    # Prune it up a bit and return it as a dict.
    optdict = vars(options)
    for key in list(optdict.keys()):
        if optdict[key] is None:
            del optdict[key]

    return optdict


def process_config():
    cmdline_opts = parse_cmdline()

    config = read_config_file(cmdline_opts.get('config_file', None))
    config = merge_config(config, cmdline_opts)

    try:
        validate_config(config)
    except NetKesConfigError as e:
        raise e

    return config


def filter_users(only_empty, desired_age_days, users):
    '''
    Performs user filtering based on the arguments passed to the program.
    '''
    log = logging.getLogger('filter_users')

    users_to_purge = []
    now = datetime.datetime.now()

    for user in users:
        # First, check if the user has stored any data and therefore if we want it.
        if user['bytes_stored'] > 0 and only_empty:
            log.debug('User %s has data stored, NOT INCLUDING in purge set.', user['email'])
            continue
        elif user['bytes_stored'] > 0:
            log.debug('User %s has data stored, INCLUDING in purge set.', user['email'])
        else:
            log.debug('User %s does not have data stored, INCLUDING in purge set.', user['email'])

        # Now let's do DATEMATH! We only want users with last_login of a given vintage or earlier.
        # If there's no 'last login', let's check the creation time instead so we don't cull
        # accounts that have just been created.
        if user['last_login'] is None:
            user_timestamp = datetime.datetime.fromtimestamp(user['creation_time'])
            log.debug('User %s using creation timestamp %s',
                      user['email'], user_timestamp.strftime("%Y-%m-%d %H:%M:%S"))
        else:
            user_timestamp = datetime.datetime.fromtimestamp(user['last_login'])
            log.debug('User %s has last_login of %s',
                      user['email'], user_timestamp.strftime("%Y-%m-%d %H:%M:%S"))

        desired_age = datetime.timedelta(days=desired_age_days)
        user_age = now - user_timestamp

        if user_age > desired_age:
            log.info('User %s is old enough, including (%d days old)', 
                     user['email'], user_age.days)
            users_to_purge.append(user)
        else:
            log.debug('User %s is NOT old enough, NOT including (%d days old)',
                      user['email'], user_age.days)

    return users_to_purge

    
def collect_users(api):
    '''
    Collects all the disabled users for the Blue account.
    '''
    log = logging.getLogger('collect_users')

    users = api.list_users()
    log.debug("Collected %d users total", len(users))

    disabled_users = [user for user in users if not user['enabled']]
    log.info("Found %d disabled users", len(disabled_users))
    
    return disabled_users

def run_purge(api, userlist, dryrun=True):
    '''
    Run the purge against the users. Only prints what it would do
    if dryrun is selected.
    '''
    if dryrun:
        log = logging.getLogger('run_purge DRYRUN')
    else:
        log = logging.getLogger('run_purge')

    for user in userlist:
        log.info('Purging user %s', user['email'])

        if not dryrun:
            api.delete_user(user['email'])

def main():
    config = process_config()

    _initialize_logging(config['verbose'])
    api = Api.create(
        config['api_root'],
        config['api_user'],
        config['api_password'],
        )

    candidate_to_purge_users = collect_users(api)
    users_to_purge = filter_users(config['only_empty'], config['older_than'],
                                  candidate_to_purge_users)
    run_purge(api, users_to_purge, config['dry_run'])

    return 0

if __name__ == "__main__":
    sys.exit(main())
