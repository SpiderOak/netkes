#!/usr/bin/env python

'''
directory_agent_main.py

Directory Agent main program.

(c) 2011 SpiderOak, Inc.
'''
import time
import os
import fcntl
import errno
import signal
import logging
import requests
from optparse import OptionParser, OptionGroup
import psycopg2
import sys

from common import (
    DATA_DIR, read_config_file, merge_config, set_config,
    validate_config, NetKesConfigError
)
from account_mgr.user_source import group_manager

TIMEOUT = int(os.environ.get('DIRECTORY_AGENT_TIMEOUT', 60 * 20))


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
                            "These commands should only be used to repair a broken instance, "
                            "and should never be used normally.  Refer to documentation!")
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

    try:
        validate_config(config)
    except NetKesConfigError, e:
        raise e

    if 'groups' not in config:
        raise StartupException("Lacking an LDAP mapping group in the config file. "
                               "Check your docs!")

    log = logging.getLogger('process_config')
    log.debug('%s' % config['api_root'])
    return config


class SimpleFlock(object):
    """Provides the simplest possible interface to flock-based file locking.
    Intended for use with the `with` syntax. It will create/truncate/delete the
    lock file as necessary.
    """

    def __init__(self, path, timeout=None):
        self._path = path
        self._timeout = timeout
        self._fd = None

    def __enter__(self):
        self._fd = os.open(self._path, os.O_CREAT)
        start_lock_search = time.time()
        while True:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                # Lock acquired!
                return
            except (OSError, IOError) as ex:
                if ex.errno != errno.EAGAIN:  # Resource temporarily unavailable
                    raise
                elif (self._timeout is not None and
                      time.time() > (start_lock_search + self._timeout)):
                    # Exceeded the user-specified timeout.
                    raise

        # TODO It would be nice to avoid an arbitrary sleep here, but spinning
        # without a delay is also undesirable.
        time.sleep(0.1)

    def __exit__(self, *args):
        fcntl.flock(self._fd, fcntl.LOCK_UN)
        os.close(self._fd)
        self._fd = None

        # Try to remove the lock file, but don't try too hard because it is
        # unnecessary. This is mostly to help the user see whether a lock
        # exists by examining the filesystem.
        try:
            os.unlink(self._path)
        except:
            pass


class TimeoutError(Exception):
    pass


class Timeout(object):
    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        signal.alarm(0)


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

    except (StartupException, NetKesConfigError,) as e:
        log.error(str(e))
        return str(e)

    if not config['dir_uri']:
        return '''LDAP not configured. Exiting'''

    set_config(config)
    with SimpleFlock("%s/lock" % (DATA_DIR,), 5):
        db_conn = psycopg2.connect(database=config['db_db'],
                                   user=config['db_user'],
                                   password=config['db_pass'],
                                   host=config['db_host'])

        try:
            with Timeout(TIMEOUT):
                if config['rebuild_database']:
                    log.info("DB repair requested, beginning rebuild")
                    group_manager.run_db_repair(config, db_conn)
                    log.info("DB repair complete")

                log.info("LDAP -> SpiderOak sync starting")
                group_manager.run_group_management(config, db_conn)
        except requests.exceptions.Timeout:
            log.error("Network request timed out")
            return 1
        except TimeoutError:
            log.error("Directory agent exceeded maximum runtime of %s seconds" % TIMEOUT)
            return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
