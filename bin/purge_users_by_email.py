import logging
from optparse import OptionParser, OptionGroup

from account_mgr.accounts_api import Api
from common import read_config_file, merge_config, set_config, validate_config, NetKesConfigError


def _initialize_logging(verbose=False):
    handler = logging.StreamHandler()

    formatter = logging.Formatter(
        '%(asctime)s %(levelname)-8s %(name)-20s: %(message)s')
    handler.setFormatter(formatter)
    logging.root.addHandler(handler)
    logging.root.setLevel(logging.INFO)


def parse_cmdline():
    parser = OptionParser()

    config_group = OptionGroup(parser, "General Configuration Options",
                               "These control the configuration of the overall SpiderOak Blue system.")
    config_group.add_option("--config", dest="config_file",
                      help="The location of the JSON configuration file.",
                      metavar="FILE")
    config_group.add_option("--emails", dest="email_file",
                      help="The location of the file containing the emails of users to purge.",
                      metavar="FILE")
    config_group.add_option("--dry-run", dest="dry_run", action="store_true", default=False,
                            help="Only display actions to be taken - do not actually perform purging.")

    parser.add_option_group(config_group)

    options, _ = parser.parse_args()
    if not options.config_file:
        parser.error("Missing required argument --config")
    if not options.email_file:
        parser.error("Missing required argument --emails")

    # Prune it up a bit and return it as a dict.
    optdict = vars(options)
    for key in optdict.keys():
        if optdict[key] is None:
            del optdict[key]

    return optdict


def process_config():
    cmdline_opts = parse_cmdline()

    config = read_config_file(cmdline_opts.get('config_file', None))

    try:
        validate_config(config)
    except NetKesConfigError, e:
        raise e

    with open(cmdline_opts['email_file']) as f:
        emails = f.readlines()

    return config, emails, cmdline_opts['dry_run']


def main():
    config, emails, dry_run = process_config()
    _initialize_logging()
    log = logging.getLogger('purge_users_by_email')

    api = Api.create(
        config['api_root'],
        config['api_user'],
        config['api_password'],
    )

    for email in emails:
        email = email.strip()
        try:
            user = api.get_user(email)
        except Api.NotFound:
            log.error('Unable to find user: "%s"', email)
            continue
        if user['purgehold_active']:
            log.info('Skipping user "%s" because purgehold is active', email)
        else:
            if dry_run:
                log.info('Dry run - simulating purging user "%s"', email)
            else:
                try:
                    api.delete_user(email)
                    log.info('User "%s" has been purged', email)
                except:
                    log.error('Error purging user "%s"', email)


if __name__ == "__main__":
    main()