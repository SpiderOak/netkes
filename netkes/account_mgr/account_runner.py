"""
account_runner.py
(c) 2011 SpiderOak, Inc

Runs account manipulation options against the local DB and the Billing API.

The functions here are meant to be quasi-transactional; if there's an error raised through the
billing API handling functions, we will write out what we can to the DB to keep state consistent.
"""
import inspect
import time
import logging

import account_mgr


class BailApiCall(Exception):
    pass

def created_and_failed_users(created_users, users):
    return created_users, [user for user in users if user not in created_users]

class AccountRunner(object):
    """
    Manages running account manipulation operations between our local DB and
    the SpiderOak BillingAPI.
    """
    _ADD_USERS_STATEMENT = '''
    INSERT INTO users
    (uniqueid, email, avatar_id, givenname, surname, group_id) VALUES
    (%(uniqueid)s,%(email)s,%(avatar_id)s,%(firstname)s,%(lastname)s,%(group_id)s);
    '''
    def __init__(self, config, db_conn):
        self._log = logging.getLogger("AccountRunner")
        self._promo_code = config.get("promo_code", None)
        self._db_conn = db_conn
        self._api = account_mgr.get_api(config)
        self._config = config

    def runall(self, changes_dict):
        """
        Commits all changes presented in the changes_dict.

        Keys in changes_dict must conform to the rest of the public APIs for this class.

        :param changes_dict: Dictionary of user changes.
        """
        for action in changes_dict.keys():
            fun = getattr(self, action)
            ok_users, fail_users = fun(changes_dict[action])
            if len(fail_users):
                msg = "Got error during runall, aborted on action: %s" % (action,)
                print msg
                self._log.error(msg)
                break

    def create(self, users):
        """
        Creates users SpiderOak users and updates the local DB with the user list.

        :param users: List of users to create
        :returns tuple(list, list): (created users, failed users).
        """
        groups = self._api.list_groups()
        def find_group(group_id):
            for group in groups:
                if group['group_id'] == group_id:
                    return group

        created_users = []
        for user in users:
            tmp_user = dict(
                name=user['firstname'] + ' ' + user['lastname'],
                email=user['email'],
                group_id=user['group_id'],
                plan_id=find_group(user['group_id'])['plan_id'],
            )
            if 'username' in user:
                tmp_user['username'] = user['username']

            try:
                try:
                    result = self._api.create_user(tmp_user)
                except self._api.DuplicateEmail:
                    if self._config.get('resolve_sync_conflicts'):
                        self._api.edit_user(user['email'], dict(enabled=True))
                        result = dict(user=self._api.get_user(user['email']))
                        self._log.info(
                            ("Resolved sync conflict using email. "
                             "User %s's account has been enabled.") % user['email'])
                    else:
                        msg = ('Unable to create %s. '
                               'A user with this email already exists') % tmp_user
                        self._log.error(msg)
                        continue
            except self._api.Error, e:
                msg = 'Unable to create %s. %s' % (tmp_user, e)
                self._log.error(msg)
                break
            user['avatar_id'] = result['user']['avatar_id']
            cur = self._db_conn.cursor()
            cur.execute(self._ADD_USERS_STATEMENT, user)
            created_users.append(user)

        return created_and_failed_users(created_users, users)


    def enable(self, users):
        """
        Toggles the enabled status of users in the SpiderOak DB.

        :param users: List of users to enable.
        :returns tuple(list, list): (created users, failed users).
        """
        created_users = []
        for user in users:
            try:
                result = self._api.edit_user(user['email'], dict(enabled=True))
            except self._api.Error:
                break
            cur = self._db_conn.cursor()
            cur.execute("UPDATE users SET enabled=true WHERE avatar_id=%(avatar_id)s", user)
            created_users.append(user)

        return created_and_failed_users(created_users, users)

    def disable(self, users):
        """Disables users in SpiderOak's user DB.

        :param users: list of users to disable
        :returns tuple(list, list): (success users, failed users)
        """
        created_users = []
        for user in users:
            try:
                result = self._api.edit_user(user['email'], dict(enabled=False))
            except self._api.Error:
                break
            cur = self._db_conn.cursor()
            cur.execute("UPDATE users SET enabled=false WHERE avatar_id=%(avatar_id)s", user)
            created_users.append(user)

        return created_and_failed_users(created_users, users)

    def group(self, users):
        """Assigns users to plans in the SO user DB.

        :param users: list of users to set the plan for.
        :returns tuple(list, list): (success users, failed users)
        """
        created_users = []
        for user in users:
            try:
                result = self._api.edit_user(user['email'], dict(group_id=user['group_id']))
            except self._api.Error:
                break
            cur = self._db_conn.cursor()
            cur.execute("UPDATE users SET group_id=%(group_id)s WHERE avatar_id=%(avatar_id)s", user)
            created_users.append(user)

        return created_and_failed_users(created_users, users)

    def email(self, users):
        """Changes user email addresses.

        :param users: list of users to set email addresses for.
        :returns tuple(list, list): (success users, failed users)
        """
        created_users = []
        for user in users:
            try:
                result = self._api.edit_user(user['orig_email'], dict(email=user['email']))
            except self._api.Error:
                break
            cur = self._db_conn.cursor()
            cur.execute("UPDATE users SET email=%(email)s WHERE avatar_id=%(avatar_id)s", user)
            created_users.append(user)

        return created_and_failed_users(created_users, users)

