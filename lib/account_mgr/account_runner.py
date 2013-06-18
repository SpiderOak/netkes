"""
account_runner.py
(c) 2011 SpiderOak, Inc

Runs account manipulation options against the local DB and the Billing API.

The functions here are meant to be quasi-transactional; if there's an error raised through the
billing API handling functions, we will write out what we can to the DB to keep state consistent.
"""
import inspect

import logging

import api_interface


class BailApiCall(Exception):
    pass

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
                self._log.error("Got error during runall, aborted on action: %s" % (action,))
                break

    def create(self, users):
        """
        Creates users SpiderOak users and updates the local DB with the user list.

        :param users: List of users to create
        :returns tuple(list, list): (created users, failed users).
        """

        try:
            created_users = self._api_create_users(users)
        except BailApiCall as e:
            (created_users, ) = e.args

        cur = self._db_conn.cursor()
        cur.executemany(self._ADD_USERS_STATEMENT, created_users)

        return (
            created_users,
            [user for user in users if user not in created_users],
        )


    def enable(self, users):
        """
        Toggles the enabled status of users in the SpiderOak DB.

        :param users: List of users to enable.
        :returns tuple(list, list): (created users, failed users).
        """
        return self._run_generic(api_interface.activate_user, users,
                                 "UPDATE users SET enabled=true WHERE avatar_id=%(avatar_id)s")

    def disable(self, users):
        """Disables users in SpiderOak's user DB.

        :param users: list of users to disable
        :returns tuple(list, list): (success users, failed users)
        """

        return self._run_generic(api_interface.deactivate_user, users,
                                 "UPDATE users SET enabled=false WHERE avatar_id=%(avatar_id)s")

    def group(self, users):
        """Assigns users to plans in the SO user DB.

        :param users: list of users to set the plan for.
        :returns tuple(list, list): (success users, failed users)
        """

        return self._run_generic(api_interface.set_user_group, users,
                                 "UPDATE users SET group_id=%(group_id)s WHERE avatar_id=%(avatar_id)s")

    def email(self, users):
        """Changes user email addresses.

        :param users: list of users to set email addresses for.
        :returns tuple(list, list): (success users, failed users)
        """

        return self._run_generic(api_interface.change_email, users,
                                 "UPDATE users SET email=%(email)s WHERE avatar_id=%(avatar_id)s")
    
    def _run_generic(self, fun, users, sql_statement):
        """Internal function to run generic actions with both the API and DB."""
        try:
            complete_users = self._api_run_generic(fun, users)
        except BailApiCall as e:
            (complete_users, ) = e.args

        cur = self._db_conn.cursor()
        cur.executemany(sql_statement, complete_users)

        return (
            complete_users,
            [user for user in users if user not in complete_users],
        )

    def _api_create_users(self, users):
        """Internal function to create users via the billing API."""
        results = list()
        for user in users:
            try:
                result = api_interface.create_user(user, self._promo_code)
            except api_interface.ApiActionFailedError as e:
                import traceback
                traceback.print_exc()
                self._log.error('Got ApiActionFailedError: %s' % e)
                raise BailApiCall(results)
            else:
                user['avatar_id'] = result['avatar_id']
                results.append(user)

            self._log.info("created user %s" % (user['email'],))

        return results

    def _api_run_generic(self, fun, users):
        """Internal function to run API calls given the specific API function."""

        results = []
        # Start building the arguments dictionary.
        argdict = {}
        args = inspect.getargspec(fun)
        if 'promo_code' in args.args:
            argdict['promo_code'] = self._promo_code

        # In the event of getting an API exception, we still need to
        # update the DB with what we've done to keep things consistent, so
        # we catch the error and bail with the current state of the
        # results array.
        for user in users:
            argdict['user'] = user
            try:
                result = fun(**argdict)
            except api_interface.ApiActionFailedError as e:
                import traceback
                traceback.print_exc()
                self._log.error('Function %s got ApiActionFailedError: %s' % (fun, e,))
                raise BailApiCall(results)
            else:
                results.append(user)

        return results
