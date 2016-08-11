import json
import urllib
import urllib2
import types
import logging

from api_client import ApiClient


class Error(Exception):
    pass


class LogErrorMeta(type):
    '''Decorate all functions so that they log all Errors.'''
    def __new__(cls, name, bases, attrs):
        for attr_name, attr_value in attrs.iteritems():
            if isinstance(attr_value, types.FunctionType):
                attrs[attr_name] = cls.log_exceptions(attr_value)

        return super(LogErrorMeta, cls).__new__(cls, name, bases, attrs)

    @classmethod
    def log_exceptions(cls, func):
        '''Log the name and arguments of any function that raises an Error.
        Then raise the exception.
        '''
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Error:
                log = logging.getLogger('accounts_api')
                log.exception('%s - %s - %s' % (func.__name__, args, kwargs))
                raise
        wrapper.__name__ = func.__name__
        return wrapper


class Api(object):
    __metaclass__ = LogErrorMeta

    class BadParams(Error):
        pass
    class PaymentRequired(Error):  # NOQA
        pass
    class NotFound(Error):  # NOQA
        pass
    class DuplicateGroupName(Error):  # NOQA
        pass
    class DuplicateUsername(Error):  # NOQA
        pass
    class DuplicateEmail(Error):  # NOQA
        pass
    class BadPlan(Error):  # NOQA
        pass
    class BadGroup(Error):  # NOQA
        pass
    class QuotaExceeded(Error):  # NOQA
        pass
    class EmailNotSent(Error):  # NOQA
        pass

    @classmethod
    def create(cls, base, username, password):
        """Factory method using default ApiClient class."""
        client = ApiClient(base, username, password)
        return cls(client)

    def __init__(self, client):
        self.Error = Error
        self.client = client

    def ping(self):
        return self.client.get_json('ping')

    # Plans

    def list_plans(self):
        return self.client.get_json('plans')

    # Quota

    def quota(self):
        return self.client.get_json('partner/quota')

    # Info

    def info(self):
        return self.client.get_json('partner/info')

    # Features

    def enterprise_features(self):
        return self.client.get_json('partner/features')

    # Backup

    def backup(self):
        return self.client.get_json('partner/backup')

    def update_backup(self, backup):
        return self.client.post_json('partner/backup', backup)

    # Settings

    def enterprise_settings(self):
        return self.client.get_json('partner/settings')

    def update_enterprise_settings(self, settings):
        try:
            return self.client.post_json('partner/settings', settings)
        except urllib2.HTTPError, err:
            if err.code == 400:
                raise self.BadParams()
            raise

    def update_enterprise_password(self, new_password):
        try:
            return self.client.post_json('partner/password', new_password)
        except urllib2.HTTPError, err:
            if err.code == 400:
                raise self.BadParams()
            raise

    # Preferences and policy

    def get_device_preferences(self):
        return self.client.get_json('devicepreferences')

    def list_policies(self):
        return self.client.get_json('devicepolicies/')

    def create_policy(self, policy_info):
        try:
            return self.client.post_json('devicepolicies/', policy_info)
        except urllib2.HTTPError, err:
            if err.code == 400:
                raise self.BadParams()
            raise

    def get_policy(self, policy_id):
        try:
            return self.client.get_json('devicepolicies/%d' % (policy_id,))
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    def edit_policy(self, policy_id, policy_info):
        try:
            self.client.post_json('devicepolicies/%d' % (policy_id,), policy_info)
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            elif err.code == 400:
                raise self.BadParams()
            raise

    def delete_policy(self, policy_id):
        try:
            self.client.delete('devicepolicies/%d' % (policy_id,))
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    # Groups

    def list_groups(self):
        return self.client.get_json('groups/')

    def search_groups(self, name):
        return self.client.get_json('groups/?search=%s' % urllib.quote(name))

    def create_group(self, group_info):
        try:
            resp = self.client.post_json_raw_response(
                'groups/', group_info)
        except urllib2.HTTPError, err:
            if err.code == 400:
                raise self.BadParams()
            elif err.code == 409:
                data = json.loads(err.read())
                if 'name' in data['conflicts']:
                    raise self.DuplicateGroupName()
                elif 'plan_id' in data['conflicts']:
                    raise self.BadPlan()
            raise
        return int(resp.info()['location'].rsplit('/', 1)[-1])

    def get_group(self, group_id):
        try:
            return self.client.get_json('groups/%d' % (group_id,))
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    def edit_group(self, group_id, group_info):
        try:
            self.client.post_json('groups/%d' % (group_id,), group_info)
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            elif err.code == 400:
                raise self.BadParams()
            elif err.code == 409:
                data = json.loads(err.read())
                if 'name' in data['conflicts']:
                    raise self.DuplicateGroupName()
                elif 'plan_id' in data['conflicts']:
                    raise self.BadPlan()
                elif 'avatars_over_quota' in data['conflicts']:
                    raise self.QuotaExceeded()
            raise

    def delete_group(self, group_id, new_group_id=None):
        try:
            if new_group_id:
                self.client.delete('groups/%d?move_to=%d' % (group_id, new_group_id))
            else:
                self.client.delete('groups/%d' % (group_id,))
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    # Shares

    def _create_query_string(self, **kw):
        get_params = dict()
        for key, value in kw.items():
            if value:
                get_params[key] = value
        query_string = ''
        if get_params:
            query_string = '?%s' % urllib.urlencode(get_params)
        return query_string

    def list_shares_for_brand(self, limit=None, offset=None):
        query_string = self._create_query_string(limit=limit, offset=offset)
        return self.client.get_json('shares/%s' % query_string)

    # Users

    def list_users_paged(self, user_limit=1000, search_by=None, order_by=None):
        all_users = []
        user_count = self.get_user_count()
        for page in range((user_count / user_limit) + 1):
            user_offset = user_limit * page
            if user_offset < user_count:
                users = self.list_users(user_limit, user_offset,
                                        search_by, order_by)
                all_users = all_users + users
                if len(users) < user_limit:
                    break
        return all_users

    def list_users(self, limit=None, offset=None, search_by=None, order_by=None):
        # If the query is not limited it may time out for large user lists
        # so we automatically page the user list.
        if limit is None and offset is None:
            return self.list_users_paged(search_by=search_by, order_by=order_by)

        query_string = self._create_query_string(
            limit=limit, offset=offset, search_by=search_by, order_by=order_by)
        return self.client.get_json('users/%s' % query_string)

    def search_users(self, name_or_email=None, limit=None, offset=None, group_id=None):
        query_string = self._create_query_string(limit=limit,
                                                 offset=offset,
                                                 search=name_or_email,
                                                 group_id=group_id)
        return self.client.get_json('users/%s' % query_string)

    def get_user_count(self):
        return self.client.get_json('users/?action=user_count')['user_count']

    def create_user(self, user_info):
        try:
            return self.client.post_json('users/', user_info)
        except urllib2.HTTPError, err:
            if err.code == 400:
                raise self.BadParams()
            if err.code == 402:
                raise self.PaymentRequired()
            elif err.code == 409:
                data = json.loads(err.read())
                if 'username' in data['conflicts']:
                    raise self.DuplicateUsername()
                if 'email' in data['conflicts']:
                    raise self.DuplicateEmail()
                elif 'plan_id' in data['conflicts']:
                    raise self.BadPlan()
                elif 'group_id' in data['conflicts']:
                    raise self.BadGroup()
            raise

    def get_user(self, username_or_email):
        try:
            return self.client.get_json(
                'users/%s' % (username_or_email,))
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    def list_devices(self, username_or_email):
        try:
            return self.client.get_json(
                'users/%s/devices' % (username_or_email,))
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    def list_client_revisions(self, min_revision=0, max_revision=-1,
                              max_days_since_login=-1):
        '''
        min_revision: 0 is the lowest possible revision
        max_revision: revisions will always be positive so use -1 to indicate
            no maximum.
        max_days_since_login: Only return results for devices that have logged
            in within a certain number of days. -1 indicates that results should
            be returned for all devices.
        '''
        data = (min_revision, max_revision, max_days_since_login,)
        url = 'clientrevisions/?min_revision=%s&max_revision=%s&max_days_since_login=%s'
        return self.client.get_json(url % data)

    def list_shares(self, username_or_email):
        try:
            return self.client.get_json(
                'users/%s/shares/' % (username_or_email,))
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    def get_share(self, username_or_email, room_key):
        try:
            return self.client.get_json(
                'users/%s/shares/%s' % (username_or_email, room_key))
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    def edit_share(self, username_or_email, room_key, enable):
        action = 'enable' if enable else 'disable'
        try:
            return self.client.post_json(
                'users/%s/shares/%s?action=%s' % (username_or_email, room_key, action), {})
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    def edit_user(self, username_or_email, user_info):
        try:
            self.client.post_json(
                'users/%s' % (username_or_email,), user_info)
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            elif err.code == 400:
                raise self.BadParams()
            elif err.code == 402:
                raise self.QuotaExceeded()
            elif err.code == 409:
                data = json.loads(err.read())
                if 'email' in data['conflicts']:
                    raise self.DuplicateEmail()
                elif 'group_id' in data['conflicts']:
                    raise self.BadGroup()
                elif 'plan_id' in data['conflicts']:
                    raise self.BadPlan()
            raise

    def delete_user(self, username_or_email):
        try:
            self.client.delete('users/%s' % (username_or_email,))
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    def send_activation_email(self, username_or_email, data={}):
        try:
            self.client.post_json('users/%s?action=sendactivationemail' % (
                username_or_email,), data)
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            elif err.code == 409:
                raise self.EmailNotSent()
            raise
