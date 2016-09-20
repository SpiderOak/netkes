import json
import unittest
from mock import patch, sentinel, Mock

from account_mgr import accounts_api


class FakeHttpError(accounts_api.urllib2.HTTPError):
    def __init__(self, code, body=''):
        self.code = code
        self.body = body

    def read(self):
        return self.body


class TestAccountsApi(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.api = accounts_api.Api(self.client)

    @patch.object(accounts_api, 'ApiClient')
    def test_create(self, ApiClient):
        api = accounts_api.Api.create(
            sentinel.base, sentinel.username, sentinel.password)
        self.assertIs(api.client, ApiClient.return_value)
        ApiClient.assert_called_once_with(
            sentinel.base, sentinel.username, sentinel.password)

    def test_ping(self):
        self.assertIs(
            self.api.ping(),
            self.client.get_json.return_value
        )
        self.client.get_json.assert_called_once_with('ping')

    # Plans

    def test_list_plans(self):
        self.assertIs(
            self.api.list_plans(),
            self.client.get_json.return_value
        )
        self.client.get_json.assert_called_once_with('plans')

    # Quota

    def test_quota(self):
        self.assertIs(
            self.api.quota(),
            self.client.get_json.return_value
        )
        self.client.get_json.assert_called_once_with('partner/quota')

    # Features

    def test_enterprise_features(self):
        self.assertIs(
            self.api.enterprise_features(),
            self.client.get_json.return_value
        )
        self.client.get_json.assert_called_once_with('partner/features')

    # Settings

    def test_enterprise_settings(self):
        self.assertIs(
            self.api.enterprise_settings(),
            self.client.get_json.return_value
        )
        self.client.get_json.assert_called_once_with('partner/settings')

    def test_update_enterprise_settings(self):
        self.assertIs(
            self.api.update_enterprise_settings(sentinel.settings),
            self.client.post_json.return_value
        )
        self.client.post_json.assert_called_once_with(
            'partner/settings', sentinel.settings)

    def test_update_enterprise_settings_bad_params(self):
        self.client.post_json.side_effect = FakeHttpError(400)
        with self.assertRaises(self.api.BadParams):
            self.api.update_enterprise_settings(sentinel.settings)

    # Groups

    def test_list_groups(self):
        self.assertIs(
            self.api.list_groups(),
            self.client.get_json.return_value
        )
        self.client.get_json.assert_called_once_with('groups/')

    def test_create_group(self):
        response = self.client.post_json_raw_response.return_value
        response.info.return_value = {'location': 'groups/42'}
        self.assertEqual(self.api.create_group(sentinel.info), 42)
        self.client.post_json_raw_response.assert_called_once_with(
            'groups/', sentinel.info)

    def test_create_group_bad_params(self):
        self.client.post_json_raw_response.side_effect = \
            FakeHttpError(400)
        with self.assertRaises(self.api.BadParams):
            self.api.create_group(sentinel.info)

    def test_create_group_duplicate_name(self):
        response = FakeHttpError(409, json.dumps({
            'reason': 'The following fields conflict '
                      'with an existing record',
            'conflicts': ['name']
        }))
        self.client.post_json_raw_response.side_effect = response
        with self.assertRaises(self.api.DuplicateGroupName):
            self.api.create_group(sentinel.info)

    def test_create_group_invalid_plan(self):
        response = FakeHttpError(409, json.dumps({
            'reason': 'Invalid values for the following fields',
            'conflicts': ['plan_id']
        }))
        self.client.post_json_raw_response.side_effect = response
        with self.assertRaises(self.api.BadPlan):
            self.api.create_group(sentinel.info)

    def test_get_group(self):
        self.assertIs(
            self.api.get_group(42),
            self.client.get_json.return_value
        )
        self.client.get_json.assert_called_once_with('groups/42')

    def test_get_group_not_found(self):
        self.client.get_json.side_effect = FakeHttpError(404)
        with self.assertRaises(self.api.NotFound):
            self.api.get_group(42)

    def test_edit_group(self):
        self.api.edit_group(42, sentinel.info)
        self.client.post_json.assert_called_once_with(
            'groups/42', sentinel.info)

    def test_edit_group_bad_params(self):
        self.client.post_json.side_effect = FakeHttpError(400)
        with self.assertRaises(self.api.BadParams):
            self.api.edit_group(42, sentinel.info)

    def test_edit_group_not_found(self):
        self.client.post_json.side_effect = FakeHttpError(404)
        with self.assertRaises(self.api.NotFound):
            self.api.edit_group(42, sentinel.info)

    def test_edit_group_duplicate_name(self):
        response = FakeHttpError(409, json.dumps({
            'reason': 'The following fields conflict '
                      'with an existing record',
            'conflicts': ['name']
        }))
        self.client.post_json.side_effect = response
        with self.assertRaises(self.api.DuplicateGroupName):
            self.api.edit_group(42, sentinel.info)

    def test_edit_group_invalid_plan(self):
        response = FakeHttpError(409, json.dumps({
            'reason': 'Invalid values for the following fields',
            'conflicts': ['plan_id']
        }))
        self.client.post_json.side_effect = response
        with self.assertRaises(self.api.BadPlan):
            self.api.edit_group(42, sentinel.info)

    def test_edit_group_quota_exceeded(self):
        data = json.dumps({'conflicts': 'avatars_over_quota'})
        self.client.post_json.side_effect = FakeHttpError(409, data)
        with self.assertRaises(self.api.QuotaExceeded):
            self.api.edit_group(42, sentinel.info)

    def test_delete_group(self):
        self.api.delete_group(42)
        self.client.delete.assert_called_once_with('groups/42')

    def test_delete_group_not_found(self):
        self.client.delete.side_effect = FakeHttpError(404)
        with self.assertRaises(self.api.NotFound):
            self.api.delete_group(42)

    # Users

    def test_list_users(self):
        self.assertIs(
            self.api.list_users(limit=1),
            self.client.get_json.return_value
        )
        self.client.get_json.assert_called_once_with('users/?limit=1')

    def test_create_user(self):
        self.api.create_user(sentinel.info)
        self.client.post_json.assert_called_once_with(
            'users/', sentinel.info)

    def test_create_user_bad_params(self):
        self.client.post_json.side_effect = FakeHttpError(400)
        with self.assertRaises(self.api.BadParams):
            self.api.create_user(sentinel.info)

    def test_create_user_duplicate_username(self):
        response = FakeHttpError(409, json.dumps({
            'reason': 'The following fields conflict '
                      'with an existing record',
            'conflicts': ['username']
        }))
        self.client.post_json.side_effect = response
        with self.assertRaises(self.api.DuplicateUsername):
            self.api.create_user(sentinel.info)

    def test_create_user_duplicate_email(self):
        response = FakeHttpError(409, json.dumps({
            'reason': 'The following fields conflict '
                      'with an existing record',
            'conflicts': ['email']
        }))
        self.client.post_json.side_effect = response
        with self.assertRaises(self.api.DuplicateEmail):
            self.api.create_user(sentinel.info)

    def test_create_user_invalid_group(self):
        response = FakeHttpError(409, json.dumps({
            'reason': 'Invalid values for the following fields',
            'conflicts': ['group_id']
        }))
        self.client.post_json.side_effect = response
        with self.assertRaises(self.api.BadGroup):
            self.api.create_user(sentinel.info)

    def test_create_user_invalid_plan(self):
        response = FakeHttpError(409, json.dumps({
            'reason': 'Invalid values for the following fields',
            'conflicts': ['plan_id']
        }))
        self.client.post_json.side_effect = response
        with self.assertRaises(self.api.BadPlan):
            self.api.create_user(sentinel.info)

    def test_get_user(self):
        self.assertIs(
            self.api.get_user('username'),
            self.client.get_json.return_value
        )
        self.client.get_json.assert_called_once_with('users/username')

    def test_get_user_not_found(self):
        self.client.get_json.side_effect = FakeHttpError(404)
        with self.assertRaises(self.api.NotFound):
            self.api.get_user('username')

    def test_list_devices(self):
        self.assertIs(
            self.api.list_devices('username'),
            self.client.get_json.return_value
        )
        self.client.get_json.assert_called_once_with(
            'users/username/devices')

    def test_list_devices_user_not_found(self):
        self.client.get_json.side_effect = FakeHttpError(404)
        with self.assertRaises(self.api.NotFound):
            self.api.list_devices('username')

    def test_edit_user(self):
        self.api.edit_user('username', sentinel.info)
        self.client.post_json.assert_called_once_with(
            'users/username', sentinel.info)

    def test_edit_user_bad_params(self):
        self.client.post_json.side_effect = FakeHttpError(400)
        with self.assertRaises(self.api.BadParams):
            self.api.edit_user('username', sentinel.info)

    def test_edit_user_not_found(self):
        self.client.post_json.side_effect = FakeHttpError(404)
        with self.assertRaises(self.api.NotFound):
            self.api.edit_user('username', sentinel.info)

    def test_edit_user_duplicate_email(self):
        response = FakeHttpError(409, json.dumps({
            'reason': 'The following fields conflict '
                      'with an existing record',
            'conflicts': ['email']
        }))
        self.client.post_json.side_effect = response
        with self.assertRaises(self.api.DuplicateEmail):
            self.api.edit_user('username', sentinel.info)

    def test_edit_user_invalid_group(self):
        response = FakeHttpError(409, json.dumps({
            'reason': 'Invalid values for the following fields',
            'conflicts': ['group_id']
        }))
        self.client.post_json.side_effect = response
        with self.assertRaises(self.api.BadGroup):
            self.api.edit_user('username', sentinel.info)

    def test_edit_user_invalid_plan(self):
        response = FakeHttpError(409, json.dumps({
            'reason': 'Invalid values for the following fields',
            'conflicts': ['plan_id']
        }))
        self.client.post_json.side_effect = response
        with self.assertRaises(self.api.BadPlan):
            self.api.edit_user('username', sentinel.info)

    def test_edit_user_quota_exceeded(self):
        self.client.post_json.side_effect = FakeHttpError(402)
        with self.assertRaises(self.api.QuotaExceeded):
            self.api.edit_user('username', sentinel.info)

    def test_delete_user(self):
        self.api.delete_user('username')
        self.client.delete.assert_called_once_with('users/username')

    def test_delete_user_not_found(self):
        self.client.delete.side_effect = FakeHttpError(404)
        with self.assertRaises(self.api.NotFound):
            self.api.delete_user('username')

    def test_send_activation_email(self):
        self.api.send_activation_email('username')
        self.client.post_json.assert_called_once_with(
            'users/username?action=sendactivationemail', {}
        )

    def test_send_activation_email_not_found(self):
        self.client.post_json.side_effect = FakeHttpError(404)
        with self.assertRaises(self.api.NotFound):
            self.api.send_activation_email('username')

    def test_send_activation_email_not_sent(self):
        self.client.post_json.side_effect = FakeHttpError(409)
        with self.assertRaises(self.api.EmailNotSent):
            self.api.send_activation_email('username')


if __name__ == '__main__':
    unittest.main()
