import unittest
from mock import Mock, MagicMock, sentinel, patch
import copy

import ldap

from directory_agent import ldap_reader

class TestCollectGroups(unittest.TestCase):
    def setUp(self):
        self.test_groups = [{'type':"dn",
                             'ldap_id': "cn=test1,dn=testdomain,dn=com",
                             'group_id': sentinel.group_id1},
                            {'type':"dn",
                             'ldap_id': "cn=test2,dn=testdomain,dn=com",
                             'group_id': sentinel.group_id2},
                            {'type':"dn",
                             'ldap_id': "cn=test3,dn=testdomain,dn=com",
                             'group_id': sentinel.group_id3},
                            ]

    def test_returns_empty_groups(self):
        conn = Mock()
        conn.search_s.return_value = []
        config = {'groups': self.test_groups,
                  'dir_guid_source': 'user_guid_source',
                  'dir_username_source': 'user_source',
                  'dir_fname_source': 'fname_source',
                  'dir_lname_source': 'lname_source',}
        self.assertEqual(len(ldap_reader.collect_groups((conn, Mock()), config)),
                         0)

    @patch('directory_agent.ldap_reader.get_group')
    def test_returns_populated_groups(self, get_group):
        conn = Mock()

        # The following tom-foolery with returns and side_effect is to make sure
        # we don't have to bother with setting up get_group correctly, and so
        # we assume it works correctly to mock it here.
        returns = [[sentinel.testuser1, sentinel.testuser2],
                   [sentinel.testuser3, sentinel.testuser4],
                   [sentinel.testuser5, sentinel.testuser6]]
        
        expected = [sentinel.testuser1, sentinel.testuser2,
                    sentinel.testuser3, sentinel.testuser4,
                    sentinel.testuser5, sentinel.testuser6,
                    ]

        def side_effect(*args):
            result = returns.pop(0)
            return result

        config = {'groups': self.test_groups,
                  'dir_guid_source': 'user_guid_source',
                  'dir_username_source': 'user_source',
                  'dir_fname_source': 'fname_source',
                  'dir_lname_source': 'lname_source',}

        groups = [("dn", Mock(),), ("dn", Mock(),), ("dn", Mock(),)]

        get_group.side_effect = side_effect

        self.assertEqual(ldap_reader.collect_groups(conn, config),
                         expected)

class TestCheckGetGroup(unittest.TestCase):
    def test_rejects_bad_group(self):
        conn = Mock()
        config = MagicMock()
        test_group = {'type':"DEADBEEF",
                      'ldap_id': "cn=test,dn=testdomain,dn=com",
                      'group_id': sentinel.group_id}
        with self.assertRaises(ldap_reader.InvalidGroupConfiguration):
            ldap_reader.get_group(conn, config, test_group)

    def test_uses_base_dn(self):
        conn = Mock()
        conn.search_s.return_value = []
        config = MagicMock()
        test_group = {'type':"dn",
                      'ldap_id': "cn=test,dn=testdomain,dn=com",
                      'group_id': sentinel.group_id}
        ldap_reader.get_group((conn, sentinel.base_dn,), config, test_group)
        args, _ = conn.search_s.call_args
        self.assertIs(args[0], sentinel.base_dn)

    def test_returns_empty_group(self):
        conn = Mock()
        conn.search_s.return_value = []
        test_group = {'type':"dn",
                      'ldap_id': "cn=test,dn=testdomain,dn=com",
                      'group_id': sentinel.group_id}
        self.assertEqual(
            len(ldap_reader.get_group((conn, Mock(),), MagicMock(), test_group)),
            0)

    def test_returns_group_users(self):
        conn = Mock()
        config = {
            'dir_guid_source': 'user_guid_source',
            'dir_username_source': 'user_source',
            'dir_fname_source': 'fname_source',
            'dir_lname_source': 'lname_source',
            }
        ldap_results = [(Mock(), {config['dir_guid_source']    : [sentinel.guid1],
                                  config['dir_username_source']: [sentinel.testuser1],
                                  config['dir_fname_source']   : [sentinel.testfname1],
                                  config['dir_lname_source']   : [sentinel.testlname1],
                                  }
                         ),
                        (Mock(), {config['dir_guid_source']    : [sentinel.guid2],
                                  config['dir_username_source']: [sentinel.testuser2],
                                  config['dir_fname_source']   : [sentinel.testfname2],
                                  config['dir_lname_source']   : [sentinel.testlname2],
                                  }
                         ),
                        (None, [Mock()]),
                        (None, [Mock()]),
                        ]

        test_group = {'type':"dn",
                      'ldap_id': "cn=test,dn=testdomain,dn=com",
                      'group_id': sentinel.group_id}
        
        conn.search_s.return_value = ldap_results
        self.assertEqual(ldap_reader.get_group((conn, Mock(),),
                                               config,
                                               test_group),
                         [{'email'     : sentinel.testuser1,
                           'firstname' : sentinel.testfname1,
                           'lastname'  : sentinel.testlname1,
                           'uniqueid'  : sentinel.guid1,
                           'group_id'  : sentinel.group_id,
                           },
                          {'email'     : sentinel.testuser2,
                           'firstname' : sentinel.testfname2,
                           'lastname'  : sentinel.testlname2,
                           'uniqueid'  : sentinel.guid2,
                           'group_id'  : sentinel.group_id,
                           }
                          ])


if __name__ == '__main__':
    unittest.main()
