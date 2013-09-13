import unittest
from mock import Mock, MagicMock, sentinel, patch
import copy
import ldap

from account_mgr.user_source import ldap_source

class TestCollectGroups(unittest.TestCase):
    def setUp(self):
        self.single_test_group = [{'type':"dn",
                             'ldap_id': "cn=test1,dn=testdomain,dn=com",
                             'group_id': sentinel.group_id1},
                           ]
        self.multiple_test_groups = [{'type':"dn",
                             'ldap_id': "cn=test1,dn=testdomain,dn=com",
                             'group_id': sentinel.group_id1},
                            {'type':"dn",
                             'ldap_id': "cn=test2,dn=testdomain,dn=com",
                             'group_id': sentinel.group_id2},
                            {'type':"dn",
                             'ldap_id': "cn=test3,dn=testdomain,dn=com",
                             'group_id': sentinel.group_id3},
                            ]

    @patch('account_mgr.user_source.ldap_source.LdapGroup.get_group')
    def test_returns_empty_groups(self, get_group):
        conn = Mock()

        test_group = MagicMock()
        test_group.__iter__.return_value = []

        get_group.return_value = test_group
#        ldap_source.LdapGroup.get_group.return_value = test_group

        config = {'groups': self.multiple_test_groups,
                  'dir_guid_source': 'user_guid_source',
                  'dir_username_source': 'user_source',
                  'dir_fname_source': 'fname_source',
                  'dir_lname_source': 'lname_source',}
        self.assertEqual(len(ldap_source.collect_groups(conn, config)),
                         0)

    @patch('account_mgr.user_source.ldap_source.LdapGroup.get_group')
    def test_calls_appropriate_args(self, get_group):
        conn = Mock()

        test_group = MagicMock()
        test_group.__iter__.return_value = []

        get_group.return_value = test_group

        config = {'groups': self.single_test_group,
                  'dir_guid_source': 'user_guid_source',
                  'dir_username_source': 'user_source',
                  'dir_fname_source': 'fname_source',
                  'dir_lname_source': 'lname_source',}
        _ = ldap_source.collect_groups(conn, config)
        ldap_source.LdapGroup.get_group.assert_called_with(
            conn, config, 
            self.single_test_group[0]['ldap_id'],
            self.single_test_group[0]['group_id'])


    @patch('account_mgr.user_source.ldap_source.LdapGroup.get_group')
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

        returned_groups = [MagicMock(), MagicMock(), MagicMock()]
        for group in returned_groups:
            group.__iter__.return_value = returns.pop(0)

        def side_effect(*args):
            result = returned_groups.pop(0)
            return result

        config = {'groups': self.multiple_test_groups,
                  'dir_guid_source': 'user_guid_source',
                  'dir_username_source': 'user_source',
                  'dir_fname_source': 'fname_source',
                  'dir_lname_source': 'lname_source',}

        get_group.side_effect = side_effect

        self.assertEqual(ldap_source.collect_groups(conn, config),
                         expected)

class TestLdapGroup(unittest.TestCase):
    def test_ldap_get_group_gets_ou_for_ou_types(self):
        conn = MagicMock()

        for object_class in ldap_source.LdapGroup._ou_object_classes:
            conn.conn.search_s.return_value = [ [ None, {'objectClass': object_class},]]

            group = ldap_source.LdapGroup.get_group(
                conn,
                sentinel.config,
                sentinel.ldap_id,
                sentinel.group_id)

            self.assertIsInstance(group, ldap_source.LdapOuGroup)
            self.assertIs(group.ldap_conn, conn)
            self.assertIs(group.config, sentinel.config)
            self.assertIs(group.ldap_id, sentinel.ldap_id)
            self.assertIs(group.group_id, sentinel.group_id)

    def test_ldap_get_group_gets_group(self):
        conn = MagicMock()
        conn.conn.search_s.return_value = [ [ None, {'objectClass': 'group'},]]

        group = ldap_source.LdapGroup.get_group(
            conn,
            sentinel.config,
            sentinel.ldap_id,
            sentinel.group_id)

        self.assertIsInstance(group, ldap_source.LdapGroupGroup)
        self.assertIs(group.ldap_conn, conn)
        self.assertIs(group.config, sentinel.config)
        self.assertIs(group.ldap_id, sentinel.ldap_id)
        self.assertIs(group.group_id, sentinel.group_id)

    def test_no_userlist_method(self):
        group = ldap_source.LdapGroup(
            Mock(), Mock(), Mock(), Mock()
        )
        with self.assertRaises(AttributeError):
            # pylint will complain that we are using a method that doesn't exist.
            # This blowing up is the point of the test, so we suppress the error.
            group.userlist() #pylint: disable=E1101

class TestLdapOuGroup(unittest.TestCase):
    @patch('account_mgr.user_source.ldap_source._PagedAsyncSearch')
    def test_returns_empty_group(self, _PagedAsyncSearch):
        _PagedAsyncSearch.return_value = []
        
        test_group = {'type':"dn",
                      'ldap_id': "cn=test,dn=testdomain,dn=com",
                      'group_id': sentinel.group_id}
        group = ldap_source.LdapOuGroup(
            MagicMock(), MagicMock(), test_group['ldap_id'], test_group['group_id']
        )
        self.assertEqual(len(group.userlist()), 0)

    @patch('account_mgr.user_source.ldap_source._PagedAsyncSearch')
    def test_returns_group_users(self, _PagedAsyncSearch):
        config = {
            'dir_guid_source': 'user_guid_source',
            'dir_username_source': 'user_source',
            'dir_fname_source': 'fname_source',
            'dir_lname_source': 'lname_source',
            'dir_member_source': 'member_source'
            }

        PAS_results = [
            (Mock(), 
             {config['dir_guid_source']    : [sentinel.guid1],
              config['dir_username_source']: [sentinel.testuser1],
              config['dir_fname_source']   : [sentinel.testfname1],
              config['dir_lname_source']   : [sentinel.testlname1],} ),
            (Mock(), 
             {config['dir_guid_source']    : [sentinel.guid2],
              config['dir_username_source']: [sentinel.testuser2],
              config['dir_fname_source']   : [sentinel.testfname2],
              config['dir_lname_source']   : [sentinel.testlname2],} ),
        ]

        _PagedAsyncSearch.return_value = PAS_results
        
        lconn = MagicMock()


        test_group = {'type':"dn",
                      'ldap_id': "cn=test,dn=testdomain,dn=com",
                      'group_id': sentinel.group_id}

        group = ldap_source.LdapOuGroup(
            lconn, config, Mock(), sentinel.group_id)

        self.assertEqual(group.userlist(),
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
        
class TestLdapGroupGroup(unittest.TestCase):
    @patch('account_mgr.user_source.ldap_source._PagedAsyncSearch')
    def test_returns_empty_group(self, _PagedAsyncSearch):
        _PagedAsyncSearch.return_value = []

        test_group = {'type':"dn",
                      'ldap_id': "cn=test,dn=testdomain,dn=com",
                      'group_id': sentinel.group_id}
        group = ldap_source.LdapGroupGroup(
            MagicMock(), MagicMock(), test_group['ldap_id'], test_group['group_id']
        )
        self.assertEqual(len(group.userlist()), 0)
                                                                        
    @patch('account_mgr.user_source.ldap_source._PagedAsyncSearch')
    def test_returns_nonranged_group_users(self, _PagedAsyncSearch):
        config = {
            'dir_guid_source': 'user_guid_source',
            'dir_username_source': 'user_source',
            'dir_fname_source': 'fname_source',
            'dir_lname_source': 'lname_source',
            'dir_member_source': 'member_source'
            }

        # Represents looking up the dir_member_source list from LDAP.
        PAS_results = [(Mock(), { config['dir_member_source']: [sentinel.testuser1, sentinel.testuser2,] })]

        _PagedAsyncSearch.return_value = PAS_results

        # A list of individual users searched from the LDAP.
        individual_lookup_results = [
            [(Mock(), 
             {config['dir_guid_source']    : [sentinel.guid1],
              config['dir_username_source']: [sentinel.testuser1],
              config['dir_fname_source']   : [sentinel.testfname1],
              config['dir_lname_source']   : [sentinel.testlname1],} )],
            [(Mock(), 
             {config['dir_guid_source']    : [sentinel.guid2],
              config['dir_username_source']: [sentinel.testuser2],
              config['dir_fname_source']   : [sentinel.testfname2],
              config['dir_lname_source']   : [sentinel.testlname2],} )],
        ]

        
        lconn = MagicMock()

        def search_side_effect(*args, **kwargs):
            user = individual_lookup_results.pop(0)
            return user

        lconn.conn.search_s.side_effect = search_side_effect


        test_group = {'type':"dn",
                      'ldap_id': "cn=test,dn=testdomain,dn=com",
                      'group_id': sentinel.group_id}

        group = ldap_source.LdapGroupGroup(
            lconn, config, Mock(), sentinel.group_id)

        self.assertEqual(group.userlist(),
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

    @patch('account_mgr.user_source.ldap_source._PagedAsyncSearch')
    def test_returns_ranged_group_users(self, _PagedAsyncSearch):
        config = {
            'dir_guid_source': 'user_guid_source',
            'dir_username_source': 'user_source',
            'dir_fname_source': 'fname_source',
            'dir_lname_source': 'lname_source',
            'dir_member_source': 'member_source'
            }

        # Represents looking up the dir_member_source list from LDAP.
        PAS_results = [
            [(Mock(),
              {
                config['dir_member_source']: [],
                "%s;range=0-1" % (config['dir_member_source'],): [sentinel.testuser1, sentinel.testuser2,] 
              })],
            [(Mock(), {
                config['dir_member_source']: [],
                "%s;range=2-3" % (config['dir_member_source'],): [sentinel.testuser3, sentinel.testuser4,] })],
            [],
        ]

        def PAS_side_effects(*args, **kwargs):
            return PAS_results.pop(0)

        _PagedAsyncSearch.side_effect = PAS_side_effects

        # A list of individual users searched from the LDAP.
        individual_lookup_results = [
            [(Mock(), 
             {config['dir_guid_source']    : [sentinel.guid1],
              config['dir_username_source']: [sentinel.testuser1],
              config['dir_fname_source']   : [sentinel.testfname1],
              config['dir_lname_source']   : [sentinel.testlname1],} )],
            [(Mock(), 
             {config['dir_guid_source']    : [sentinel.guid2],
              config['dir_username_source']: [sentinel.testuser2],
              config['dir_fname_source']   : [sentinel.testfname2],
              config['dir_lname_source']   : [sentinel.testlname2],} )],
            [(Mock(), 
             {config['dir_guid_source']    : [sentinel.guid3],
              config['dir_username_source']: [sentinel.testuser3],
              config['dir_fname_source']   : [sentinel.testfname3],
              config['dir_lname_source']   : [sentinel.testlname3],} )],
            [(Mock(), 
             {config['dir_guid_source']    : [sentinel.guid4],
              config['dir_username_source']: [sentinel.testuser4],
              config['dir_fname_source']   : [sentinel.testfname4],
              config['dir_lname_source']   : [sentinel.testlname4],} )],
        ]

        
        lconn = MagicMock()

        def search_side_effect(*args, **kwargs):
            user = individual_lookup_results.pop(0)
            return user

        lconn.conn.search_s.side_effect = search_side_effect


        test_group = {'type':"dn",
                      'ldap_id': "cn=test,dn=testdomain,dn=com",
                      'group_id': sentinel.group_id}

        group = ldap_source.LdapGroupGroup(
            lconn, config, Mock(), sentinel.group_id)

        self.assertEqual(group.userlist(),
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
                           },
                          {'email'     : sentinel.testuser3,
                           'firstname' : sentinel.testfname3,
                           'lastname'  : sentinel.testlname3,
                           'uniqueid'  : sentinel.guid3,
                           'group_id'  : sentinel.group_id,
                           },
                          {'email'     : sentinel.testuser4,
                           'firstname' : sentinel.testfname4,
                           'lastname'  : sentinel.testlname4,
                           'uniqueid'  : sentinel.guid4,
                           'group_id'  : sentinel.group_id,
                           },
                          ])

if __name__ == '__main__':
    unittest.main()
