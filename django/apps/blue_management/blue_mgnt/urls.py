from django.conf.urls import *
from django.conf import settings as django_settings

from views.views import *
from views.users import *
from views.policy import *
from views.managementvm import *

urlpatterns = patterns('',
    (r'^$', index, {}, 'index'),
    (r'^saved/$', index, {'saved': True}, 'index_saved'),
    (r'^login/$', login_user, {}, 'login'),
    (r'^logout/$', logout, {}, 'logout'),
    (r'^users/$', users, {}, 'users'),
    (r'^users/saved/$', users, {'saved': True}, 'users_saved'),
    (r'^users/saved/(?P<page>\d+)/$', users, {'saved': True}, 'users_saved'),
    (r'^users/csv/download/$', users_csv_download, {}, 'users_csv_download'),
    (r'^users/csv/$', users_csv, {}, 'users_csv'),
    (r'^users/(?P<email>.+)/saved/$', user_detail, {'saved': True}, 'user_detail_saved'),
    (r'^users/(?P<email>.+)/$', user_detail, {}, 'user_detail'),
    (r'^groups/$', groups, {}, 'groups'),
    (r'^groups/saved/$', groups, {'saved': True}, 'groups_saved'),
    (r'^policy/$', policy, {}, 'policy'),
    (r'^policy/saved/$', policy, {'saved': True}, 'policy_saved'),
    (r'^policy/detail/(?P<name>.+)/saved/$', policy_detail, {'saved': True}, 'policy_detail_saved'),
    (r'^policy/detail/(?P<name>.+)/$', policy_detail, {}, 'policy_detail'),
    (r'^shares/$', shares, {}, 'shares'),
    (r'^shares/$', shares, {}, 'shares'),
    (r'^shares/saved/$', shares, {'saved': True}, 'shares_saved'),
    (r'^settings/$', settings, {}, 'settings'),
    (r'^settings/saved/$', settings, {'saved': True}, 'settings_saved'),
    (r'^settings/password/$', password, {}, 'password'),
    (r'^settings/password/saved/$', password, {'saved': True}, 'password_saved'),
    (r'^features/$', features, {}, 'features'),
    (r'^features/saved/$', features, {'saved': True}, 'features_saved'),
    (r'^admingroups/$', admin_groups, {}, 'admin_groups'),
    (r'^admingroups/saved/$', admin_groups, {'saved': True}, 'admin_groups_saved'),
    (r'^logs/$', logs, {}, 'logs'),
    (r'^logs/download/$', download_logs, {}, 'download_logs'),
    (r'^validate/$', validate, {}, 'validate'),
)

# We don't want to serve some pages *AT ALL* if we're not on a management VM.
# The List:
# auth codes
if getattr(django_settings, 'MANAGEMENT_VM', False):
    urlpatterns += patterns('',
        (r'^codes/$', auth_codes, {}, 'auth_codes'),
        (r'^codes/saved/$', auth_codes, {'saved': True}, 'auth_codes_saved'),
    )
