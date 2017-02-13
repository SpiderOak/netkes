from django.conf.urls import patterns
from django.views.generic import RedirectView

from views import views
from views import groups
from views import users
from views import managementvm
from views import settings
from views import billing
from views import policies

urlpatterns = patterns('',
    (r'^$', users.users, {}, 'index'),  # NOQA
    (r'^saved/$', users.users, {'saved': True}, 'index_saved'),
    (r'^clearcache/$', views.clear_cache, {}, 'clear_cache'),
    (r'^login/$', views.login_user, {}, 'login'),
    (r'^logout/$', views.logout, {}, 'logout'),
    (r'^escrowlogin/(?P<escrow_username>.+)/$', managementvm.escrow_login, {}, 'escrow_login'),
    (r'^users/$', users.users, {}, 'users'),
    (r'^users/saved/$', users.users, {'saved': True}, 'users_saved'),
    (r'^users/saved/(?P<page>\d+)/$', users.users, {'saved': True}, 'users_saved'),
    (r'^users/csv/download/$', views.users_csv_download, {}, 'users_csv_download'),
    (r'^users/csv/$', views.users_csv, {}, 'users_csv'),
    (r'^users/(?P<email>.+)/saved/$', users.user_detail,
     {'saved': True}, 'user_detail_saved'),
    (r'^users/(?P<email>.+)/$', users.user_detail, {}, 'user_detail'),
    (r'^groups/$', groups.groups, {}, 'groups'),
    (r'^groups/saved/$', groups.groups, {'saved': True}, 'groups_saved'),
    (r'^groups/(?P<group_id>\d+)/$', groups.group_detail, {}, 'group_detail'),
    (r'^groups/(?P<group_id>\d+)/saved/$', groups.group_detail,
     {'saved': True}, 'group_detail_saved'),
    (r'^shares/$', views.shares, {}, 'shares'),
    (r'^shares/saved/$', views.shares, {'saved': True}, 'shares_saved'),
    (r'^shares/(?P<email>.+)/(?P<room_key>.+)/$', views.share_detail, {}, 'share_detail'),
    (r'^reports/$', views.reports, {}, 'reports'),
    (r'^manage/$', views.manage, {}, 'manage'),
    (r'^manage/fingerprint/$', views.fingerprint, {}, 'fingerprint'),
    (r'^settings/$', settings.settings, {}, 'settings'),
    (r'^settings/saved/$', settings.settings, {'saved': True}, 'settings_saved'),
    (r'^settings/password/$', settings.password, {}, 'password'),
    (r'^settings/password/saved/$', settings.password, {'saved': True}, 'password_saved'),
    (r'^logs/$', managementvm.logs, {}, 'logs'),
    (r'^logs/download/$', views.download_logs, {}, 'download_logs'),
    (r'^validate/$', views.validate, {}, 'validate'),
    (r'^favicon\.ico$', RedirectView.as_view(url='/static/blue_mgnt/img/favicon.png')),
    (r'^codes/$', managementvm.auth_codes, {}, 'auth_codes'),
    (r'^codes/saved/$', managementvm.auth_codes, {'saved': True}, 'auth_codes_saved'),
    (r'^billing/$', billing.billing, {}, 'billing'),
    (r'^billing/update_cc/$', billing.billing_update_cc, {}, 'billing_update_cc'),
    (r'^billing/check_coupon$', billing.check_coupon, {}, 'billing_check_coupon'),
    (r'^billing/create_subscription$', billing.create_subscription,
     {}, 'billing_create_subscription'),
    (r'^policies/$', policies.policy_list, {}, 'policy_list'),
    (r'^policies/(?P<policy_id>\d+)/$', policies.policy_detail, {}, 'policy_detail'),
    (r'^policies/create/$', policies.policy_create, {}, 'policy_create'),
    (r'^policies/(?P<policy_id>\d+)/delete/$',
     policies.policy_delete, {'delete': True}, 'policy_delete'),
    (r'^policies/(?P<policy_id>\d+)/delete/confirm/$',
     policies.policy_delete, {'delete': False}, 'policy_delete_confirm'),
)
