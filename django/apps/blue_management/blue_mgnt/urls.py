from django.conf.urls import url
from django.views.generic import RedirectView

from views import (
    views, groups, users, managementvm, settings, billing,
    policies, invoices
)

urlpatterns = [
    url(r'^$', users.users, {}, 'index'),  # NOQA
    url(r'^saved/$', users.users, {'saved': True}, 'index_saved'),
    url(r'^clearcache/$', views.clear_cache, {}, 'clear_cache'),
    url(r'^login/$', views.login_user, {}, 'login'),
    url(r'^logout/$', views.logout, {}, 'logout'),
    url(r'^escrowlogin/(?P<escrow_username>.+)/$', managementvm.escrow_login, {}, 'escrow_login'),
    url(r'^users/$', users.users, {}, 'users'),
    url(r'^users/saved/$', users.users, {'saved': True}, 'users_saved'),
    url(r'^users/saved/(?P<page>\d+)/$', users.users, {'saved': True}, 'users_saved'),
    url(r'^users/csv/download/$', views.users_csv_download, {}, 'users_csv_download'),
    url(r'^users/csv/$', views.users_csv, {}, 'users_csv'),
    url(r'^users/(?P<email>.+)/saved/$', users.user_detail,
     {'saved': True}, 'user_detail_saved'),
    url(r'^users/(?P<email>.+)/$', users.user_detail, {}, 'user_detail'),
    url(r'^groups/$', groups.groups, {}, 'groups'),
    url(r'^groups/saved/$', groups.groups, {'saved': True}, 'groups_saved'),
    url(r'^groups/(?P<group_id>\d+)/$', groups.group_detail, {}, 'group_detail'),
    url(r'^groups/(?P<group_id>\d+)/saved/$', groups.group_detail,
     {'saved': True}, 'group_detail_saved'),
    url(r'^shares/$', views.shares, {}, 'shares'),
    url(r'^shares/saved/$', views.shares, {'saved': True}, 'shares_saved'),
    url(r'^shares/(?P<email>.+)/(?P<room_key>.+)/$', views.share_detail, {}, 'share_detail'),
    url(r'^reports/$', views.reports, {}, 'reports'),
    url(r'^manage/$', views.manage, {}, 'manage'),
    url(r'^manage/fingerprint/$', views.fingerprint, {}, 'fingerprint'),
    url(r'^settings/$', settings.settings, {}, 'settings'),
    url(r'^settings/saved/$', settings.settings, {'saved': True}, 'settings_saved'),
    url(r'^settings/password/$', settings.password, {}, 'password'),
    url(r'^settings/password/saved/$', settings.password, {'saved': True}, 'password_saved'),
    url(r'^logs/$', managementvm.logs, {}, 'logs'),
    url(r'^logs/download/$', views.download_logs, {}, 'download_logs'),
    url(r'^validate/$', views.validate, {}, 'validate'),
    url(r'^favicon\.ico$', RedirectView.as_view(url='/static/blue_mgnt/img/favicon.png')),
    url(r'^codes/$', managementvm.auth_codes, {}, 'auth_codes'),
    url(r'^codes/saved/$', managementvm.auth_codes, {'saved': True}, 'auth_codes_saved'),
    url(r'^billing/$', billing.billing, {}, 'billing'),
    url(r'^billing/update_cc/$', billing.billing_update_cc, {}, 'billing_update_cc'),
    url(r'^billing/check_coupon$', billing.check_coupon, {}, 'billing_check_coupon'),
    url(r'^billing/create_subscription$', billing.create_subscription,
     {}, 'billing_create_subscription'),
    url(r'^policies/$', policies.policy_list, {}, 'policy_list'),
    url(r'^policies/(?P<policy_id>\d+)/$', policies.policy_detail, {}, 'policy_detail'),
    url(r'^policies/create/$', policies.policy_create, {}, 'policy_create'),
    url(r'^policies/(?P<policy_id>\d+)/delete/$',
     policies.policy_delete, {'delete': True}, 'policy_delete'),
    url(r'^policies/(?P<policy_id>\d+)/delete/confirm/$',
     policies.policy_delete, {'delete': False}, 'policy_delete_confirm'),
    url(r'^invoices/$', invoices.invoice_list, {}, 'invoice_list'),
    url(r'^invoices/(?P<invoice_month>\d+-\d+-\d+)/$',
        invoices.invoice_detail, {}, 'invoice_detail'),
]
