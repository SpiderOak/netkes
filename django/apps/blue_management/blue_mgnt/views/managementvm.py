import os
import datetime
import glob
from base64 import b32encode

from views import (
    enterprise_required, log_admin_action, get_base_url,
    Pagination
)
from django.shortcuts import redirect, render
from django import forms
from django.core.urlresolvers import reverse
from django.contrib.auth.decorators import permission_required
from django.conf import settings as django_settings

from blue_mgnt import models
from netkes.account_mgr import setup_token

RESULTS_PER_PAGE = 25


def get_login_link(username, auth_token):
    b32_username = b32encode(username).rstrip('=')
    return '%s/storage/%s/escrowlogin-v2?auth_token=%s' % (
        get_base_url(),
        b32_username,
        auth_token
    )


@enterprise_required
@permission_required('blue_mgnt.can_view_user_data', raise_exception=True)
def escrow_login(request, api, account_info, config, username,
                 escrow_username, saved=False):
    user = api.get_user(escrow_username)
    log_admin_action(request, "Used storage login for user: %s" % user['email'])
    data = dict(
        token=setup_token.new_token(),
        expiry=datetime.datetime.now() + datetime.timedelta(minutes=1),
        no_devices_only=False,
        single_use_only=False,
        auto_generated=True,
    )
    models.AdminSetupTokens.objects.create(**data)
    return redirect(get_login_link(escrow_username, data['token']))


class CodeForm(forms.Form):
    expiry_days = forms.IntegerField(
        min_value=0,
        label='Expiry',
        help_text='days',
        initial=1
    )
    no_devices_only = forms.BooleanField(
        required=False,
        initial=True,
        label='No Devices Only?',
    )
    single_use_only = forms.BooleanField(
        required=False,
        initial=True,
        label='Single Use Only?',
    )


@enterprise_required
@permission_required('blue_mgnt.can_manage_auth_codes', raise_exception=True)
def auth_codes(request, api, account_info, config, username, saved=False):
    features = api.enterprise_features()
    page = int(request.GET.get('page', 1))
    show_inactive = int(request.GET.get('show_inactive', 1))

    user_offset = RESULTS_PER_PAGE * (page - 1)
    codes = models.AdminSetupTokensUse.objects.filter(auto_generated=False)
    codes = codes.order_by('-date_created')
    if not show_inactive:
        codes = codes.filter(active=True)
    code_count = codes.count()
    codes = codes[user_offset:user_offset + RESULTS_PER_PAGE]
    new_code = CodeForm()

    pagination = Pagination('blue_mgnt:auth_codes',
                            code_count,
                            page,
                            RESULTS_PER_PAGE, )

    if request.method == 'POST':
        if request.POST.get('form', '') == 'new_code':
            new_code = CodeForm(request.POST)
            if new_code.is_valid():
                data = dict(
                    token=setup_token.new_token(),
                    expiry=(
                        datetime.datetime.now() +
                        datetime.timedelta(days=new_code.cleaned_data['expiry_days'])
                    ),
                    no_devices_only=new_code.cleaned_data['no_devices_only'],
                    single_use_only=new_code.cleaned_data['single_use_only']
                )
                models.AdminSetupTokens.objects.create(**data)
                log_admin_action(request, 'Created code: %s' % data)
                return redirect(reverse('blue_mgnt:auth_codes_saved') +
                                '?show_inactive=%s' % show_inactive)
        if request.POST.get('form', '') == 'disable_code':
            code = models.AdminSetupTokens.objects.get(token=request.POST['token'])
            code.expiry = datetime.datetime.now()
            code.save()
            log_admin_action(request, 'Disabled code: %s' % request.POST['token'])
            return redirect(reverse('blue_mgnt:auth_codes_saved') +
                            '?show_inactive=%s' % show_inactive)

    return render(request, 'authcodes.html', dict(
        page=page,
        show_inactive=show_inactive,
        new_code=new_code,
        pagination=pagination,
        datetime=datetime,
        user=request.user,
        username=username,
        features=features,
        codes=codes,
        account_info=account_info,
        saved=saved,
    ))


@enterprise_required
@permission_required('blue_mgnt.can_manage_logs', raise_exception=True)
def logs(request, api, account_info, config, username, saved=False):
    page = int(request.GET.get('page', 1))
    search = request.GET.get('search', '')

    user_offset = RESULTS_PER_PAGE * (page - 1)

    log_search = os.path.join(django_settings.LOG_DIR,
                              '%s*' % django_settings.ADMIN_ACTIONS_LOG_FILENAME)
    log_entries = [open(x).readlines() for x in glob.glob(log_search)]
    log_entries = list(reversed(reduce(list.__add__, log_entries)))
    if search:
        log_entries = [log for log in log_entries if search.lower() in log.lower()]

    pagination = Pagination('blue_mgnt:logs',
                            len(log_entries),
                            page,
                            RESULTS_PER_PAGE, )

    log_entries = log_entries[user_offset:user_offset + RESULTS_PER_PAGE]

    return render(request, 'logs.html', dict(
        page=page,
        pagination=pagination,
        datetime=datetime,
        search=search,
        user=request.user,
        username=username,
        log_entries=log_entries,
        account_info=account_info,
    ))
