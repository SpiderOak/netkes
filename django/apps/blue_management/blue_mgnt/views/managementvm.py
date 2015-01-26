import os
import datetime
import subprocess
import glob
from base64 import b32encode

from .views import enterprise_required, log_admin_action, get_base_url
from django.template import RequestContext
from django.shortcuts import redirect, render_to_response
from django.db import connection
from django import forms
from django.core.urlresolvers import reverse
from django.contrib.auth.models import Group, Permission
from django.forms.formsets import formset_factory
from django.contrib.auth.decorators import permission_required
from django.conf import settings as django_settings

from blue_mgnt import models
from netkes.account_mgr import setup_token
from .views import pageit
from functools import reduce

RESULTS_PER_PAGE = 25

def get_login_link(username, auth_token):
    b32_username = b32encode(username).rstrip('=')
    return '%s/storage/%s/escrowlogin-v2?auth_token=%s' % (get_base_url(),
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
    )
    models.AdminSetupTokens.objects.create(**data)
    return redirect(get_login_link(escrow_username, data['token']))

class CodeForm(forms.Form):
    expiry_interval = forms.IntegerField(label='Expiry',
                                         initial=1,
                                         min_value=1,
                                         help_text='days',)
    no_devices_only = forms.BooleanField(required=False,
                                         initial=True,
                                         label='No Devices Only?',
                                        )
    single_use_only = forms.BooleanField(required=False,
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
    codes = models.AdminSetupTokensUse.objects.order_by('-date_created')
    if not show_inactive:
        codes = codes.filter(active=True)
    code_count = codes.count()
    codes = codes[user_offset:user_offset + RESULTS_PER_PAGE]
    next_page = code_count > (user_offset + RESULTS_PER_PAGE)
    new_code = CodeForm()

    if request.method == 'POST':
        if request.POST.get('form', '') == 'new_code':
            new_code = CodeForm(request.POST)
            if new_code.is_valid():
                data = dict(
                    token=setup_token.new_token(),
                    expiry=(datetime.timedelta(days=new_code.cleaned_data['expiry_interval']) 
                            + datetime.datetime.now()),
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

    return render_to_response('authcodes.html', dict(
        page=page,
        show_inactive=show_inactive,
        new_code=new_code,
        next_page=next_page,
        datetime=datetime,
        user=request.user,
        username=username,
        features=features,
        codes=codes,
        account_info=account_info,
        saved=saved,
    ),
    RequestContext(request))

@enterprise_required
@permission_required('blue_mgnt.can_manage_logs', raise_exception=True)
def logs(request, api, account_info, config, username, saved=False):
    page = int(request.GET.get('page', 1))
    search = request.GET.get('search', '')

    user_offset = RESULTS_PER_PAGE * (page - 1)

    log_search = os.path.join(django_settings.LOG_DIR,
                              '%s*' % django_settings.ADMIN_ACTIONS_LOG_FILENAME)
    log_entries = [open(x).readlines() for x in glob.glob(log_search)]
    log_entries = sorted(reduce(list.__add__, log_entries), reverse=True)
    log_entries = [log for log in log_entries if search.lower() in log.lower()]

    count = len(log_entries)
    log_entries = log_entries[user_offset:user_offset + RESULTS_PER_PAGE]
    next_page = count > (user_offset + RESULTS_PER_PAGE)
    all_pages = pageit('logs', api, page, count)

    return render_to_response('logs.html', dict(
        page=page,
        next_page=next_page,
        datetime=datetime,
        search=search,
        user=request.user,
        username=username,
        log_entries=log_entries,
        account_info=account_info,
        all_pages=all_pages,
    ),
    RequestContext(request))



