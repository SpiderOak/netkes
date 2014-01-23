import os
import datetime
import subprocess
import glob
from base64 import b32encode

from views import enterprise_required, render_to_response, log_admin_action, get_base_url
from django.template import RequestContext
from django.shortcuts import redirect
from django.db import connection
from django import forms
from django.core.urlresolvers import reverse
from django.contrib.auth.models import Group, Permission
from django.forms.formsets import formset_factory
from django.contrib.auth.decorators import permission_required
from django.conf import settings as django_settings

from interval.forms import IntervalFormField

from blue_mgnt import models
from netkes.account_mgr import setup_token

RESULTS_PER_PAGE = 25

def get_login_link(username, auth_token):
    b32_username = b32encode(username).rstrip('=')
    return '%s/storage/%s/escrowlogin?auth_token=%s' % (get_base_url(), 
                                                        b32_username,
                                                        auth_token
                                                       )
@enterprise_required
@permission_required('blue_mgnt.can_view_user_data')
def escrow_login(request, api, account_info, config, username, 
                 escrow_username, saved=False):
    data = dict(
        token=setup_token.new_token(),
        expiry=datetime.datetime.now() + datetime.timedelta(minutes=1), 
        no_devices_only=False, 
        single_use_only=False,
    )
    models.AdminSetupTokens.objects.create(**data)
    return redirect(get_login_link(escrow_username, data['token']))

class CodeForm(forms.Form):
    expiry_interval = IntervalFormField('D', 
                                        label='Expiry', 
                                        initial=datetime.timedelta(days=1))
    no_devices_only = forms.BooleanField(required=False, 
                                         initial=True,
                                         help_text='testing it out'
                                        )
    single_use_only = forms.BooleanField(required=False, initial=True)

@enterprise_required
@permission_required('blue_mgnt.can_manage_auth_codes')
def auth_codes(request, api, account_info, config, username, saved=False):
    features = api.enterprise_features()
    opts = api.enterprise_settings()
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
                    expiry=new_code.cleaned_data['expiry_interval'] + datetime.datetime.now(), 
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
@permission_required('blue_mgnt.can_manage_admins')
def admin_groups(request, api, account_info, config, username, saved=False):
    features = api.enterprise_features()


    class AdminGroupForm(forms.Form):
        name = forms.CharField()
        ldap_dn = forms.CharField(required=True, 
                                  widget=forms.Textarea(attrs={'rows':'1', 'cols':'60'}))
        permissions = forms.MultipleChoiceField(
                        required=False, 
                        choices=[(p.id, p.name) for p in 
                                 request.user.user_permissions.all()], 
                        widget=forms.CheckboxSelectMultiple)
        group_id = forms.IntegerField(widget=forms.HiddenInput, required=False)

        def clean(self):
            cleaned_data = super(AdminGroupForm, self).clean()
            name = cleaned_data.get('name', '')
            group_id = cleaned_data.get('group_id', '')

            try:
                group = Group.objects.get(name=name)
                if group.id != group_id:
                    self._errors['name'] = self.error_class(["There is already a group with this name"])
            except Group.DoesNotExist:
                pass

            return cleaned_data


    initial = []
    for group in Group.objects.all():
        admin_group = models.AdminGroup.objects.get(pk=group.id)
        initial.append(dict(group_id=group.id,
                            name=group.name,
                            ldap_dn=admin_group.ldap_dn,
                            permissions=[p.id for p in group.permissions.all()]))


    class BaseAdminGroupFormSet(forms.formsets.BaseFormSet):
        def clean(self):
            if any(self.errors):
                return
            names = []
            for x in range(0, self.total_form_count()):
                form = self.forms[x]
                name = form.cleaned_data['name']
                if name in names:
                    form._errors['name'] = form.error_class([
                        'There is already a group with this name'])
                names.append(name)


    new_admin_group = AdminGroupForm()
    AdminGroupFormSet = formset_factory(AdminGroupForm, 
                                        extra=0, 
                                        formset=BaseAdminGroupFormSet, 
                                        can_delete=True)
    admin_groups = AdminGroupFormSet(initial=initial, prefix='admin_groups')

    if request.method == 'POST' and request.user.has_perm('blue_mgnt.can_manage_settings'):
        if request.POST.get('form', '') == 'new_admin_group':
            new_admin_group = AdminGroupForm(request.POST)
            if new_admin_group.is_valid():
                group = Group.objects.create(name=new_admin_group.cleaned_data['name']) 
                for permission_id in new_admin_group.cleaned_data['permissions']:
                    group.permissions.add(Permission.objects.get(pk=permission_id))
                group.save()
                admin_group = models.AdminGroup.objects.create( 
                    group_id=group.id, 
                    ldap_dn=new_admin_group.cleaned_data['ldap_dn'])
                args = (new_admin_group.cleaned_data['name'], 
                        new_admin_group.cleaned_data['ldap_dn'],
                       )
                msg = 'Created admin group: %s %s' % args
                log_admin_action(request, msg)
                return redirect(reverse('blue_mgnt:admin_groups_saved'))
        else:
            admin_groups = AdminGroupFormSet(request.POST, prefix='admin_groups')
            if admin_groups.is_valid():
                for admin_group_form in admin_groups.forms:
                    admin_group = models.AdminGroup.objects.get(
                        pk=admin_group_form.cleaned_data['group_id'])
                    admin_group.ldap_dn=admin_group_form.cleaned_data['ldap_dn']
                    admin_group.save()
                    group = Group.objects.get(
                        pk=admin_group_form.cleaned_data['group_id'])
                    group.name = admin_group_form.cleaned_data['name']
                    group.permissions.clear()
                    for permission_id in admin_group_form.cleaned_data['permissions']:
                        group.permissions.add(Permission.objects.get(pk=permission_id))
                    group.save()
                    args = (admin_group_form.cleaned_data['name'], 
                            admin_group_form.cleaned_data['ldap_dn'],
                        )
                    msg = 'Modified admin group: %s %s' % args
                    log_admin_action(request, msg)
                for admin_group_form in admin_groups.deleted_forms:
                    admin_group = models.AdminGroup.objects.get(
                        pk=admin_group_form.cleaned_data['group_id'])
                    group = Group.objects.get(
                        pk=admin_group_form.cleaned_data['group_id'])
                    admin_group.delete()
                    group.delete()
                    args = (group.name, 
                            admin_group.ldap_dn,
                        )
                    msg = 'Deleted admin group: %s %s' % args
                    log_admin_action(request, msg)

                return redirect(reverse('blue_mgnt:admin_groups_saved'))

    return render_to_response('admin_groups.html', dict(
        account_info=account_info,
        user=request.user,
        username=username,
        admin_groups=admin_groups,
        new_admin_group=new_admin_group,
        features=features,
        saved=saved,
        permissions=request.user.user_permissions.all(),
        permissions_count=request.user.user_permissions.count(),
    ),
    RequestContext(request))

@enterprise_required
@permission_required('blue_mgnt.can_manage_logs')
def logs(request, api, account_info, config, username, saved=False):
    features = api.enterprise_features()
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

    return render_to_response('logs.html', dict(
        page=page,
        next_page=next_page,
        datetime=datetime,
        search=search,
        user=request.user,
        username=username,
        features=features,
        log_entries=log_entries,
        account_info=account_info,
    ),
    RequestContext(request))



