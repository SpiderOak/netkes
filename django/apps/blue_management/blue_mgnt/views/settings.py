import pytz
import subprocess
from IPy import IP
import ldap

from views import (
    enterprise_required, render,
    log_admin_action, hash_password
)

from django.utils.safestring import mark_safe
from django import forms
from django.forms.formsets import formset_factory
from django.shortcuts import redirect
from django.contrib.auth.decorators import permission_required
from django.core.cache import cache
from django.core.validators import MinLengthValidator
from django.conf import settings as django_settings


from netkes.netkes_agent import config_mgr
from netkes import account_mgr
from netkes.account_mgr.user_source.ldap_source import get_auth_username

AGENT_CONFIG_VARS = [
    'minimum_password_length',
    'api_root',
    'auth_method',
    'dir_auth_source',
    'dir_base_dn',
    'dir_fname_source',
    'dir_guid_source',
    'dir_lname_source',
    'dir_member_source',
    'dir_password',
    'dir_type',
    'dir_uid_source',
    'dir_uri',
    'dir_user',
    'dir_username_source',
    'listen_addr',
    'listen_port',
    'send_activation_email',
    'resolve_sync_conflicts',
]


def save_settings(request, api, options):
    cleaned_data = options.cleaned_data
    data = dict()
    data.update(cleaned_data)
    if 'timezone' in data:
        del data['timezone']
    if 'enable_local_users' in data:
        del data['enable_local_users']
    if 'autopurge_interval' in data:
        data['autopurge_interval'] = data['autopurge_interval']
    if 'versionpurge_interval' in data:
        data['versionpurge_interval'] = data['versionpurge_interval']
    if 'purgehold_duration' in data:
        data['purgehold_duration'] = data['purgehold_duration'] * 86400
    for var in AGENT_CONFIG_VARS:
        if var in data:
            del data[var]

    log_admin_action(request, 'update settings with data: %s' % data)
    api.update_enterprise_settings(data)

    config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
    for var in AGENT_CONFIG_VARS:
        if var in cleaned_data:
            config_mgr_.config[var] = cleaned_data[var]
    config_mgr_.apply_config()

    if 'timezone' in cleaned_data:
        subprocess.call(['timedatectl', 'set-timezone', cleaned_data['timezone']])


def login_test(config, username, password):
    if username:
        if account_mgr.authenticator(config, username, password, False):
            return 'Authentication was successful!'
        else:
            conn = ldap.initialize(config['dir_uri'])
            try:
                auth_user = get_auth_username(config, username)
                conn.simple_bind_s(auth_user, password)
            except Exception, e:
                return 'Authentication failed. {}'.format(e)
    return 'Authentication failed.'


@enterprise_required
@permission_required('blue_mgnt.can_view_settings', raise_exception=True)
def settings(request, api, account_info, config, username, saved=False):
    opts = api.enterprise_settings()
    features = api.enterprise_features()

    class OpenmanageOptsForm(forms.Form):
        if features['ldap']:
            ad_domain = forms.CharField(
                required=False,
                label='Restrict client installs to domain',
                initial=opts['ad_domain']
            )
        autopurge_interval = forms.IntegerField(
            min_value=0,
            label='Deleted Items Automatic Purge',
            help_text='days',
            initial=opts['autopurge_interval'],
            required=False,
        )
        versionpurge_interval = forms.IntegerField(
            min_value=0,
            label='Historical Version Automatic Purge',
            help_text='days',
            initial=opts['versionpurge_interval'],
            required=False,
        )
        purgehold_duration = forms.IntegerField(
            min_value=0,
            label='Purgehold Duration',
            help_text='days',
            initial=opts['purgehold_duration'] / 86400,
            required=False,
        )
        support_email = forms.EmailField(initial=opts['support_email'])
        admin_email = forms.EmailField(initial=opts['admin_email'])
        if features['ldap']:
            omva_url = forms.URLField(
                label='Management VM External URL',
                initial=opts['omva_url'],
            )
            timezone = forms.ChoiceField(
                choices=[(x, x) for x in pytz.common_timezones],
                initial=file('/etc/timezone').read().strip(),
            )

        def __init__(self, *args, **kwargs):
            super(OpenmanageOptsForm, self).__init__(*args, **kwargs)

            for var in AGENT_CONFIG_VARS:
                if var == 'minimum_password_length':
                    self.fields[var] = forms.IntegerField(
                        min_value=1,
                        initial=config.get(var, 8),
                        required=False,
                    )
                elif features['ldap']:
                    if var in ['send_activation_email', 'resolve_sync_conflicts']:
                        if var == 'resolve_sync_conflicts':
                            initial = False
                            help_text = mark_safe(
                                'Only enable this feature if you have read the documentation '
                                '<a href="https://spideroak.com/articles/account-page-in-spideroak-enterprise#resolve-sync-conflicts">'  # NOQA
                                'here.</a>'
                            )
                        else:
                            initial = True
                            help_text = ''
                        self.fields[var] = forms.BooleanField(
                            initial=config.get(var, initial),
                            required=False,
                            help_text=help_text,
                        )
                    else:
                        self.fields[var] = forms.CharField(
                            initial=config.get(var, ''),
                            required=False
                        )

    options = OpenmanageOptsForm()

    class BaseIPBlockFormSet(forms.formsets.BaseFormSet):
        def clean(self):
            if any(self.errors):
                return
            blocks = [a.cleaned_data['ip_block'] for a in self.forms
                      if a.cleaned_data.get('ip_block') and not a.cleaned_data.get('DELETE')]
            api.update_enterprise_settings(dict(signup_network_restriction=blocks))
            log_admin_action(request, 'update signup network restrictions: %s' % blocks)

    error = False
    command_output = ''

    if request.method == 'POST' and request.user.has_perm('blue_mgnt.can_manage_settings'):
        if request.POST.get('form', '') == 'reboot':
            log_admin_action(request, 'reboot management vm')
            subprocess.call(['shutdown', '-r', 'now'])
            return redirect('blue_mgnt:settings_saved')
        elif request.POST.get('form', '') == 'sync':
            log_admin_action(request, 'sync management vm')
            p = subprocess.Popen('/opt/openmanage/bin/run_openmanage.sh',
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            command_output = p.communicate()[0]
            if not command_output:
                cache.clear()
                return redirect('blue_mgnt:settings_saved')
        elif request.POST.get('form', '') == 'rebuild_db':
            log_admin_action(request, 'Rebuild DB')
            p = subprocess.Popen('/opt/openmanage/bin/rebuild_db.sh',
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            command_output = p.communicate()[0]
            if not command_output:
                return redirect('blue_mgnt:settings_saved')
        elif request.POST.get('form', '') == 'restart_directory':
            log_admin_action(request, 'restart directory')
            config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
            config_mgr_._kick_services()
            return redirect('blue_mgnt:settings_saved')
        elif request.POST.get('form', '') == 'login_test':
            log_admin_action(request, 'login test')
            command_output = login_test(
                config,
                request.POST.get('username', ''),
                request.POST.get('password', ''),
            )
        else:
            options = OpenmanageOptsForm(request.POST)

            if options.is_valid():
                save_settings(request, api, options)
                return redirect('blue_mgnt:settings_saved')

    return render(request, 'settings.html', dict(
        user=request.user,
        username=username,
        features=features,
        command_output=command_output,
        options=options,
        saved=saved,
        error=error,
        account_info=account_info,
    ))


class PasswordForm(forms.Form):
    password = forms.CharField(
        widget=forms.PasswordInput,
        min_length=django_settings.MINIMUM_PASSWORD_LENGTH
    )
    password_again = forms.CharField(label="Repeat Password", widget=forms.PasswordInput)

    def __init__(self, *args, **kwargs):
        config = kwargs.pop('config', None)
        super(PasswordForm, self).__init__(*args, **kwargs)
        self._init_password_length_from_config(config)

    def _init_password_length_from_config(self, config):
        try:
            min_length = int(config['minimum_password_length'])
        except (KeyError, TypeError):
            min_length = django_settings.MINIMUM_PASSWORD_LENGTH
        field = self.fields['password']
        field.validators.append(
            MinLengthValidator(min_length)
        )

    def clean_password_again(self):
        password = self.cleaned_data['password_again']
        if self.cleaned_data.get('password') != password:
            raise forms.ValidationError('Passwords do not match.')
        return password


@enterprise_required
@permission_required('blue_mgnt.can_manage_settings', raise_exception=True)
def password(request, api, account_info, config, username, saved=False):
    features = api.enterprise_features()
    password_form = PasswordForm(config=config)
    if request.method == 'POST':
        if request.POST.get('form', '') == 'password':
            password_form = PasswordForm(request.POST, config=config)
            if password_form.is_valid():
                new_password = password_form.cleaned_data['password'].encode('utf-8')
                log_admin_action(request, 'change password')

                new_pass, api_pass = hash_password(new_password)

                api.update_enterprise_password(api_pass)
                config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
                config_mgr_.config['api_password'] = api_pass
                config_mgr_.config['local_password'] = new_pass
                config_mgr_.apply_config()
                return redirect('blue_mgnt:password_saved')

    return render(request, 'password.html', dict(
        minimum_password_length=config.get('minimum_password_length', 8),
        user=request.user,
        username=username,
        features=features,
        password_form=password_form,
        saved=saved,
        account_info=account_info,
    ))
