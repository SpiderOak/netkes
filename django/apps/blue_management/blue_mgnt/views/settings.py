import datetime
import pytz
import subprocess 
from IPy import IP

from views import enterprise_required, render_to_response, log_admin_action

from django import forms
from django.forms.formsets import formset_factory
from django.template import RequestContext
from django.shortcuts import redirect
from django.contrib.auth.decorators import permission_required

from interval.forms import IntervalFormField
from netkes.netkes_agent import config_mgr 

AGENT_CONFIG_VARS = [
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
]

def save_settings(request, api, options):
    cleaned_data = options.cleaned_data
    data = dict()
    data.update(cleaned_data)
    del data['timezone']
    if 'enable_local_users' in data: 
        del data['enable_local_users']
    if 'share_link_ttl' in data: 
        data['share_link_ttl'] = data['share_link_ttl'].days * 1440
    if 'autopurge_interval' in data:
        data['autopurge_interval'] = data['autopurge_interval'].days
    if 'versionpurge_interval' in data:
        data['versionpurge_interval'] = data['versionpurge_interval'].days
    for var in AGENT_CONFIG_VARS:
        if var in data:
            del data[var]

    log_admin_action(request, 'update settings with data: %s' % data)
    api.update_enterprise_settings(data)

    config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
    for var in AGENT_CONFIG_VARS:
        config_mgr_.config[var] = cleaned_data[var]
    config_mgr_.apply_config()

    with open('/etc/timezone', 'w') as f:
        f.write(cleaned_data['timezone'])
    subprocess.call(['dpkg-reconfigure', '-f', 'noninteractive', 'tzdata'])


class IPBlockForm(forms.Form):
    ip_block = forms.CharField(max_length=43, label='IP Block:')

    def clean_ip_block(self):
        data = self.cleaned_data['ip_block']
        try:
            ip = IP(data)
        except ValueError, e:
            raise forms.ValidationError('Invalid IP Block')
        return data


@enterprise_required
@permission_required('blue_mgnt.can_view_settings', raise_exception=True)
def settings(request, api, account_info, config, username, saved=False):
    opts = api.enterprise_settings()
    features = api.enterprise_features()

    class OpenmanageOptsForm(forms.Form):
        #share_link_ttl = IntervalFormField(
        #    'D', 
        #    label='Share Link Time-to-Live', 
        #    initial=datetime.timedelta(minutes=opts['share_link_ttl'])
        #)
        if features['ldap']:
            ad_domain = forms.CharField(
                required=False, 
                label='Restrict client installs to domain', 
                initial=opts['ad_domain']
            )
        autopurge_interval = IntervalFormField(
            'D', 
            label='Deleted Items Automatic Purge', 
            initial=datetime.timedelta(days=opts['autopurge_interval'])
        )
        versionpurge_interval = IntervalFormField(
            'D', 
            label='Historical Version Automatic Purge', 
            initial=datetime.timedelta(days=opts['versionpurge_interval'])
        )
        support_email = forms.EmailField(initial=opts['support_email'])
        omva_url = forms.URLField(
            label='OpenManage Virtual Appliance URL', 
            initial=opts['omva_url'], 
        )
        timezone = forms.ChoiceField(
            choices=[(x, x) for x in pytz.common_timezones],
            initial=file('/etc/timezone').read().strip(),
        )

        def __init__(self, *args, **kwargs):
            super(OpenmanageOptsForm, self).__init__(*args, **kwargs)
            
            for var in AGENT_CONFIG_VARS:
                self.fields[var] = forms.CharField(
                    initial=config.get(var, ''), 
                    required=False
                )

    options = OpenmanageOptsForm()

    class BaseIPBlockFormSet(forms.formsets.BaseFormSet):
        def clean(self):
            if any(self.errors):
                return
            blocks = [a.cleaned_data['ip_block'] for a in self.forms \
                      if a.cleaned_data.get('ip_block') and not a.cleaned_data.get('DELETE')]
            api.update_enterprise_settings(dict(signup_network_restriction=blocks))
            log_admin_action(request, 'update signup network restrictions: %s' % blocks)

    IPBlockFormSet = formset_factory(IPBlockForm, 
                                     can_delete=True,
                                     formset=BaseIPBlockFormSet)

    ip_blocks = IPBlockFormSet(initial=[dict(ip_block=x) for x in opts['signup_network_restriction']], 
                               prefix='ip_blocks')
    error = False
    sync_output = ''
    rebuild_output = ''

    if request.method == 'POST' and request.user.has_perm('blue_mgnt.can_manage_settings'):
        if request.POST.get('form', '') == 'ip_block':
            ip_blocks = IPBlockFormSet(request.POST, prefix='ip_blocks')
            if ip_blocks.is_valid():
                return redirect('blue_mgnt:settings_saved')
            else:
                error = True
        elif request.POST.get('form', '') == 'reboot':
            log_admin_action(request, 'reboot management vm')
            subprocess.call(['shutdown', '-r', 'now'])
            return redirect('blue_mgnt:settings_saved')
        elif request.POST.get('form', '') == 'sync':
            log_admin_action(request, 'sync management vm')
            p = subprocess.Popen('/opt/openmanage/bin/run_openmanage.sh', 
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT
                                )
            sync_output = p.communicate()[0]
            if not sync_output:
                return redirect('blue_mgnt:settings_saved')
        elif request.POST.get('form', '') == 'rebuild_db':
            log_admin_action(request, 'Rebuild DB')
            p = subprocess.Popen('/opt/openmanage/bin/rebuild_db.sh', 
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT
                                )
            rebuild_output = p.communicate()[0]
            if not rebuild_output:
                return redirect('blue_mgnt:settings_saved')
        elif request.POST.get('form', '') == 'restart_directory':
            log_admin_action(request, 'restart directory')
            config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
            config_mgr_._kick_services()
            return redirect('blue_mgnt:settings_saved')
        else:
            options = OpenmanageOptsForm(request.POST)

            if options.is_valid():
                save_settings(request, api, options)
                return redirect('blue_mgnt:settings_saved')

    return render_to_response('settings.html', dict(
        user=request.user,
        username=username,
        features=features,
        ip_blocks=ip_blocks,
        sync_output=sync_output,
        rebuild_output=rebuild_output,
        options=options,
        saved=saved,
        error=error,
        account_info=account_info,
    ),
    RequestContext(request))


class PasswordForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput)
    password_again = forms.CharField(label="Repeat Password", widget=forms.PasswordInput)

    def clean_password_again(self):
        password = self.cleaned_data['password_again']
        if self.cleaned_data.get('password') != password:
            raise forms.ValidationError('Passwords do not match.')
        return password


@enterprise_required
@permission_required('blue_mgnt.can_manage_settings', raise_exception=True)
def password(request, api, account_info, config, username, saved=False):
    features = api.enterprise_features()
    password_form = PasswordForm()
    if request.method == 'POST':
        if request.POST.get('form', '') == 'password':
            password_form = PasswordForm(request.POST)
            if password_form.is_valid():
                new_password = password_form.cleaned_data['password']
                log_admin_action(request, 'change password')
                api.update_enterprise_password(new_password)
                config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
                config_mgr_.config['api_password'] = new_password
                config_mgr_.apply_config()
                return redirect('blue_mgnt:password_saved')

    return render_to_response('password.html', dict(
        user=request.user,
        username=username,
        features=features,
        password_form=password_form,
        saved=saved,
        account_info=account_info,
    ),
    RequestContext(request))
