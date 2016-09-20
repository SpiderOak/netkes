# PYTHONPATH=/opt/openmanage/django python permissions.py

import os

os.environ['DJANGO_SETTINGS_MODULE'] = 'omva.settings'

from django.contrib.auth.models import Permission  # NOQA
from django.contrib.contenttypes.models import ContentType  # NOQA


def create_permissions():
    content_type = ContentType.objects.get_or_create(
        app_label='blue_mgnt', model='AccountsApi')[0]

    Permission.objects.get_or_create(
        codename='can_edit_bonus_gigs',
        name='Can edit bonus gigs',
        content_type=content_type)
    Permission.objects.get_or_create(
        codename='can_manage_users',
        name='Can manage users',
        content_type=content_type)
    Permission.objects.get_or_create(
        codename='can_view_user_data',
        name='Can view user data',
        content_type=content_type)
    Permission.objects.get_or_create(
        codename='can_manage_shares',
        name='Can enable or disable shares',
        content_type=content_type)
    Permission.objects.get_or_create(
        codename='can_view_groups',
        name='Can view groups',
        content_type=content_type)
    Permission.objects.get_or_create(
        codename='can_manage_groups',
        name='Can manage groups',
        content_type=content_type)
    Permission.objects.get_or_create(
        codename='can_manage_auth_codes',
        name='Can manage auth codes',
        content_type=content_type)
    Permission.objects.get_or_create(
        codename='can_manage_admins',
        name='Can manage admins',
        content_type=content_type)
    Permission.objects.get_or_create(
        codename='can_view_settings',
        name='Can view settings',
        content_type=content_type)
    Permission.objects.get_or_create(
        codename='can_manage_settings',
        name='Can manage settings',
        content_type=content_type)
    #Permission.objects.get_or_create(
    #    codename='can_manage_logs',
    #    name='Can manage groups',
    #    content_type=content_type)

create_permissions()
