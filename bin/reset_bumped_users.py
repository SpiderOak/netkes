#!/usr/bin/env python

import os
from netkes import common
from netkes.account_mgr.accounts_api import Api

os.environ['DJANGO_SETTINGS_MODULE'] = 'omva.settings'

from django.utils.timezone import now

from blue_mgnt.models import BumpedUser
from blue_mgnt.views.users import SIZE_OF_GIGABYTE, SIZE_OF_BUMP

config = common.read_config_file()

api = Api.create(
    config["api_root"],
    config["api_user"],
    config["api_password"],
)

bumped_users = BumpedUser.objects.filter(bonus_gb_reset=False)
bumped_users = bumped_users.filter(time_to_reset_bonus_gb__lt=now())
for bumped_user in bumped_users:
    user = api.get_user(bumped_user.email)
    data = dict()
    data['bonus_bytes'] = max((user['bonus_bytes'] / SIZE_OF_GIGABYTE) - SIZE_OF_BUMP, 
                             0) * SIZE_OF_GIGABYTE
    api.edit_user(bumped_user.email, data)
    bumped_user.bonus_gb_reset=True
    bumped_user.save()

