from django.db import models
import datetime


class AdminSetupTokensUse(models.Model):
    token = models.CharField(max_length=40, primary_key=True)
    date_created = models.DateTimeField()
    expiry = models.DateTimeField()
    no_devices_only = models.BooleanField()
    single_use_only = models.BooleanField()
    used = models.BooleanField()
    active = models.BooleanField()

    def new_token(self):
        return self.date_created > (datetime.datetime.now() - datetime.timedelta(minutes=5))

    class Meta:
        db_table = 'admin_setup_tokens_use'


class AdminSetupTokens(models.Model):
    token = models.CharField(max_length=40, primary_key=True)
    date_created = models.DateTimeField(auto_now_add=True)
    expiry = models.DateTimeField()
    no_devices_only = models.BooleanField()
    single_use_only = models.BooleanField()

    class Meta:
        db_table = 'admin_setup_tokens'


class AdminGroup(models.Model):
    group_id = models.IntegerField(primary_key=True)
    ldap_dn = models.TextField(blank=True)
    user_group_id = models.IntegerField()
    date_created = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'admin_group'


'''
create table admin_group (
    group_id int4 primary key,
    ldap_dn text,
    date_created timestamp not null default current_timestamp
);
grant select, insert, update on admin_group to admin_console;
'''









