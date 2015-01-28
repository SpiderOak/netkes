from django.db import models
import datetime


class AdminSetupTokensUse(models.Model):
    token = models.CharField(max_length=40, primary_key=True)
    date_created = models.DateTimeField()
    expiry = models.DateTimeField()
    no_devices_only = models.BooleanField(default=True)
    single_use_only = models.BooleanField(default=True)
    used = models.BooleanField(default=False)
    active = models.BooleanField(default=True)

    def new_token(self):
        return self.date_created > (datetime.datetime.now() - datetime.timedelta(minutes=5))

    class Meta:
        db_table = 'admin_setup_tokens_use'


class AdminSetupTokens(models.Model):
    token = models.CharField(max_length=40, primary_key=True)
    date_created = models.DateTimeField(auto_now_add=True)
    expiry = models.DateTimeField()
    no_devices_only = models.BooleanField(default=True)
    single_use_only = models.BooleanField(default=True)

    class Meta:
        db_table = 'admin_setup_tokens'


class AdminGroup(models.Model):
    group_id = models.IntegerField(primary_key=True)
    ldap_dn = models.TextField(blank=True)
    user_group_id = models.IntegerField()
    date_created = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'admin_group'


