from django.db import models
import datetime


class AdminSetupTokensUse(models.Model):
    token = models.CharField(max_length=40, primary_key=True)
    date_created = models.DateTimeField()
    expiry = models.DateTimeField()
    no_devices_only = models.BooleanField(default=False)
    single_use_only = models.BooleanField(default=False)
    auto_generated = models.BooleanField(default=False)
    used = models.BooleanField()
    active = models.BooleanField()

    def new_token(self):
        return self.date_created > (datetime.datetime.now() - datetime.timedelta(minutes=5))

    class Meta:
        managed = False
        db_table = 'admin_setup_tokens_use'


class AdminSetupTokens(models.Model):
    token = models.CharField(max_length=40, primary_key=True)
    date_created = models.DateTimeField(auto_now_add=True)
    expiry = models.DateTimeField()
    no_devices_only = models.BooleanField(default=False)
    single_use_only = models.BooleanField(default=False)
    auto_generated = models.BooleanField(default=False)

    class Meta:
        managed = False
        db_table = 'admin_setup_tokens'


class AdminGroup(models.Model):
    group_id = models.IntegerField(primary_key=True)
    ldap_dn = models.TextField(blank=True)
    user_group_id = models.IntegerField()
    date_created = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'admin_group'


class BumpedUser(models.Model):
    email = models.EmailField()
    bonus_gb_reset = models.BooleanField(default=False)
    time_to_reset_bonus_gb = models.DateTimeField()

    class Meta:
        db_table = 'bumped_user'

    def __unicode__(self):
        return '{}: {}, {}'.format(self.email,
                                   self.time_to_reset_bonus_gb,
                                   self.bonus_gb_reset)


class InvoiceNote(models.Model):
    note = models.TextField(
        default='',
        help_text=('An optional note that will appear on your invoices. '
                   'Use this if you need to add an address, VAT number, or similar.'),
    )

    def __unicode__(self):
        return self.note
