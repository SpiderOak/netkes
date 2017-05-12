# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AdminGroup',
            fields=[
                ('group_id', models.IntegerField(serialize=False, primary_key=True)),
                ('ldap_dn', models.TextField(blank=True)),
                ('user_group_id', models.IntegerField()),
                ('date_created', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'admin_group',
            },
        ),
        migrations.CreateModel(
            name='AdminSetupTokens',
            fields=[
                ('token', models.CharField(max_length=40, serialize=False, primary_key=True)),
                ('date_created', models.DateTimeField(auto_now_add=True)),
                ('expiry', models.DateTimeField()),
                ('no_devices_only', models.BooleanField(default=False)),
                ('single_use_only', models.BooleanField(default=False)),
                ('auto_generated', models.BooleanField(default=False)),
            ],
            options={
                'db_table': 'admin_setup_tokens',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='AdminSetupTokensUse',
            fields=[
                ('token', models.CharField(max_length=40, serialize=False, primary_key=True)),
                ('date_created', models.DateTimeField()),
                ('expiry', models.DateTimeField()),
                ('no_devices_only', models.BooleanField(default=False)),
                ('single_use_only', models.BooleanField(default=False)),
                ('auto_generated', models.BooleanField(default=False)),
                ('used', models.BooleanField()),
                ('active', models.BooleanField()),
            ],
            options={
                'db_table': 'admin_setup_tokens_use',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='BumpedUser',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('email', models.EmailField(max_length=254)),
                ('bonus_gb_reset', models.BooleanField(default=False)),
                ('time_to_reset_bonus_gb', models.DateTimeField()),
            ],
            options={
                'db_table': 'bumped_user',
            },
        ),
    ]
