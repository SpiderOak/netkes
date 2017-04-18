# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blue_mgnt', '0001_initial'),
    ]

    operations = [
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
            },
        ),
    ]
