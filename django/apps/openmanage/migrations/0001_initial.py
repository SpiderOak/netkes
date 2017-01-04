# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Password',
            fields=[
                ('email', models.CharField(max_length=64, serialize=False, primary_key=True)),
                ('pw_hash', models.CharField(max_length=128)),
            ],
            options={
                'db_table': 'passwords',
            },
        ),
    ]
