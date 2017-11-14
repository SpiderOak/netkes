# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blue_mgnt', '0002_adminsetuptokens_adminsetuptokensuse'),
    ]

    operations = [
        migrations.CreateModel(
            name='InvoiceNote',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('note', models.TextField()),
            ],
        ),
    ]
