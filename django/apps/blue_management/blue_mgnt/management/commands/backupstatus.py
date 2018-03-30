import csv
import time
import os

from django.core.management.base import BaseCommand
from django.utils import timezone

from blue_mgnt.views.views import get_api
from netkes.common import read_config_file

SECONDS_IN_A_DAY = 60 * 60 * 24
SORT_COLUMNS = {
    'name': 0,
    'device_name': 1,
    'bytes_stored': 2,
    'last_login': 3,
    'last_backup_complete': 4,
}


class Command(BaseCommand):
    help = 'Create backup status report'

    def add_arguments(self, parser):
        parser.add_argument(
            '-s', '--sort-order', default='last_backup_complete', choices=SORT_COLUMNS.keys()
        )
        parser.add_argument('-r', '--reverse', action='store_true')
        parser.add_argument('-b', '--backed-up-within', default=90, type=int)
        parser.add_argument('-n', '--not-backed-up-within', default=3, type=int)
        parser.add_argument(
            '-o', '--outdir', default='/var/log/omva/backup_status', type=str
        )

    def _backed_up_within(self, last_backup_complete, backed_up_within):
        return (int(time.time()) - last_backup_complete) <= backed_up_within

    def handle(self, *args, **options):
        config = read_config_file()
        api = get_api(config)
        backed_up_within_seconds = options.get('backed_up_within') * SECONDS_IN_A_DAY
        not_backed_up_within_seconds = options.get('not_backed_up_within') * SECONDS_IN_A_DAY
        sort_order = options.get('sort_order')
        search_by = 'recently_stopped_uploading={}|{}'.format(
            backed_up_within_seconds, not_backed_up_within_seconds
        )
        filename = timezone.now().strftime('backup_status_%Y-%m-%d_%H:%M:%S.csv')

        writer = csv.writer(open(os.path.join(options.get('outdir'), filename), 'w'))
        headers = [
            'name', 'device_name', 'bytes_stored', 'last_login', 'last_backup_complete',
        ]
        writer.writerow(headers)
        rows = []

        for user in api.list_users(search_by=search_by):
            for device in api.list_devices(user['email']):
                last_backup_complete = device['last_backup_complete']
                if (
                    self._backed_up_within(last_backup_complete, backed_up_within_seconds)
                    and not
                    self._backed_up_within(last_backup_complete, not_backed_up_within_seconds)
                ):
                    rows.append([
                        user['name'],
                        device['name'],
                        user['bytes_stored'],
                        user['last_login'],
                        device['last_backup_complete'],
                    ])

        rows = sorted(
            rows, key=lambda x: x[SORT_COLUMNS[sort_order]], reverse=options.get('reverse')
        )

        for row in rows:
            writer.writerow(row)

        self.stdout.write(self.style.SUCCESS('Successfully created backup status report'))
