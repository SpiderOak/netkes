from django.core.validators import RegexValidator
import re

name_validator = RegexValidator(
    regex=r'^[a-zA-Z][a-zA-Z0-9_]{3,37}$',
    message=(
        'Usernames must start with a letter, '
        'be at least four characters long, '
        'and may contain letters, numbers, '
        'and underscores.'
    ),
    flags=re.UNICODE,
)
