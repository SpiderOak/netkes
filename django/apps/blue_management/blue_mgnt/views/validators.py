from django.core.validators import RegexValidator
import re

name_validator = RegexValidator(
    regex=r"^[\w\d\_]+$",
    message="This field can only contain letter, numbers and underscores",
    flags=re.UNICODE,
)
