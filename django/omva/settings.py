import os
import sys
from netkes import common

PROJECT_DIR = os.path.abspath(os.path.dirname(__file__))

sys.path += [os.path.join(PROJECT_DIR, '../apps')]
sys.path += ['/opt/openmanage/django/apps']

DEBUG = False

ADMINS = ()

MANAGERS = ADMINS

config = common.read_config_file()

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'openmanage',
        'USER': 'admin_console',
        'PASSWORD': 'iexyjtso',
        'HOST': 'localhost',
    }
}

SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_AGE = 60 * 15

ACCOUNT_API_URL = config['api_root']
BILLING_API_URL = config['billing_root']

EMAIL_HOST = 'localhost'
EMAIL_PORT = 25

MANAGEMENT_VM = True

LOGIN_URL = '/login/'

MINIMUM_PASSWORD_LENGTH = 8

TIME_ZONE = 'America/Chicago'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# Absolute path to the directory that holds media.
# Example: "/home/media/media.lawrence.com/"
MEDIA_ROOT = ''

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash if there is a path component (optional in other cases).
# Examples: "http://media.lawrence.com", "http://example.com/media/"
MEDIA_URL = ''

ALLOWED_HOSTS = ['*']

# URL prefix for admin media -- CSS, JavaScript and images. Make sure to use a
# trailing slash.
# Examples: "http://foo.com/media/", "/media/".
ADMIN_MEDIA_PREFIX = '/static/affiliate/admin/'

# Make this unique, and don't share it with anybody.
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']

MIDDLEWARE = [
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
]

ROOT_URLCONF = 'omva.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.request',
                'django.template.context_processors.tz',
                'django.contrib.messages.context_processors.messages',
                'blue_mgnt.context_processors.blue_common',
            ]
        }
    },
]

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.admin',
    'blue_mgnt',
    'openmanage',
)

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': '/opt/openmanage/django_cache2',
    }
}

SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'


AUTHENTICATION_BACKENDS = (
    'blue_mgnt.views.views.NetkesBackend',
)

TEST_RUNNER = 'django.test.runner.DiscoverRunner'

LOG_DIR = '/var/log/admin_console/'
ADMIN_ACTIONS_LOG_FILENAME = os.getenv('ADMIN_ACTIONS_LOG_FILE', 'admin_actions.log')

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(asctime)s %(message)s'
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        },
        'files': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'simple',
            'filename': os.path.join(LOG_DIR, 'admin_console.log')
        },
        'admin_actions_files': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'simple',
            'filename': os.path.join(LOG_DIR, ADMIN_ACTIONS_LOG_FILENAME)
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'files'],
            'propagate': True,
            'level': 'INFO',
        },
        'admin_actions': {
            'handlers': ['console', 'admin_actions_files'],
            'propagate': True,
            'level': 'DEBUG',
        },
    },
    'root': {
        'handlers': ['console']
    }
}

try:
    from dev_settings import *  # NOQA
except Exception:
    pass
