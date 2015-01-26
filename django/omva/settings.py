import os
import sys
from netkes import common
import logging

PROJECT_DIR = os.path.abspath(os.path.dirname(__file__))

sys.path += [os.path.join(PROJECT_DIR, '../apps')]
sys.path += ['/opt/openmanage/django/apps']

DEBUG = False
TEMPLATE_DEBUG = DEBUG

ADMINS = ()

MANAGERS = ADMINS

common.set_config(common.read_config_file())
config = common.get_config()

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'openmanage',
        'USER': 'admin_console',
        'PASSWORD': 'iexyjtso',
        'HOST': 'localhost',
    }
}

DATABASE_ENGINE = 'postgresql_psycopg2'
DATABASE_NAME = 'openmanage'          
DATABASE_USER = 'admin_console'      
DATABASE_PASSWORD = 'iexyjtso'      
DATABASE_HOST = 'localhost'
DATABASE_PORT = ''

SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_AGE = 60 * 15

ACCOUNT_API_URL = config['api_root']
BILLING_API_URL = config['billing_root']

EMAIL_HOST = 'localhost'
EMAIL_PORT = 25

MANAGEMENT_VM = True

LOGIN_URL = '/login/'

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = None

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

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader'
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.middleware.transaction.TransactionMiddleware',
    'pagination.middleware.PaginationMiddleware',
)

ROOT_URLCONF = 'omva.urls'

TEMPLATE_DIRS = (
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

TEMPLATE_CONTEXT_PROCESSORS = (
    'django.contrib.auth.context_processors.auth',
    'django.core.context_processors.debug',
    'django.core.context_processors.i18n',
    'django.core.context_processors.media',
    'django.core.context_processors.request',
    'blue_mgnt.context_processors.blue_common',
)

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.admin',
    'blue_mgnt',
    'openmanage',
    'pagination',
)

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': '/opt/openmanage/django_cache',
    }
}


AUTHENTICATION_BACKENDS = (
    'blue_mgnt.views.views.NetkesBackend',
)

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
        'console':{
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        },
        'files':{
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'simple',
            'filename': os.path.join(LOG_DIR, 'admin_console.log')
        },
        'admin_actions_files':{
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
    from .dev_settings import *
except Exception:
    pass
