from armenfinance.settings.base import *


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'armenfinance',
        'USER': 'armenfinance',
        'PASSWORD': 'armenfinance',
        'HOST': 'localhost',
    }
}

USER_AUTH_MODEL = 'main.CustomUser'