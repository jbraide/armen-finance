from armenfinance.settings.base import *
import djcelery 

SECRET_KEY = 'rgrnmr#zk2st-m9mc43pjirup+lv&3gw04$&1bu&i%l6z(nz40'

AUTH_USER_MODEL = 'main.CustomUser'

# gmail
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_USE_TLS = True
EMAIL_PORT = 587
EMAIL_HOST_USER = 'thea1technologiesio@gmail.com'
EMAIL_HOST_PASSWORD = 'lkbncdxncpybgmnt'

# smartweb
# EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
# EMAIL_HOST = 'smtp.uniqtrades.com'
# EMAIL_USE_TLS = True
# EMAIL_PORT = 25
# EMAIL_HOST_USER = 'support@uniqtrades.com'
# EMAIL_HOST_PASSWORD = 'KzpC*4b0$z$s'


# the scheduler config will 
# - store jobs in the project databasde
# - execute jobs in threads inside the application process

SCHEDULER_CONFIG = {
    'apscheduler.jobstores.default': {
        'class': 'django_apschduler.jobstore:DjangoJobStore'
    },
    'apscheduler.executors.processpool': {
        'type': 'threadpool'
    },
}

SCHEDULER_AUTOSTART = True 

DEBUG = True

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'armenfinance',
        'USER': 'armenfinance',
        'PASSWORD': 'armenfinance',
        'HOST': 'localhost',
    }
}


# # celery settings
# ''' specify which broker you will use '''
# import kombu
BROKER_URL = 'redis://localhost:6379'
CELERY_RESULT_BACKEND = 'redis://localhost:6379'
CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_TASK_SERIALIZER = 'json'
# CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'Africa/Lagos'