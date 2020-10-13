from armenfinance.settings.base import *

# SECRET_KEY = 'rgrnmr#zk2st-m9mc43pjirup+lv&3gw04$&1bu&i%l6z(nz40'

AUTH_USER_MODEL = 'main.CustomUser'


EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_USE_TLS = True
EMAIL_PORT = 587
EMAIL_HOST_USER = 'thea1technologiesio@gmail.com'
EMAIL_HOST_PASSWORD = 'lkbncdxncpybgmnt'


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