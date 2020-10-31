from __future__ import absolute_import
import os
from celery import Celery

# set the default Django settings module for the 'celery' program
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'armenfinance.settings.development')

from django.conf import settings
app = Celery('armenfinance')

# using a string here means the worker don't have to serialize 
# the configuration object to child processes.
app.config_from_object('django.conf:settings')

# load task modules from all registered django app configs. 
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)


@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}}'.format(self.request))