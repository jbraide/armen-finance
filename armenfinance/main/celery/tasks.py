from celery.decorators import task 
from celery.utils.log import get_task_logger

from time import sleep

# activation link task
from . import details_send

logger = get_task_logger(__name__)

# import model
from django.contrib.auth import get_user_model

@task(name='activation_link_send_task', serializer='json')
def activation_link_send_task(duration, online_id, subject, message, email):
    is_task_completed = False

    print(online_id)
    sleep(40)
    user = get_user_model()

    # try:
    #     pass
    # except Exception as err:
    #     pass
    details_send.send_activation_link(user,subject, message, email)
    sleep(duration)
    return ('first_task_done')