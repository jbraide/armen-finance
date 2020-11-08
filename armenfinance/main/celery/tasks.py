from celery.decorators import task 
from celery.utils.log import get_task_logger

from time import sleep

# activation link task
from . import details_send

logger = get_task_logger(__name__)

# import model
from django.contrib.auth import get_user_model

@task(name='activation_link_send_task')
def activation_link_send_task(duration, user_id, subject, message, email):
    is_task_completed = False

    # print(user_queried)
    print(user_id)


    # sleep(40)
    user_queried = get_user_model().objects.get(online_id=user_id)

    # try:
    #     pass
    # except Exception as err:
    #     pass
    details_send.send_activation_link(user_queried,subject, message, email)
    sleep(duration)
    return ('first_task_done')