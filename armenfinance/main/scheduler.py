# import logging

# from apscheduler.schedulers.background import BackgroundScheduler
# from apscheduler.executors.pool import ProcessPoolExecutor, ThreadPoolExecutor
# from django_apscheduler.jobstores import register_events, register_job

# from django.conf import settings

# # create scheduler to run in a thread inside the application process
# scheduler = BackgroundScheduler(settings.SCHEDULER_CONFIG)

# def start():
#     if settings.DEBUG:
#         # hook into the apscheduler logger
#         logging.basicConfig()
#         logging.getLogger('apscheduler').setLevel(logging.DEBUG)

#     # adding this job here instead of to crons
#     scheduler.add_job()


from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()

def mail_sender():
    print('I/m printing every 10 seconds ')

def start():
    scheduler.add_job(mail_sender, 'interval', seconds=10)
    scheduler.start()