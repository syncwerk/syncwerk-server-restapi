import logging
import time
import threading

from django.core.management.base import BaseCommand
from django.core.management import call_command

from restapi.settings import ENABLE_BACKGROUND_EMAIL_SENDING, BACKGROUND_EMAIL_SENDING_INTERVAL

logger = logging.getLogger(__name__)

background_email_sending_log_handler = logging.FileHandler('/var/log/syncwerk/background_email_sending.log')
background_email_sending_log_handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
background_email_sending_log_handler.setFormatter(formatter)

logger.addHandler(background_email_sending_log_handler)

def is_background_email_sending_available():
    return True if ENABLE_BACKGROUND_EMAIL_SENDING else False
    # license_info = parse_license_to_json()
    # available_features_arr = license_info['available_features']
    # if license_info['edition'] == 'freeware':
    #     return True
    # else:
    #     return True if 'virusScanning' in available_features_arr and ENABLE_VIRUS_SCANNING else False

class BackgroundEmailSenderThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    
    def run(self):
        while True:
            if is_background_email_sending_available():
                time.sleep(BACKGROUND_EMAIL_SENDING_INTERVAL*60)
                logger.info('Background email sending is running')
                call_command('send_notices')
            else:
                logger.info('Background email sending is disabled')
                time.sleep(BACKGROUND_EMAIL_SENDING_INTERVAL*60)

class Command(BaseCommand):
    def handle(self, *args, **kargs):
        logger.info('Background email sender is running')
        background_mail_sender_thread = BackgroundEmailSenderThread()
        background_mail_sender_thread.start()
