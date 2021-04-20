import logging
import threading
import time
from datetime import datetime, timedelta

from django.core.management.base import BaseCommand
from restapi.api3.custom.admin.audit_log import AuditLog
from restapi.settings import (AUDIT_LOG_NUMBER_OF_DAYS_TO_KEEP,
                              ENABLE_CLEAR_OLD_AUDIT_LOG,
                              OLD_AUDIT_LOG_SCAN_INTERVAL)

logger = logging.getLogger(__name__)


class ClearOldAuditLogBackgroundThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        if ENABLE_CLEAR_OLD_AUDIT_LOG:
            while True:
                logger.info('Old audit log scanning is running...')
                older_than_date = datetime.now() - timedelta(days=AUDIT_LOG_NUMBER_OF_DAYS_TO_KEEP)
                audit_log_instance = AuditLog.getInstance()
                audit_log_list_total = audit_log_instance.clear_old_log(older_than_date)
                time.sleep(OLD_AUDIT_LOG_SCAN_INTERVAL*60)
        else:
            logger.info('Clear old audit log is not available')

class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        print "Old audit log scanning thread starting"
        old_audit_log_scanning_thread = ClearOldAuditLogBackgroundThread()
        old_audit_log_scanning_thread.start()
