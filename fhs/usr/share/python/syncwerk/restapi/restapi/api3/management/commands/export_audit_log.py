import logging
import time
import argparse
import csv 
import os 
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from restapi.api3.custom.admin.audit_log import AuditLog

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Export Audit Log to CSV'

    def export_audit_log(self, output_file):
        audit_log_instance = AuditLog.getInstance()
        audit_log_list = audit_log_instance.getAuditListArray()

        with open(output_file, 'wb') as f:
            writer = csv.writer(f, lineterminator='\n')

            count = 0
            for row in audit_log_list:
                if count == 0:
                    headers = row.keys()
                    writer.writerow(headers)
                    count += 1
                writer.writerow(row.values())
    
    def get_human_readable_size(self, size,precision=2):
        suffixes=['B','KB','MB','GB','TB']
        suffixIndex = 0
        while size > 1024 and suffixIndex < 4:
            suffixIndex += 1 #increment the index of the suffix
            size = size/1024.0 #apply the division
        return "%.*f%s"%(precision,size,suffixes[suffixIndex])

    def add_arguments(self, parser):
        current_dt = datetime.now().strftime("%Y%m%d.%H.%M.%S")
        default_output_file = os.getcwd()+'/'+current_dt+'_audit_log.csv'

        parser.add_argument('-o', type=str, default=default_output_file, help="Output file path")

    def handle(self, *args, **kwargs):
        self.stdout.write("Exporting...",ending="")

        # Variable
        current_dt = datetime.now().strftime("%Y%m%d.%H.%M.%S")
        output_file_name = kwargs.get('o')

        # Audit log export
        # Start count time
        start = time.time()

        # Export
        self.export_audit_log(output_file_name)

        # End count time
        end = time.time()
        self.stdout.write(self.style.SUCCESS("Done"))
        # Print result
        print("==============")
        self.stdout.write("Export complete in %.2f seconds"%(end-start))
        self.stdout.write("File size: %s"%(self.get_human_readable_size(os.path.getsize(output_file_name))))
        print("==============")
        self.stdout.write(self.style.SUCCESS("%s"%output_file_name))
        