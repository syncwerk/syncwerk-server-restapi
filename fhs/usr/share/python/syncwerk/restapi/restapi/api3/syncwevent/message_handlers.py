import logging
import time

from datetime import date

from restapi.settings import EVENT_LOG_INTERVAL
from restapi.api3.models import MonthlyUserTraffic
from restapi.signals import repo_update_commit_signal
from restapi.base.accounts import User

from synserv import get_commit, get_org_id_by_repo_id
from objectstorage import commit_mgr, fs_mgr, block_mgr
from objectstorage.commit_differ import CommitDiffer

logger = logging.getLogger(__name__)

log_list = []

def log_event_to_file():
    global log_list
    if len(log_list) > 0:
        logger.info('Event information log')
        for message_entry in log_list:
            logger.info(message_entry)
    log_list *= 0
    time.sleep(EVENT_LOG_INTERVAL)
    log_event_to_file()

def handle_message(message_type, message_arr):

    global log_list
    log_list.append(message_type)
    log_list.append(message_arr)
    
    if message_type == 'syncwerk_server_daemon.stats':
        handle_stat_message(message_arr)
    
    if message_type == 'syncwerk_server_daemon.event':
        if message_arr[0] == 'repo-update':
            handle_repo_update_message(message_arr)

def handle_stat_message(message_arr):
    message_subject = message_arr[0]
    user_email = message_arr[1]
    # repo_id = message_arr[2]
    traffic_size_in_bytes = long(message_arr[3])
    current_month = date.today().strftime('%Y-%m-01')

    if user_email == '':
        return False

    try:
        existing_monthly_traffic_report = MonthlyUserTraffic.objects.get(user=user_email, month=current_month)
        if message_subject == 'web-file-upload':
            existing_monthly_traffic_report.web_file_upload += traffic_size_in_bytes
        elif message_subject == 'web-file-download':
            existing_monthly_traffic_report.web_file_download += traffic_size_in_bytes
        elif message_subject == 'sync-file-upload':
            existing_monthly_traffic_report.sync_file_upload += traffic_size_in_bytes
        elif message_subject == 'sync-file-download':
            existing_monthly_traffic_report.sync_file_download += traffic_size_in_bytes
        elif message_subject == 'link-file-upload':
            existing_monthly_traffic_report.link_file_upload += traffic_size_in_bytes
        elif message_subject == 'link-file-download':
            existing_monthly_traffic_report.link_file_download += traffic_size_in_bytes
        else:
            pass
        existing_monthly_traffic_report.save()
        
    except MonthlyUserTraffic.DoesNotExist:
        traffic_report = MonthlyUserTraffic()
        traffic_report.user = user_email
        traffic_report.month = current_month
        if message_subject == 'web-file-upload':
            traffic_report.web_file_upload = traffic_size_in_bytes
        elif message_subject == 'web-file-download':
            traffic_report.web_file_download = traffic_size_in_bytes
        elif message_subject == 'sync-file-upload':
            traffic_report.sync_file_upload = traffic_size_in_bytes
        elif message_subject == 'sync-file-download':
            traffic_report.sync_file_download = traffic_size_in_bytes
        elif message_subject == 'link-file-upload':
            traffic_report.link_file_upload = traffic_size_in_bytes
        elif message_subject == 'link-file-download':
            traffic_report.link_file_download = traffic_size_in_bytes
        else:
            pass

        traffic_report.save()


def handle_repo_update_message(elements):
    etype = 'repo-update'
    repo_id = elements[1]
    commit_id = elements[2]

    detail =  {'repo_id': repo_id,
               'commit_id': commit_id}

    commit = commit_mgr.load_commit(repo_id, 1, commit_id)
    if commit is None:
        commit = commit_mgr.load_commit(repo_id, 0, commit_id)

    # TODO: maybe handle merge commit.
    if commit is not None and commit.parent_id and not commit.second_parent_id:

        parent = commit_mgr.load_commit(repo_id, commit.version, commit.parent_id)

        if parent is not None:
            differ = CommitDiffer(repo_id, commit.version, parent.root_id, commit.root_id,
                                  True, True)

            sender = None
            try:
                sender = User.objects.get(email=commit.creator_name)
            except Exception as e:
                logger.info("Can not get user in message handle: %s"%e)

            repo_update_commit_signal.send(sender=sender, commit=commit, commit_differ=differ)
            