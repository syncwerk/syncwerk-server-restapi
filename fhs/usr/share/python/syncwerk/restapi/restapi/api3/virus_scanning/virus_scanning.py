import threading
import time
import tempfile
import os
import subprocess
import logging
import shutil

from objectstorage import commit_mgr, fs_mgr, block_mgr

from objectstorage.commit_differ import CommitDiffer

from synserv import syncwserv_threaded_rpc, syncwerk_api, get_repo

from django.core.management.base import BaseCommand
from django.utils import timezone

from restapi import settings
from restapi.utils import send_html_email
from restapi.base.accounts import User

from restapi.api3.models import VirusScannedHeader, VirusScanningInfectedFile
from restapi.syncwerk_server_models.models import FolderBranch

# logger = logging.basicConfig(filename='/var/log/syncwerk/virusscan.log')

logger = logging.getLogger(__name__)

virus_log_handler = logging.FileHandler('/var/log/syncwerk/virusscan.log')
virus_log_handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
virus_log_handler.setFormatter(formatter)

logger.addHandler(virus_log_handler)

# This variable must be cleaned after each scan
list_of_infected_files = []

def send_infected_file_list_to_admin():
    """Notify admins when an api throttle happen"""
    admins = User.objects.get_superusers()
    admin_emails = []
    for admin in admins:
        admin_emails.append(admin.email)
    c = {
        'infected_files': list_of_infected_files,
        }
    send_html_email('Virus Detected',
            'api3/sysadmin/virus_detected_files.html', c, None, admin_emails)

def get_file_ext(file_path):
    path_arr = file_path.split('/')
    file_name = path_arr[len(path_arr) - 1]
    file_name_arr = file_name.split('.')
    file_ext = file_name_arr[len(file_name_arr) - 1]
    return file_ext

def check_if_file_should_be_scanned(file_obj):
    # Check size
    if file_obj.size > settings.VIRUS_SCAN_FILE_SIZE_LIMIT:
        return False
    # Check ext
    file_ext = get_file_ext(file_obj.path)
    if file_ext in settings.VIRUS_SCAN_SKIP_EXT:
        return False
    return True

def scan_file(file_obj, repo_details, repo_owner, commit_id):
    if check_if_file_should_be_scanned(file_obj) is False:
        logger.info('Skipping...')
        logger.info(repo_details.name)
        logger.info(file_obj.path)
        return 0
    else:
        try:
            logger.info('Scanning...')
            logger.info(repo_details.name)
            logger.info(file_obj.path)
            temp_fd, temp_path = tempfile.mkstemp()
            syncw_file = fs_mgr.load_syncwerk(repo_details.id, 1, file_obj.obj_id)
            for block in syncw_file.blocks:
                os.write(temp_fd, block_mgr.load_block(repo_details.id, 1, block))

            with open(os.devnull, 'w') as devnull:
                result_code = subprocess.call([settings.VIRUS_SCAN_COMMAND, temp_path],
                                                stdout=devnull, stderr=devnull)
            if result_code in settings.VIRUS_SCAN_RESULT_INFECTED_CODE:
                logger.info('Virus detected!')
                logger.info('Folder id: ' + repo_details.id)
                logger.info('Folder name: ' + repo_details.name)
                logger.info('Commit id: ' + commit_id)
                logger.info('Path of infected file: '+ file_obj.path)
                # # Check if there is the same record in the infected files already
                # existing_infected_files = VirusScanningInfectedFile.objects.filter(is_handled=False, repo_id=repo_id, path=file_obj.path)
                # if len(existing_infected_files <= 0):
                # Create record in infected files table
                infected_file = VirusScanningInfectedFile()
                infected_file.infected_file_path = file_obj.path
                infected_file.repo_id = repo_details.id
                infected_file.commit_id = commit_id
                infected_file.is_handled = False
                infected_file.save()
                list_of_infected_files.append({
                    'folder_id': repo_details.id,
                    'folder_name': repo_details.name,
                    'folder_owner': repo_owner,
                    'commit_id': commit_id,
                    'infected_file_path': file_obj.path,
                    'detected_at': timezone.now
                })
        except Exception as e:
            pass
        finally:
            if temp_fd > 0:
                os.close(temp_fd)
                os.unlink(temp_path)

def scan_folder(repo_id, commit_id):
    list_file_to_scan = []
    file_scan_result = 0
    scan_root_id = '0000000000000000000000000000000000000000'
    current_head_root_id = '0000000000000000000000000000000000000000'
    scanned_header = None
    try:
        scanned_header = VirusScannedHeader.objects.get(repo_id=repo_id)
        if scanned_header.scanned_head_id == commit_id:
            # No need for scanning the folder
            return []
        else:
            #   if commit_id == '66290c5fd7ff86bd7d18481cad6a84672a07e696':
            # test = 'a56328551ff2c5aa5c992caa511ba539e67b3d39'
            scan_root_id = commit_mgr.get_commit_root_id(scanned_header.repo_id, 1, scanned_header.scanned_head_id)
            current_head_root_id = commit_mgr.get_commit_root_id(repo_id, 1, commit_id)
    except Exception:
        scanned_header = None
        current_head_root_id = commit_mgr.get_commit_root_id(repo_id, 1, commit_id)
    commit_differ_obj = CommitDiffer(repo_id, 1, scan_root_id, current_head_root_id)
    diffs = commit_differ_obj.diff()
    list_file_to_scan = diffs[0] + diffs[4]
    if len(list_file_to_scan) == 0:
        pass
    else:
        repo_details = get_repo(repo_id)
        repo_owner = syncwerk_api.get_repo_owner(repo_id)
        # Do the scanning
        for file_obj in list_file_to_scan:
            file_scan_result = scan_file(file_obj, repo_details, repo_owner, commit_id)
            if file_scan_result == -1:
                break
    # Update the scanned table
    if scanned_header is None:
        new_scanned_record = VirusScannedHeader()
        new_scanned_record.repo_id = repo_id
        new_scanned_record.scanned_head_id = commit_id
        new_scanned_record.save()
    else:
        scanned_header.scanned_head_id = commit_id
        scanned_header.save()

def check_virus_scanning_ready():
    if len(settings.VIRUS_SCAN_CHECK_SCAN_COMMAND_READY) == 0:
        return True
    for check_command in settings.VIRUS_SCAN_CHECK_SCAN_COMMAND_READY:
        logger.info('Running check of "%s"' % check_command)
        check_ready_cmd = check_command.split(' ')
        check_process = subprocess.Popen(check_ready_cmd)
        check_process.communicate()[0]
        logger.info('Check return status code: %d' % check_process.returncode)
        if not check_process.returncode == 0:
            return False
    return True

def start_virus_scanning(log_to_console=False):
    if log_to_console:
        console_log_handler = logging.StreamHandler()
        console_log_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_log_handler.setFormatter(console_formatter)
        logger.addHandler(console_log_handler)
    # Check if lock file is existed
    if os.path.isfile(settings.VIRUS_SCAN_LOCK_FILE):
        logger.info('Another virus scanning process is currently taking place')
        logger.info('If you are sure there is no virus scanning process is running, you can remove %s' % (settings.VIRUS_SCAN_LOCK_FILE))
    
    else:
        if not check_virus_scanning_ready():
            logger.error('Virus scanning program is not ready')
            logger.error('Virus scanning will not run this time')
            return
        try:
            # Creating lock file
            open(settings.VIRUS_SCAN_LOCK_FILE, 'a').close()
            logger.info('Virus scanning is starting')
            all_folders = FolderBranch.objects.all()
            for folder in all_folders:
                scan_folder(folder.repo_id, folder.commit_id)
            # Send email to admin if len(list_of_infected_files) > 0
            if len(list_of_infected_files) > 0:
                send_infected_file_list_to_admin()
                del list_of_infected_files[:]
            # Remove lock file to signal that the scan is now complete.
            os.remove(settings.VIRUS_SCAN_LOCK_FILE)
        except Exception as e:
            logger.error(e)
            logger.error('Failed to create lock file at %s' % settings.VIRUS_SCAN_LOCK_FILE)
            logger.error('Virus scanning will not run this time')
            logger.error('Trying to remove lock file if there is any')
            os.remove(settings.VIRUS_SCAN_LOCK_FILE)
        