# Copyright (c) 2012-2016 Seafile Ltd.
# -*- coding: utf-8 -*-
import logging

import synserv
from synserv import syncwerk_api, ccnet_api

from restapi.utils import EMPTY_SHA1, is_org_context, is_pro_version
from restapi.base.models import RepoSecretKey
from restapi.base.templatetags.restapi_tags import email2nickname

from restapi.settings import ENABLE_STORAGE_CLASSES, \
        STORAGE_CLASS_MAPPING_POLICY, ENABLE_FOLDER_PERM

logger = logging.getLogger(__name__)

def list_dir_by_path(cmmt, path):
    if cmmt.root_id == EMPTY_SHA1:
        return []
    else:
        dirs = syncwerk_api.list_dir_by_commit_and_path(cmmt.repo_id, cmmt.id, path)
        return dirs if dirs else []

def get_sub_repo_abbrev_origin_path(repo_name, origin_path):
    """Return abbrev path for sub repo based on `repo_name` and `origin_path`.

    Arguments:
    - `repo_id`:
    - `origin_path`:
    """
    if len(origin_path) > 20:
        abbrev_path = origin_path[-20:]
        return repo_name + '/...' + abbrev_path
    else:
        return repo_name + origin_path

def get_repo_owner(request, repo_id):
    if is_org_context(request):
        repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
    else:
        # for admin panel
        # administrator may get org repo's owner
        repo_owner = syncwerk_api.get_repo_owner(repo_id)
        if not repo_owner:
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)

    return repo_owner

def is_repo_owner(request, repo_id, username):
    return username == get_repo_owner(request, repo_id)

def get_repo_shared_users(repo_id, repo_owner, include_groups=True):
    """Return a list contains users and group users. Repo owner is ommited.
    """
    ret = []
    users = syncwerk_api.list_repo_shared_to(repo_owner, repo_id)
    ret += [x.user for x in users]
    if include_groups:
        for e in syncwerk_api.list_repo_shared_group_by_user(repo_owner, repo_id):
            g_members = synserv.get_group_members(e.group_id)
            ret += [x.user_name for x in g_members if x.user_name != repo_owner]

    return list(set(ret))

def get_library_storages(request):
    """ Return info of storages can be used.

    1. If not enable user role feature OR
       haven't configured `storage_ids` option in user role setting:

       Return storage info getted from syncwerk_api.
       And always put the default storage as the first item in the returned list.

    2. If have configured `storage_ids` option in user role setting:

       Only return storage info in `storage_ids`.
       Filter out the wrong stotage id(s).
       Not change the order of the `storage_ids` list.
    """

    if not is_pro_version():
        return []

    if not ENABLE_STORAGE_CLASSES:
        return []

    # get all storages info
    try:
        storage_classes = syncwerk_api.get_all_storage_classes()
    except Exception as e:
        logger.error(e)
        return []

    all_storages = []
    for storage in storage_classes:
        storage_info = {
            'storage_id': storage.storage_id,
            'storage_name': storage.storage_name,
            'is_default': storage.is_default,
        }
        if storage.is_default:
            all_storages.insert(0, storage_info)
        else:
            all_storages.append(storage_info)

    if STORAGE_CLASS_MAPPING_POLICY == 'USER_SELECT':

        return all_storages

    elif STORAGE_CLASS_MAPPING_POLICY == 'ROLE_BASED':
        user_role_storage_ids = request.user.permissions.storage_ids()
        if not user_role_storage_ids:
            return []

        user_role_storages = []
        for user_role_storage_id in user_role_storage_ids:
            for storage in all_storages:
                if storage['storage_id'] == user_role_storage_id:
                    user_role_storages.append(storage)
                    continue

        return user_role_storages

    else:
        # STORAGE_CLASS_MAPPING_POLICY == 'REPO_ID_MAPPING'
        return []

def get_locked_files_by_dir(request, repo_id, folder_path):
    """ Get locked files in a folder

    Returns:
        A dict contains locked file name and locker owner.

        locked_files = {
            'file_name': 'lock_owner';
            ...
        }
    """

    username = request.user.username

    # get lock files
    dir_id = syncwerk_api.get_dir_id_by_path(repo_id, folder_path)
    dirents = syncwerk_api.list_dir_with_perm(repo_id,
            folder_path, dir_id, username, -1, -1)

    locked_files = {}
    for dirent in dirents:
        if dirent.is_locked:
            locked_files[dirent.obj_name] = dirent.lock_owner

    return locked_files

def get_shared_groups_by_repo(repo_id, org_id=None):
    if not org_id:
        group_ids = syncwerk_api.get_shared_group_ids_by_repo(
                repo_id)
    else:
        group_ids = syncwerk_api.org_get_shared_group_ids_by_repo(org_id,
                repo_id)

    if not group_ids:
        return []

    groups = []
    for group_id in group_ids:
        group = ccnet_api.get_group(int(group_id))
        if group:
            groups.append(group)

    return groups

def get_related_users_by_repo(repo_id, org_id=None):
    """ Return all users who can view this library.

    1. repo owner
    2. users repo has been shared to
    3. members of groups repo has been shared to
    """

    users = []

    if org_id:
        repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
        user_shared_to = syncwerk_api.list_org_repo_shared_to(org_id,
                repo_owner, repo_id)
    else:
        repo_owner = syncwerk_api.get_repo_owner(repo_id)
        user_shared_to = syncwerk_api.list_repo_shared_to(
                repo_owner, repo_id)

    # 1. repo owner
    users.append(repo_owner)

    # 2. users repo has been shared to
    for user in user_shared_to:
        users.append(user.user)

    # 3. members of groups repo has been shared to
    groups = get_shared_groups_by_repo(repo_id, org_id)
    for group in groups:
        members = ccnet_api.get_group_members(group.id)
        for member in members:
            if member.user_name not in users:
                users.append(member.user_name)

    return users

# TODO
def is_valid_repo_id_format(repo_id):
    return len(repo_id) == 36

def can_set_folder_perm_by_user(username, repo, repo_owner):
    """ user can get/update/add/delete folder perm feature must comply with the following
            setting: ENABLE_FOLDER_PERM
            repo:repo is not virtual
            permission: is admin or repo owner.
    """
    if not ENABLE_FOLDER_PERM:
        return False
    if repo.is_virtual:
        return False
    is_admin = is_repo_admin(username, repo.id)
    if username != repo_owner and not is_admin:
        return False
    return True

def add_encrypted_repo_secret_key_to_database(repo_id, password):
    try:
        if not RepoSecretKey.objects.get_secret_key(repo_id):
            # get secret_key, then save it to database
            secret_key = syncwerk_api.get_secret_key(repo_id, password)
            RepoSecretKey.objects.add_secret_key(repo_id, secret_key)
    except Exception as e:
        logger.error(e)


def is_group_repo_staff(repo_id, username):
    is_staff = False

    group_repo_owner = syncwerk_api.get_repo_owner(repo_id)

    if '@syncwerk_group' in group_repo_owner:
        group_id = email2nickname(group_repo_owner)
        is_staff = synserv.check_group_staff(group_id, username)

    return is_staff

# TODO
from restapi.share.utils import is_repo_admin
