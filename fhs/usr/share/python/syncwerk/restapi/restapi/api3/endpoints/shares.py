import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

import synserv
from synserv import syncwerk_api, ccnet_api

from restapi.api3.utils import api_error, api_response
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.endpoints.share_links import get_share_link_info
from restapi.api3.endpoints.upload_links import _get_upload_link_info
from restapi.share.models import FileShare, UploadLinkShare
from restapi.profile.models import Profile
from restapi.utils import is_org_context, is_valid_username, send_perm_audit_msg
from restapi.base.templatetags.restapi_tags import email2nickname

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema
from restapi.api3.models import MeetingRoom, MeetingRoomShare
from restapi.api3.endpoints.admin.groups import get_group_info

class Shares(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get all shares',
        operation_description='''Get all shares of the current user''',
        tags=['shares'],
        responses={
            200: openapi.Response(
                description='List retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "share_permission": "rw",
                                "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                                "share_type": "personal",
                                "encrypted": False,
                                "user_name": "Bibbye Synnott",
                                "contact_email": "bsynnott3@artisteer.com",
                                "folder_name": "efewf",
                                "mtime": 1548673284,
                                "path": "/fefe/efewf",
                                "type": "folder",
                                "user_email": "bsynnott3@artisteer.com",
                                "size": 0
                            },
                            {
                                "username": "admin@alpha.syncwerk.com",
                                "share_permission": "w",
                                "view_cnt": 0,
                                "ctime": "2019-01-28T10:58:15+00:00",
                                "encrypted": False,
                                "mtime": 1548919504,
                                "token": "85cde770ae614d2f80b9",
                                "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                                "link": "u/d/85cde770ae614d2f80b9/",
                                "obj_name": "fefe",
                                "path": "/fefe/",
                                "size": 419577,
                                "type": "upload-link",
                                "repo_name": "My Folder"
                            },
                            {
                                "username": "admin@alpha.syncwerk.com",
                                "share_permission": "w",
                                "view_cnt": 1,
                                "ctime": "2019-02-18T07:01:50+00:00",
                                "encrypted": False,
                                "mtime": 1550461334,
                                "token": "b2e3f939706740dbae66",
                                "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                                "link": "u/d/b2e3f939706740dbae66/",
                                "obj_name": "/",
                                "path": "/",
                                "size": 0,
                                "type": "upload-link",
                                "repo_name": "test wiki 4"
                            }
                        ]
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid",
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error',
                examples={
                    'application/json': {
                        "message": "Internal server error",
                        "data": None
                    }
                }
            ),
        }
    )
    def get(self, request, format=None):

        username = request.user.username
        returned_result = []
        returned_folders = []
        shared_repos = []
        shared_folders = []
        try:
            if is_org_context(request):
                org_id = request.user.org.org_id
                shared_repos += syncwerk_api.get_org_share_out_repo_list(org_id, username, -1, -1)
                shared_repos += synserv.syncwserv_threaded_rpc.get_org_group_repos_by_owner(org_id, username)
                shared_repos += synserv.syncwserv_threaded_rpc.list_org_inner_pub_repos_by_owner(org_id, username)
            else:
                shared_repos += syncwerk_api.get_share_out_repo_list(username, -1, -1)
                shared_repos += syncwerk_api.get_group_repos_by_owner(username)
                if not request.cloud_mode:
                    shared_repos += syncwerk_api.list_inner_pub_repos_by_owner(username)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        shared_repos.sort(lambda x, y: cmp(x.repo_name, y.repo_name))
        # find all repos
        for repo in shared_repos:
            if repo.is_virtual:
                    continue

            result = {}
            result['type'] = 'repo'
            result['repo_id'] = repo.repo_id
            result['repo_name'] = repo.repo_name
            result['path'] = repo.origin_path
            result['folder_name'] = repo.name
            result['share_type'] = repo.share_type
            result['share_permission'] = repo.permission
            result['encrypted'] = repo.encrypted
            result['mtime'] = repo.last_modify
            result['size'] = repo.size

            if repo.share_type == 'personal':
                result['user_name'] = email2nickname(repo.user)
                result['user_email'] = repo.user
                result['contact_email'] = Profile.objects.get_contact_email_by_user(repo.user)

            if repo.share_type == 'group':
                group = ccnet_api.get_group(repo.group_id)
                result['group_id'] = repo.group_id
                result['group_name'] = group.group_name

            returned_result.append(result)

        # find all folders
        try:
            if is_org_context(request):
                org_id = request.user.org.org_id
                shared_folders += syncwerk_api.get_org_share_out_repo_list(org_id, username, -1, -1)
                shared_folders += synserv.syncwserv_threaded_rpc.get_org_group_repos_by_owner(org_id, username)
            else:
                shared_folders += syncwerk_api.get_share_out_repo_list(username, -1, -1)
                shared_folders += syncwerk_api.get_group_repos_by_owner(username)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        shared_folders.sort(lambda x, y: cmp(x.repo_name, y.repo_name))
        for repo in shared_folders:
            if not repo.is_virtual:
                    continue

            result = {}
            result['type'] = 'folder'
            result['repo_id'] = repo.origin_repo_id
            result['path'] = repo.origin_path
            result['folder_name'] = repo.name
            result['share_type'] = repo.share_type
            result['share_permission'] = repo.permission
            result['mtime'] = repo.last_modify
            result['size'] = repo.size
            result['encrypted'] = repo.encrypted

            if repo.share_type == 'personal':
                result['user_name'] = email2nickname(repo.user)
                result['user_email'] = repo.user
                result['contact_email'] = Profile.objects.get_contact_email_by_user(repo.user)

            if repo.share_type == 'group':
                group = ccnet_api.get_group(repo.group_id)
                result['group_id'] = repo.group_id
                result['group_name'] = group.group_name

            returned_result.append(result)

        # find all share links
        fileshares = FileShare.objects.filter(username=username)
        links_info = []
        for fs in fileshares:
            link_info = get_share_link_info(fs)
            link_info['type'] ='download-link'
            link_info['share_permission'] = 'r'
            links_info.append(link_info)

        if len(links_info) == 1:
            link_results = links_info
        else:
            dir_list = filter(lambda x: x['is_dir'], links_info)
            file_list = filter(lambda x: not x['is_dir'], links_info)

            dir_list.sort(lambda x, y: cmp(x['obj_name'], y['obj_name']))
            file_list.sort(lambda x, y: cmp(x['obj_name'], y['obj_name']))

            link_results = dir_list + file_list

        returned_result.extend(link_results)

        # find all upload links
        upload_link_shares = UploadLinkShare.objects.filter(username=username)
        for uls in upload_link_shares:
            link_info = _get_upload_link_info(uls)
            link_info['type'] ='upload-link'
            link_info['share_permission'] = 'w'
            returned_result.append(link_info)

        # fins all public share
        public_shared_meeting_rooms = MeetingRoom.objects.filter(
            owner_id=request.user.email,
            share_token__isnull=False,
        )
        for meeting_room in public_shared_meeting_rooms:
            tmp = {
                "meeting_name": meeting_room.room_name,
                "item_name": meeting_room.room_name,
                "ctime": meeting_room.created_at,
                "type": "meeting-public-share",
                "meeting_room_id": meeting_room.id,
                "share_token": meeting_room.share_token,
            }
            returned_result.append(tmp)
        # find all private meeting share
        owned_meeting_rooms = MeetingRoom.objects.filter(owner_id=request.user.email)
        for meeting_room in owned_meeting_rooms:
            share_entries = MeetingRoomShare.objects.filter(meeting_room_id=meeting_room.id)
            for share_entry in share_entries:
                if share_entry.share_type == 'SHARED_TO_USER':
                    tmp = {
                        "meeting_name": meeting_room.room_name,
                        "item_name": meeting_room.room_name,
                        "ctime": share_entry.created_at,
                        "share_to": share_entry.share_to_user,
                        "share_type": share_entry.share_type,
                        "type": "meeting-private-share",
                        "share_entry_id": share_entry.id,
                        "meeting_room_id": meeting_room.id,
                    }
                    returned_result.append(tmp)

                elif share_entry.share_type == 'SHARED_TO_GROUP':
                    group_info = get_group_info(share_entry.group_id)
                    tmp = {
                        "meeting_name": meeting_room.room_name,
                        "item_name": meeting_room.room_name,
                        "ctime": share_entry.created_at,
                        "share_to": group_info["name"],
                        "share_type": share_entry.share_type,
                        "type": "meeting-private-share",
                        "share_entry_id": share_entry.id,
                        "meeting_room_id": meeting_room.id,
                    }
                    returned_result.append(tmp)

        return api_response(data=returned_result)
