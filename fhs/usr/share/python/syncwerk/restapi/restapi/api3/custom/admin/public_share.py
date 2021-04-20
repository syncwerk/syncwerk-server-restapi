import os
import logging

from synserv import syncwerk_api, ccnet_api

from django.utils.translation import ugettext as _

from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser

from restapi.share.models import FileShare, UploadLinkShare
from restapi.profile.models import Profile
from restapi.utils.timeutils import timestamp_to_isoformat_timestr

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response
from restapi.api3.endpoints.share_links import get_share_link_info
from restapi.api3.endpoints.upload_links import _get_upload_link_info
from restapi.api3.models import CcnetUser
from restapi.api3.models import MeetingRoom, MeetingRoomShare

from restapi.base.templatetags.restapi_tags import email2nickname
from restapi.api3.endpoints.admin.groups import get_group_info

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class AdminPublicShare(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - List all shares',
        operation_description='''List all shares''',
        tags=['admin-shares'],
        responses={
            200: openapi.Response(
                description='Shares retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "shares": [
                                {
                                    "username": "admin@alpha.syncwerk.com",
                                    "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                                    "ctime": "2019-02-20T03:06:50+00:00",
                                    "share_type": "public_download",
                                    "mtime": 1550650345,
                                    "expire_date": "",
                                    "token": "88bce88084aa42f4a40c",
                                    "view_cnt": 7,
                                    "link": "f/88bce88084aa42f4a40c/",
                                    "size": 1160017,
                                    "obj_name": "fewhfewf.csv",
                                    "path": "/fewhfewf.csv",
                                    "is_dir": False,
                                    "permissions": {
                                        "can_edit": False,
                                        "can_download": True
                                    },
                                    "is_expired": False,
                                    "encrypted": False,
                                    "repo_name": "My Folder"
                                },
                                {
                                    "username": "admin@alpha.syncwerk.com",
                                    "view_cnt": 1,
                                    "ctime": "2019-02-18T07:01:50+00:00",
                                    "share_type": "public_upload",
                                    "encrypted": False,
                                    "mtime": 1550461334,
                                    "token": "b2e3f939706740dbae66",
                                    "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                                    "link": "u/d/b2e3f939706740dbae66/",
                                    "obj_name": "/",
                                    "path": "/",
                                    "size": 0,
                                    "repo_name": "test wiki 4"
                                },
                                {
                                    "share_permission": "rw",
                                    "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                                    "ctime": "2019-02-18T03:42:14+00:00",
                                    "share_type": "personal",
                                    "encrypted": False,
                                    "user_name": "Bibbye Synnott",
                                    "contact_email": "bsynnott3@artisteer.com",
                                    "folder_name": "test wiki 4",
                                    "mtime": 1550461334,
                                    "owner": "admin@alpha.syncwerk.com",
                                    "path": "/",
                                    "size": 0,
                                    "type": "repo",
                                    "user_email": "bsynnott3@artisteer.com",
                                    "repo_name": "test wiki 4"
                                },
                                {
                                    "share_permission": "rw",
                                    "repo_id": "bb966ac2-ec76-4940-96fa-7e0fdec41a32",
                                    "ctime": "2019-02-19T08:42:59+00:00",
                                    "share_type": "group",
                                    "encrypted": False,
                                    "group_name": "3",
                                    "folder_name": "fefefe",
                                    "mtime": 1550565779,
                                    "owner": "admin@alpha.syncwerk.com",
                                    "path": "/",
                                    "size": 0,
                                    "type": "repo",
                                    "group_id": 3,
                                    "repo_name": "fefefe"
                                }
                            ]
                        }
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
    def get(self, request):
        download_links = FileShare.objects.all().order_by('-ctime')
        shares = []
        pub_links = []
        for l in download_links:
            if l.is_file_share_link():
                l.name = os.path.basename(l.path)
            else:
                l.name = os.path.dirname(l.path)
            link_info = get_share_link_info(l)
            link_info['share_type'] = "public_download"
            pub_links.append(link_info)
            shares.append(link_info)

        upload_links = UploadLinkShare.objects.all().order_by('-ctime')
        for l in upload_links:
            link_info = _get_upload_link_info(l)
            link_info['share_type'] = "public_upload"
            pub_links.append(link_info)
            shares.append(link_info)
        # Loop through all the user in the system and list all the share of them
        all_users = CcnetUser.objects.all()

        for user in all_users:
            # find all repo share
            shared_repos = []
            try:
                shared_repos += syncwerk_api.get_share_out_repo_list(user.email, -1, -1)
                shared_repos += syncwerk_api.get_group_repos_by_owner(user.email)
                if not request.cloud_mode:
                    shared_repos += syncwerk_api.list_inner_pub_repos_by_owner(user.email)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(500, error_msg)

            for repo in shared_repos:
                if repo.is_virtual:
                    continue

                result = {}
                result['type'] = 'repo'
                result['repo_id'] = repo.repo_id
                result['repo_name'] = repo.repo_name
                result['path'] = repo.origin_path if repo.origin_path != None else '/'
                result['folder_name'] = repo.name
                result['share_type'] = repo.share_type
                result['share_permission'] = repo.permission
                result['encrypted'] = repo.encrypted
                result['mtime'] = repo.last_modify
                result['ctime'] = timestamp_to_isoformat_timestr(repo.last_modify)
                result['size'] = repo.size
                result['owner'] = user.email

                if repo.share_type == 'personal':
                    result['user_name'] = email2nickname(repo.user)
                    result['user_email'] = repo.user
                    result['contact_email'] = Profile.objects.get_contact_email_by_user(
                        repo.user)

                if repo.share_type == 'group':
                    group = ccnet_api.get_group(repo.group_id)
                    result['group_id'] = repo.group_id
                    result['group_name'] = group.group_name

                shares.append(result)
            
            # find all folders
            shared_folders = []
            try:
                shared_folders += syncwerk_api.get_share_out_repo_list(user.email, -1, -1)
                shared_folders += syncwerk_api.get_group_repos_by_owner(user.email)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(500, error_msg)

            shared_folders.sort(lambda x, y: cmp(x.repo_name, y.repo_name))
            for repo in shared_folders:
                if not repo.is_virtual:
                        continue

                result = {}
                result['type'] = 'folder'
                result['repo_id'] = repo.origin_repo_id
                result['path'] = repo.origin_path if repo.origin_path != None else '/'
                result['folder_name'] = repo.name
                result['share_type'] = repo.share_type
                result['share_permission'] = repo.permission
                result['mtime'] = repo.last_modify
                result['ctime'] = timestamp_to_isoformat_timestr(repo.last_modify)
                result['size'] = repo.size
                result['encrypted'] = repo.encrypted
                result['owner'] = user.email
                
                if repo.share_type == 'personal':
                    result['user_name'] = email2nickname(repo.user)
                    result['user_email'] = repo.user
                    result['contact_email'] = Profile.objects.get_contact_email_by_user(repo.user)

                if repo.share_type == 'group':
                    group = ccnet_api.get_group(repo.group_id)
                    result['group_id'] = repo.group_id
                    result['group_name'] = group.group_name

                shares.append(result)
            
            # find all public meeting share
            public_shared_meeting_rooms = MeetingRoom.objects.filter(
                owner_id=user.email,
                share_token__isnull=False,
            )
            for meeting_room in public_shared_meeting_rooms:
                tmp = {
                    "meeting_name": meeting_room.room_name,
                    "repo_name": meeting_room.room_name, # Workaround for 1307
                    "ctime": meeting_room.created_at,
                    "share_type": "meeting-public-share",
                    "meeting_room_id": meeting_room.id,
                    "share_token": meeting_room.share_token,
                    "room_owner": meeting_room.owner_id
                }
                shares.append(tmp)

            # find all private meeting share
            owned_meeting_rooms = MeetingRoom.objects.filter(owner_id=user.email)
            for meeting_room in owned_meeting_rooms:
                share_entries = MeetingRoomShare.objects.filter(meeting_room_id=meeting_room.id)
                for share_entry in share_entries:
                    if share_entry.share_type == 'SHARED_TO_USER':
                        tmp = {
                            "meeting_name": meeting_room.room_name,
                            "repo_name": meeting_room.room_name, # Workaround for 1307
                            "ctime": share_entry.created_at,
                            "share_to": share_entry.share_to_user,
                            "room_share_type": share_entry.share_type,
                            "share_type": "meeting-private-share",
                            "share_entry_id": share_entry.id,
                            "meeting_room_id": meeting_room.id,
                            "room_owner": meeting_room.owner_id,
                        }
                        shares.append(tmp)

                    elif share_entry.share_type == 'SHARED_TO_GROUP':
                        group_info = get_group_info(share_entry.group_id)
                        tmp = {
                            "meeting_name": meeting_room.room_name,
                            "repo_name": meeting_room.room_name, # Workaround for 1307
                            "ctime": share_entry.created_at,
                            "share_to": group_info["name"],
                            "room_share_type": share_entry.share_type,
                            "share_type": "meeting-private-share",
                            "share_entry_id": share_entry.id,
                            "meeting_room_id": meeting_room.id,
                            "room_owner": meeting_room.owner_id,
                        }
                        shares.append(tmp)

        return api_response(code=200, data={
            'shares': shares,
        })


class PublicShares(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - List all public share links',
        operation_description='''List all public share links''',
        tags=['admin-shares'],
        responses={
            200: openapi.Response(
                description='Shares retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "pub_links": [
                                {
                                    "username": "admin@alpha.syncwerk.com",
                                    "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                                    "type": "download",
                                    "ctime": "2019-02-20T03:06:50+00:00",
                                    "mtime": 1550650345,
                                    "expire_date": "",
                                    "token": "88bce88084aa42f4a40c",
                                    "view_cnt": 7,
                                    "link": "f/88bce88084aa42f4a40c/",
                                    "size": 1160017,
                                    "obj_name": "fewhfewf.csv",
                                    "path": "/fewhfewf.csv",
                                    "is_dir": False,
                                    "permissions": {
                                        "can_edit": False,
                                        "can_download": True
                                    },
                                    "is_expired": False,
                                    "encrypted": False,
                                    "repo_name": "My Folder"
                                },
                                {
                                    "username": "admin@alpha.syncwerk.com",
                                    "view_cnt": 9,
                                    "ctime": "2019-01-22T11:04:13+00:00",
                                    "encrypted": False,
                                    "mtime": 1550650345,
                                    "token": "317861b41c8d475cbc7d",
                                    "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                                    "link": "u/d/317861b41c8d475cbc7d/",
                                    "obj_name": "/",
                                    "path": "/",
                                    "size": 1160017,
                                    "type": "upload",
                                    "repo_name": "My Folder"
                                }
                            ]
                        }
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
    def get(self, request):
        download_links = FileShare.objects.all().order_by('-ctime')
        pub_links = []
        for l in download_links:
            if l.is_file_share_link():
                l.name = os.path.basename(l.path)
            else:
                l.name = os.path.dirname(l.path)
            link_info = get_share_link_info(l)
            link_info['type'] = "download"
            pub_links.append(link_info)

        upload_links = UploadLinkShare.objects.all().order_by('-ctime')
        for l in upload_links:
            link_info = _get_upload_link_info(l)
            link_info['type'] = "upload"
            pub_links.append(link_info)

        return api_response(code=200, data={
            'pub_links': pub_links
        })


class AdminDownloadLink(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Remove public download link',
        operation_description='''Remove public download link''',
        tags=['admin-shares'],
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_="path",
                type='string',
                description='share link token',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Download link removed successfully',
                examples={
                    'application/json': {
                        "message": "Download link removed successfully",
                        "data": None
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
    def delete(self, request, token):
        FileShare.objects.filter(token=token).delete()
        return api_response(code=200, msg=_('Remove download link successfully.'))


class AdminUploadLink(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Remove public upload link',
        operation_description='''Remove public upload link''',
        tags=['admin-shares'],
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_="path",
                type='string',
                description='share link token',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Upload link removed successfully',
                examples={
                    'application/json': {
                        "message": "Upload link removed successfully",
                        "data": None
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
    def delete(self, request, token):
        UploadLinkShare.objects.filter(token=token).delete()
        return api_response(code=200, msg=_('Remove upload link successfully.'))
