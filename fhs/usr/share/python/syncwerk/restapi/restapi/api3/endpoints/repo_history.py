import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response
from restapi.api3.models import SharedRepo

from restapi.api3.custom.repo_history_changes import get_diff

from restapi.profile.models import Profile
from restapi.base.templatetags.restapi_tags import email2nickname
from restapi.options.models import UserOptions, CryptoOptionNotSetError
from restapi.utils.timeutils import timestamp_to_isoformat_timestr
from restapi.utils import new_merge_with_no_conflict
from restapi.views import check_folder_permission

from restapi.base.templatetags.restapi_tags import translate_commit_desc

import synserv
from synserv import syncwerk_api

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)

class RepoHistory(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def get_item_info(self, commit):
        email = commit.creator_name
        item_info = {
            "name": email2nickname(email),
            "contact_email": Profile.objects.get_contact_email_by_user(email),
            'email': email,
            'time': timestamp_to_isoformat_timestr(commit.ctime),
            'description': commit.desc,
            'commit_id': commit.id,
            'client_version': commit.client_version,
            'device_name': commit.device_name
        }

        return item_info

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get folder histories',
        operation_description='''Get all history snapshots of a folder''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
        ],
        responses={
            200: openapi.Response(
                description='History retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "allow_view_snapshot": True,
                            "allow_view_history": True,
                            "allow_restore_snapshot": True,
                            "repo_name": "My Folder",
                            "more": False,
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "total_number_of_commits": 14,
                            "permission": "rw",
                            "commits": [
                                {
                                    "commit_id": "dea792528ff1f28d0130954071cecf4423e6cf39",
                                    "contact_email": "admin@alpha.syncwerk.com",
                                    "name": "admin",
                                    "time": "2019-02-19T02:09:43+00:00",
                                    "details": {
                                        "renamed": [],
                                        "deldir": [],
                                        "modified": [],
                                        "newdir": [
                                            "frtgr"
                                        ],
                                        "new": [],
                                        "removed": []
                                    },
                                    "client_version": None,
                                    "device_name": None,
                                    "email": "admin@alpha.syncwerk.com",
                                    "number_of_changes": 1,
                                    "description": "Added directory \"frtgr\""
                                },
                                {
                                    "commit_id": "1a0a1abcc18468a0166b67a7b167144670569a1f",
                                    "contact_email": "admin@alpha.syncwerk.com",
                                    "name": "admin",
                                    "time": "2019-01-31T07:25:04+00:00",
                                    "details": {
                                        "renamed": [],
                                        "deldir": [],
                                        "modified": [],
                                        "newdir": [],
                                        "new": [
                                            "fefe/something_by_omegaswallow-dbh8mfq.png"
                                        ],
                                        "removed": []
                                    },
                                    "client_version": None,
                                    "device_name": None,
                                    "email": "admin@alpha.syncwerk.com",
                                    "number_of_changes": 1,
                                    "description": "Added \"something_by_omegaswallow-dbh8mfq.png\"."
                                },
                            ]
                        }
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid",
                    }
                }
            ),
            403: openapi.Response(
                description='Operation not permitted',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            404: openapi.Response(
                description='Folder not found',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
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
    def get(self, request, repo_id, format=None):
    
        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        permission = check_folder_permission(request, repo_id, '/')
        if permission is None:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        username = request.user.username
        try:
            server_crypto = UserOptions.objects.is_server_crypto(username)
        except CryptoOptionNotSetError:
            # Assume server_crypto is ``False`` if this option is not set.
            server_crypto = False

        password_set = False
        if repo.encrypted and \
                (repo.enc_version == 1 or (repo.enc_version == 2 and server_crypto)):
            try:
                ret = syncwerk_api.is_password_set(repo_id, username)
                if ret == 1:
                    password_set = True
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            if not password_set:
                error_msg = 'Library is encrypted, but password is not set in server.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        try:
            page = int(request.GET.get('page', '1'))
            per_page = int(request.GET.get('per_page', '100'))
        except ValueError:
            page = 1
            per_page = 100

        if page <= 0:
            error_msg = 'page invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if per_page == 0:
            error_msg = 'per_page invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        start = (page - 1) * per_page
        limit = per_page + 1

        if per_page == -1:
            start = -1
            limit = -1
        try:
            all_commits = syncwerk_api.get_commit_list(repo_id, -1, -1)
            number_of_all_commits = len(syncwerk_api.get_commit_list(repo_id, -1, -1))
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        items = []
        commits = all_commits[:per_page]
        for commit in commits:
            if new_merge_with_no_conflict(commit):
                continue

            item_info = self.get_item_info(commit)
            changes = get_diff(repo_id, '', commit.id)
            item_info['number_of_changes'] = len(changes['new']) + len(changes['removed']) + len(changes['renamed']) +len(changes['modified']) +len(changes['newdir']) +len(changes['deldir'])
            item_info['details'] = changes
            item_info['description'] = translate_commit_desc(item_info['description'])
            items.append(item_info)
        
        result = {
            'repo_id': repo.id,
            'repo_name': repo.name,
            'commits': items,
            'total_number_of_commits': len(items),
            'permission': permission,
            'more': True if len(all_commits) == per_page + 1 else False
        }

        # Check history permission
        if request.user.email == syncwerk_api.get_repo_owner(repo.id):
            result['allow_view_history'] = True
            result['allow_view_snapshot'] = True
            result['allow_restore_snapshot'] = True
        else:
            try:
                share_item = SharedRepo.objects.using('syncwerk-server').get(repo_id=repo.repo_id,from_email=syncwerk_api.get_repo_owner(repo.id),to_email=request.user.email)
                result['allow_view_history'] = share_item.allow_view_history
                result['allow_view_snapshot'] = share_item.allow_view_snapshot
                result['allow_restore_snapshot'] = share_item.allow_restore_snapshot
            except Exception as e:
                result['allow_view_history'] = True
                result['allow_view_snapshot'] = False
                result['allow_restore_snapshot'] = False

        # return Response(result)
        return api_response(data=result)
