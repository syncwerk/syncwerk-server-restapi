# Copyright (c) 2012-2016 Seafile Ltd.
import logging
import re

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.template.defaultfilters import filesizeformat
from django.utils.translation import ugettext as _
from pyrpcsyncwerk import RpcsyncwerkError
import synserv
from synserv import ccnet_api, syncwerk_api, syncwserv_threaded_rpc

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response
from restapi.base.accounts import User
from restapi.signals import repo_deleted, repo_update_signal
from restapi.api3.constants import EventLogActionType
from restapi.views import get_system_default_repo_id
from restapi.admin_log.signals import admin_operation
from restapi.admin_log.models import REPO_CREATE, REPO_DELETE, REPO_TRANSFER
from constance import config

from restapi.base.templatetags.restapi_tags import email2nickname
from restapi.utils.timeutils import timestamp_to_isoformat_timestr
from restapi.profile.models import Profile

try:
    from restapi.settings import MULTI_TENANCY
except ImportError:
    MULTI_TENANCY = False

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema


logger = logging.getLogger(__name__)

_REPO_ID_PATTERN = re.compile(r'[-0-9a-f]{36}')

def get_repo_info(repo):

    repo_owner = syncwerk_api.get_repo_owner(repo.repo_id)
    if not repo_owner:
        try:
            org_repo_owner = syncwerk_api.get_org_repo_owner(repo.repo_id)
        except Exception:
            org_repo_owner = None

    result = {}
    result['id'] = repo.repo_id
    result['name'] = repo.repo_name
    result['owner'] = repo_owner or org_repo_owner
    result['size'] = repo.size
    result['size_formatted'] = filesizeformat(repo.size)
    result['encrypted'] = repo.encrypted
    result['file_count'] = repo.file_count
    result['description'] = repo.desc

    return result


class AdminLibraries(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)
    parser_classes = (parsers.JSONParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get all folders',
        operation_description='''Get all folders in the system''',
        tags=['admin-folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='name',
                in_="query",
                type='string',
                description='name for serching folders',
            ),
            openapi.Parameter(
                name='owner',
                in_="query",
                type='string',
                description='owner for serching folders',
            ),
        ],
        responses={
            200: openapi.Response(
                description='List retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "page_info": {
                                "current_page": 1,
                                "has_next_page": False
                            },
                            "repos": [
                                {
                                    "name": "test wiki",
                                    "encrypted": False,
                                    "description": "",
                                    "file_count": 1,
                                    "owner": "admin@alpha.syncwerk.com",
                                    "size_formatted": "37\u00a0bytes",
                                    "id": "32c13cd4-3752-46bc-b1cf-cff4d50a671f",
                                    "size": 37
                                },
                                {
                                    "name": "test111",
                                    "encrypted": False,
                                    "description": "",
                                    "file_count": 3,
                                    "owner": "admin@alpha.syncwerk.com",
                                    "size_formatted": "17\u00a0bytes",
                                    "id": "3935599b-e3d8-4068-8e3c-b0f4e6e03ba3",
                                    "size": 17
                                },
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
            403: openapi.Response(
                description='Operation not permitted',
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
    def get(self, request, format=None):
        # search libraries (by name/owner)
        repo_name = request.GET.get('name', '')
        owner = request.GET.get('owner', '')
        repos = []
        if repo_name and owner:
            # search by name and owner
            owned_repos = syncwerk_api.get_owned_repo_list(owner)
            for repo in owned_repos:
                if not repo.name or repo.is_virtual:
                    continue

                if repo_name in repo.name:
                    repo_info = get_repo_info(repo)
                    repos.append(repo_info)

            # return Response({"name": repo_name, "owner": owner, "repos": repos})
            resp = {"name": repo_name, "owner": owner, "repos": repos}
            return api_response(data=resp)

        elif repo_name:
            # search by name(keyword in name)
            repos_all = syncwerk_api.get_repo_list(-1, -1)
            for repo in repos_all:
                if not repo.name or repo.is_virtual:
                    continue

                if repo_name in repo.name:
                    repo_info = get_repo_info(repo)
                    repos.append(repo_info)

            # return Response({"name": repo_name, "owner": '', "repos": repos})
            resp = {"name": repo_name, "owner": '', "repos": repos}
            return api_response(data=resp)

        elif owner:
            # search by owner
            owned_repos = syncwerk_api.get_owned_repo_list(owner)
            for repo in owned_repos:
                if repo.is_virtual:
                    continue

                repo_info = get_repo_info(repo)
                repos.append(repo_info)

            # return Response({"name": '', "owner": owner, "repos": repos})
            resp = {"name": '', "owner": owner, "repos": repos}
            return api_response(data=resp)

        # temp fix for getting all lib
        repos_all = syncwerk_api.get_repo_list(-1,-1)
        has_next_page = False
        current_page = 1
        # get libraries by page
        # try:
        #     current_page = int(request.GET.get('page', '1'))
        #     per_page = int(request.GET.get('per_page', '100'))
        # except ValueError:
        #     current_page = 1
        #     per_page = 100

        # start = (current_page - 1) * per_page
        # limit = per_page + 1

        # if current_page == -1:
        #     start = -1
        #     limit = -1
        # logger.debug('Page: %s', current_page)

        # repos_all = syncwerk_api.get_repo_list(start, limit)

        # if len(repos_all) > per_page:
        #     repos_all = repos_all[:per_page]
        #     has_next_page = True
        # else:
        #     has_next_page = False

        default_repo_id = get_system_default_repo_id()
        repos_all = filter(lambda r: not r.is_virtual, repos_all)
        repos_all = filter(lambda r: r.repo_id != default_repo_id, repos_all)

        return_results = []

        for repo in repos_all:
            repo_info = get_repo_info(repo)
            return_results.append(repo_info)

        page_info = {
            'has_next_page': has_next_page,
            'current_page': current_page
        }

        # return Response({"page_info": page_info, "repos": return_results})
        resp = {"page_info": page_info, "repos": return_results}
        return api_response(data=resp)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Create new folder',
        operation_description='''Admin creating new folder''',
        tags=['admin-folders'],
        request_body=openapi.Schema(
            type='object',
            properties={
                'name': openapi.Schema(
                    type='string',
                    description='name of the new folder',
                ),
                'owner': openapi.Schema(
                    type='string',
                    description='email of the owner. Not provided and current logging in admin will become the owner',
                ),
                'passwd': openapi.Schema(
                    type='string',
                    description='password if you want to create an encrypted folder. It should be "null" rather than empty string if you want to create the unencrypted folder.',
                ),
            }
        ),
        responses={
            200: openapi.Response(
                description='History limit updated successfully',
                examples={
                    'application/json': {
                        "message": "The folder has been added successfully.",
                        "data": {
                            "name": "qwqwq",
                            "encrypted": False,
                            "description": "",
                            "file_count": 0,
                            "owner": "admin@alpha.syncwerk.com",
                            "size_formatted": "0\u00a0bytes",
                            "id": "d7057aeb-8486-4250-84ef-3d22aced4b25",
                            "size": 0
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
            520: openapi.Response(
                description='Operation failed',
                examples={
                    'application/json': {
                        "message": "Failed to set folder history limit",
                        "data": None
                    }
                }
            ),
        }
    )
    def post(self, request):
        repo_name = request.data.get('name', None)
        if not repo_name:
            error_msg = 'name invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        username = request.user.username
        repo_owner = request.data.get('owner', None)
        if repo_owner:
            try:
                User.objects.get(email=repo_owner)
            except User.DoesNotExist:
                error_msg = 'User %s not found.' % repo_owner
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)
        else:
            repo_owner = username

        passwd = request.data.get("passwd", None)

        if not passwd:
            passwd = None

        if (passwd is not None) and (not config.ENABLE_ENCRYPTED_FOLDER):
            return api_error(status.HTTP_403_FORBIDDEN,
                             _('NOT allow to create encrypted folder.'))
        try:
            repo_id = syncwerk_api.create_repo(repo_name, '', repo_owner, passwd)
        except RpcsyncwerkError as e:
            logger.error(e)
            return api_error(HTTP_520_OPERATION_FAILED,
                             _('Failed to create folder.'))

        if not repo_id:
            return api_error(HTTP_520_OPERATION_FAILED,
                             _('Failed to create folder.'))

        # send admin operation log signal
        admin_op_detail = {
            "id": repo_id,
            "name": repo_name,
            "owner": repo_owner,
        }
        admin_operation.send(sender=None, admin_name=request.user.username,
                operation=REPO_CREATE, detail=admin_op_detail)

        repo = syncwerk_api.get_repo(repo_id)
        repo_info = get_repo_info(repo)
        # return Response(repo_info)
        return api_response(data=repo_info, msg=_('The folder has been added successfully.'))

    def _create_enc_repo(self, request, repo_id, repo_name, repo_desc, username):

        logger.debug('Creating encrypt library in admin view...')
        if not _REPO_ID_PATTERN.match(repo_id):
            return api_error(status.HTTP_400_BAD_REQUEST, _('Folder id must be a valid uuid'))
        magic = request.data.get('magic', '')
        random_key = request.data.get('random_key', '')
        try:
            enc_version = int(request.data.get('enc_version', 0))
        except ValueError:
            return None, api_error(status.HTTP_400_BAD_REQUEST,
                                   _('Invalid enc_version param.'))
        if len(magic) != 64 or len(random_key) != 96 or enc_version < 0:
            return None, api_error(status.HTTP_400_BAD_REQUEST,
                                   _('You must provide magic, random_key and enc_version.'))
        else:
            repo_id = syncwerk_api.create_enc_repo(
                repo_id, repo_name, repo_desc, username,
                magic, random_key, enc_version)
        return repo_id, None

class AdminLibrary(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Delete folder',
        operation_description='''Delete a specific folder''',
        tags=['admin-folders'],
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
                description='Folder removed successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
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
    def delete(self, request, repo_id, format=None):
        
        if get_system_default_repo_id() == repo_id:
            error_msg = _('System library can not be deleted.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            # for case of `syncwerk-data` has been damaged
            # no `repo object` will be returned from syncwerk api
            # delete the database record anyway
            try:
                syncwerk_api.remove_repo(repo_id)
            except Exception as e:
                logger.error(e)
                error_msg = _('Internal Server Error')
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            # return Response({'success': True})
            return api_response()

        repo_name = repo.name
        repo_owner = syncwerk_api.get_repo_owner(repo_id)
        if not repo_owner:
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)

        try:
            syncwerk_api.remove_repo(repo_id)
            related_usernames = synserv.get_related_users_by_repo(repo_id)

            # send signal for syncwevents
            repo_deleted.send(sender=None, org_id=-1, usernames=related_usernames,
                    repo_owner=repo_owner, repo_id=repo_id, repo_name=repo.name)
            
            # for handle auditlog
            repo_update_signal.send(sender=request.user,
                                            request=request,
                                            action_type=EventLogActionType.DELETED_DIR.value,
                                            repo_id=repo_id,
                                            repo_name=repo.name)

        except Exception as e:
            logger.error(e)
            error_msg = _('Internal Server Error')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # send admin operation log signal
        admin_op_detail = {
            "id": repo_id,
            "name": repo_name,
            "owner": repo_owner,
        }
        admin_operation.send(sender=None, admin_name=request.user.username,
                operation=REPO_DELETE, detail=admin_op_detail)

        # return Response({'success': True})
        return api_response(msg=_("The folder has been removed successfully"))

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Transfer folder',
        operation_description='''Transfer a specific folder''',
        tags=['admin-folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='owner',
                in_="formData",
                type='string',
                description='email of the new owner',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Folder transfered successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
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
    def put(self, request, repo_id, format=None):
        
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = _('Folder %s not found.' % repo_id)
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        new_owner = request.data.get('owner', None)
        if not new_owner:
            error_msg = _('owner invalid.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            new_owner_obj = User.objects.get(email=new_owner)
        except User.DoesNotExist:
            error_msg = _('User %s not found.' % new_owner)
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if not new_owner_obj.permissions.can_add_repo():
            # error_msg = _('Transfer failed: role of %s is %s, can not add library.' % (
            #     new_owner, new_owner_obj.role))
            error_msg = _('Transfer failed: role of {owner} is {role}, can not add library.'.format(
                owner=new_owner, role=new_owner_obj.role))
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        if MULTI_TENANCY:
            try:
                if syncwserv_threaded_rpc.get_org_id_by_repo_id(repo_id) > 0:
                    error_msg = _('Can not transfer organization library.')
                    return api_error(status.HTTP_403_FORBIDDEN, error_msg)

                if ccnet_api.get_orgs_by_user(new_owner):
                    error_msg = _('Can not transfer library to organization user %s' % new_owner)
                    return api_error(status.HTTP_403_FORBIDDEN, error_msg)
            except Exception as e:
                logger.error(e)
                error_msg = _('Internal Server Error')
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        repo_owner = syncwerk_api.get_repo_owner(repo_id)

        # get repo shared to user/group list
        shared_users = syncwerk_api.list_repo_shared_to(
                repo_owner, repo_id)
        shared_groups = syncwerk_api.list_repo_shared_group_by_user(
                repo_owner, repo_id)

        # get all pub repos
        pub_repos = []
        if not request.cloud_mode:
            pub_repos = syncwerk_api.list_inner_pub_repos_by_owner(repo_owner)

        # transfer repo
        syncwerk_api.set_repo_owner(repo_id, new_owner)

        # reshare repo to user
        for shared_user in shared_users:
            shared_username = shared_user.user

            if new_owner == shared_username:
                continue

            syncwerk_api.share_repo(repo_id, new_owner,
                    shared_username, shared_user.perm)

        # reshare repo to group
        for shared_group in shared_groups:
            shared_group_id = shared_group.group_id

            if not ccnet_api.is_group_user(shared_group_id, new_owner):
                continue

            syncwerk_api.set_group_repo(repo_id, shared_group_id,
                    new_owner, shared_group.perm)

        # check if current repo is pub-repo
        # if YES, reshare current repo to public
        for pub_repo in pub_repos:
            if repo_id != pub_repo.id:
                continue

            syncwerk_api.add_inner_pub_repo(repo_id, pub_repo.permission)

            break

        # send admin operation log signal
        admin_op_detail = {
            "id": repo_id,
            "name": repo.name,
            "from": repo_owner,
            "to": new_owner,
        }
        admin_operation.send(sender=None, admin_name=request.user.username,
                operation=REPO_TRANSFER, detail=admin_op_detail)

        repo = syncwerk_api.get_repo(repo_id)
        repo_info = get_repo_info(repo)

        # return Response(repo_info)
        return api_response(data=repo_info, msg=_("The folder has been transfered successfully"))

class AdminLibraryPassword(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Grant encrypted folder access',
        operation_description='''Grant access to encrypted folder''',
        tags=['admin-folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='password',
                in_="formData",
                type='string',
                description='password of the encrypted folder',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Access granted',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request / incorrect password',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None,
                        "error_code": ""
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
    def post(self, request, repo_id):
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        password = request.data.get('password', None)
        if not password:
            error_msg = 'password invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        repo_owner = syncwerk_api.get_repo_owner(repo_id)
        if not repo_owner:
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)

        try:
            syncwerk_api.set_passwd(repo_id, repo_owner, password)
            # return Response({'success': True})
            return api_response()
        except RpcsyncwerkError as e:
            if e.msg == 'Bad arguments':
                error_msg = 'Bad arguments'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
            elif e.msg == 'Incorrect password':
                error_msg = _(u'Wrong password')
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
            elif e.msg == 'Internal server error':
                error_msg = _(u'Internal server error')
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)
            else:
                error_msg = _(u'Decrypt library error')
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

class AdminLibraryShares(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get internal shares of a folder',
        operation_description='''Get internal shares of a folder''',
        tags=['admin-folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='share_type',
                in_="query",
                type='string',
                description='type of the share to retrieve',
                enum=['user','group']
            ),
        ],
        responses={
            200: openapi.Response(
                description='List share retrieved',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "shares": [
                                {
                                    "share_permission": "rw",
                                    "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                                    "ctime": "2019-03-04T09:11:51+00:00",
                                    "share_type": "personal",
                                    "encrypted": False,
                                    "user_name": "Uriah Libero",
                                    "contact_email": "ulibero4@infoseek.co.jp",
                                    "folder_name": "My Folder",
                                    "mtime": 1551690711,
                                    "owner": "admin@alpha.syncwerk.com",
                                    "path": "/",
                                    "size": 389029494,
                                    "type": "repo",
                                    "user_email": "ulibero4@infoseek.co.jp",
                                    "repo_name": "My Folder"
                                },
                                {
                                    "share_permission": "rw",
                                    "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                                    "ctime": "2019-03-04T09:11:51+00:00",
                                    "share_type": "personal",
                                    "encrypted": False,
                                    "user_name": "Jillie Mobley",
                                    "contact_email": "jmobley6@pbs.org",
                                    "folder_name": "My Folder",
                                    "mtime": 1551690711,
                                    "owner": "admin@alpha.syncwerk.com",
                                    "path": "/",
                                    "size": 389029494,
                                    "type": "repo",
                                    "user_email": "jmobley6@pbs.org",
                                    "repo_name": "My Folder"
                                },
                                {
                                    "share_permission": "rw",
                                    "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                                    "ctime": "2019-03-04T09:11:51+00:00",
                                    "share_type": "personal",
                                    "encrypted": False,
                                    "user_name": "Bibbye Synnott",
                                    "contact_email": "bsynnott3@artisteer.com",
                                    "folder_name": "My Folder",
                                    "mtime": 1551690711,
                                    "owner": "admin@alpha.syncwerk.com",
                                    "path": "/",
                                    "size": 389029494,
                                    "type": "repo",
                                    "user_email": "bsynnott3@artisteer.com",
                                    "repo_name": "My Folder"
                                }
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
                        "data": None,
                        "error_code": ""
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
    def get(self, request, repo_id):
        share_type= request.GET.get('share_type', None)
        shares = []
        if share_type not in ['user', 'group']:
            error_msg = _(u'Invalid share type. Only "user" or "group" allowed')
            return api_error(code=400, msg=error_msg)
        repo = syncwerk_api.get_repo(repo_id)
        repo_owner = syncwerk_api.get_repo_owner(repo.repo_id)
        if share_type == 'user':
            try:
                share_items = syncwerk_api.list_repo_shared_to(
                                repo_owner, repo.repo_id)
                for share_item in share_items:
                    
                    user_email = share_item.user
                    user_name = email2nickname(user_email) if user_email else '--'

                    share_info = {}
                    share_info['type'] = 'repo'
                    share_info['repo_id'] = repo.repo_id
                    share_info['repo_name'] = repo.repo_name
                    share_info['path'] = repo.origin_path if repo.origin_path != None else '/'
                    share_info['folder_name'] = repo.name
                    share_info['share_type'] = 'personal'
                    share_info['share_permission'] = share_item.perm
                    share_info['encrypted'] = repo.encrypted
                    share_info['mtime'] = repo.last_modify
                    share_info['ctime'] = timestamp_to_isoformat_timestr(repo.last_modify)
                    share_info['size'] = repo.size
                    share_info['owner'] = repo_owner
                    share_info['user_name'] = user_name
                    share_info['user_email'] = user_email
                    share_info['contact_email'] = Profile.objects.get_contact_email_by_user(
                        share_item.user)

                    shares.append(share_info)

            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)
        
        elif share_type == 'group':
            try:
                share_items = syncwerk_api.list_repo_shared_group_by_user(
                                repo_owner, repo.repo_id)
                for share_item in share_items:
                    
                    group_id = share_item.group_id
                    group = ccnet_api.get_group(group_id)
                    group_name = group.group_name if group else '--'

                    share_info = {}
                    share_info['type'] = 'repo'
                    share_info['repo_id'] = repo.repo_id
                    share_info['repo_name'] = repo.repo_name
                    share_info['path'] = repo.origin_path if repo.origin_path != None else '/'
                    share_info['folder_name'] = repo.name
                    share_info['share_type'] = 'group'
                    share_info['share_permission'] = share_item.perm
                    share_info['encrypted'] = repo.encrypted
                    share_info['mtime'] = repo.last_modify
                    share_info['ctime'] = timestamp_to_isoformat_timestr(repo.last_modify)
                    share_info['size'] = repo.size
                    share_info['owner'] = repo_owner
                    share_info['group_id'] = group_id
                    share_info['group_name'] = group_name

                    shares.append(share_info)

            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return api_response(code=200, data={
            'shares': shares,
        })