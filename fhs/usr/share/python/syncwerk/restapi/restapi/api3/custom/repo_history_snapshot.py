import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response
from restapi.api3.models import SharedRepo
from restapi.options.models import UserOptions, CryptoOptionNotSetError
from restapi.views import check_folder_permission, gen_path_link, get_repo_dirents

from restapi.base.templatetags.restapi_tags import translate_commit_desc

import synserv
from synserv import syncwerk_api, syncwserv_rpc, syncwserv_threaded_rpc

from pyrpcsyncwerk import RpcsyncwerkError

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class RepoHistorySnapshot(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get history snapshot folders/files',
        operation_description='''Get all files and folders in a specific snapshot''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='p',
                in_="query",
                type='string',
                description='path inside the folder',
            ),
            openapi.Parameter(
                name='commit_id',
                in_="query",
                type='string',
                description='snapshot commit id',
            ),
        ],
        responses={
            200: openapi.Response(
                description='snapshot dirents retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "repo": {
                                "allow_restore_snapshot": True,
                                "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                                "allow_view_snapshot": True,
                                "name": "My Folder",
                                "allow_view_history": True
                            },
                            "file_list": [
                                {
                                    "obj_name": "Tro-choi-hoi-cho.docx",
                                    "file_size": 13209,
                                    "obj_id": "814e9e55a3c29365f29b3f462d316e85b2af2461"
                                }
                            ],
                            "current_commit": {
                                "ctime": 1548151605,
                                "id": "ce2da729a7ce44842d834254002b7ab08600af08",
                                "creator_name": "admin@alpha.syncwerk.com",
                                "desc": "Added \"Tro-choi-hoi-cho.docx\"."
                            },
                            "dir_list": [],
                            "path": "/",
                            "zipped": [
                                [
                                    "My Folder",
                                    "/"
                                ]
                            ],
                            "is_repo_owner": True,
                            "user_perm": "rw"
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
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_404_NOT_FOUND, 'Library does not exist')

        username = request.user.username
        path = request.GET.get('p', '/')
        if path[-1] != '/':
            path = path + '/'
        user_perm = check_folder_permission(request, repo.id, '/')
        if user_perm is None:
            return api_error(status.HTTP_401_UNAUTHORIZED, 'Permission denied')

        try:
            server_crypto = UserOptions.objects.is_server_crypto(username)
        except CryptoOptionNotSetError:
            # Assume server_crypto is ``False`` if this option is not set.
            server_crypto = False

        if repo.encrypted and \
            (repo.enc_version == 1 or (repo.enc_version == 2 and server_crypto)) \
            and not syncwerk_api.is_password_set(repo.id, username):
            resp = {
                'repo': {
                    'repo_id': repo.repo_id,
                    'name': repo.name
                }
            }
            return api_response(data=resp)

        commit_id = request.GET.get('commit_id', None)
        if commit_id is None:
            return api_response()
        current_commit = synserv.get_commit(repo.id, repo.version, commit_id)
        if not current_commit:
            current_commit = synserv.get_commit(repo.id, repo.version, repo.head_cmmt_id)

        file_list, dir_list, dirent_more = get_repo_dirents(request, repo,
                                                            current_commit, path)
        zipped = gen_path_link(path, repo.name)

        repo_owner = syncwerk_api.get_repo_owner(repo.id)
        is_repo_owner = True if username == repo_owner else False

        dirents = []
        for dirent in dir_list:
            dirents.append({
                'obj_name': dirent.obj_name
            })
        files = [] 
        for file in file_list:
            files.append({
                'obj_id': file.obj_id,
                'obj_name': file.obj_name,
                'file_size': file.file_size
            })

        resp = {
            'repo': {
                'repo_id': repo.repo_id,
                'name': repo.name
            },
            'is_repo_owner': is_repo_owner,
            'user_perm': user_perm,
            'current_commit': {
                'id': current_commit.id,
                'desc': translate_commit_desc(current_commit.props.desc),
                'ctime': current_commit.props.ctime,
                'creator_name': current_commit.props.creator_name,
            },
            'dir_list': dirents,
            'file_list': files,
            'path': path,
            'zipped': zipped
            }
        
        # Check history permission
        if request.user.email == syncwerk_api.get_repo_owner(repo.id):
            resp['repo']['allow_view_history'] = True
            resp['repo']['allow_view_snapshot'] = True
            resp['repo']['allow_restore_snapshot'] = True
        else:
            try:
                share_item = SharedRepo.objects.using('syncwerk-server').get(repo_id=repo.repo_id,from_email=syncwerk_api.get_repo_owner(repo.id),to_email=request.user.email)
                resp['repo']['allow_view_history'] = share_item.allow_view_history
                resp['repo']['allow_view_snapshot'] = share_item.allow_view_snapshot
                resp['repo']['allow_restore_snapshot'] = share_item.allow_restore_snapshot
            except Exception as e:
                resp['repo']['allow_view_history'] = True
                resp['repo']['allow_view_snapshot'] = False
                resp['repo']['allow_restore_snapshot'] = False

        return api_response(data=resp)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Restore a snapshot',
        operation_description='''Restore a snapshot''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='commit_id',
                in_="query",
                type='string',
                description='snapshot commit id',
            ),
        ],
        responses={
            200: openapi.Response(
                description='snapshot restored retrieved successfully',
                examples={
                    'application/json': {
                        "message": "Snapshot restored successfully",
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
            return api_error(status.HTTP_404_NOT_FOUND, 'Library does not exist')

        # perm check
        perm = check_folder_permission(request, repo_id, '/')
        username = request.user.username
        repo_owner = syncwerk_api.get_repo_owner(repo.id)

        if perm is None or repo_owner != username:
            return api_error(status.HTTP_401_UNAUTHORIZED, 'Permission denied')

        try:
            server_crypto = UserOptions.objects.is_server_crypto(username)
        except CryptoOptionNotSetError:
            # Assume server_crypto is ``False`` if this option is not set.
            server_crypto = False

        password_set = False
        if repo.props.encrypted and \
                (repo.enc_version == 1 or (repo.enc_version == 2 and server_crypto)):
            try:
                ret = syncwserv_rpc.is_passwd_set(repo_id, username)
                if ret == 1:
                    password_set = True
            except RpcsyncwerkError, e:
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, e.msg)

            if not password_set:
                return api_response(data={'repo_id': repo_id, 'password_protected': True})

        commit_id = request.GET.get('commit_id', '')
        if not commit_id:
            return api_error(status.HTTP_400_BAD_REQUEST, msg='Please specify history ID')

        try:
            syncwserv_threaded_rpc.revert_on_server(repo_id, commit_id, request.user.username)
        except RpcsyncwerkError, e:
            if e.msg == 'Bad arguments':
                return api_error(status.HTTP_400_BAD_REQUEST, msg='Invalid arguments.')
            elif e.msg == 'No such repo':
                return api_error(status.HTTP_403_FORBIDDEN, msg='Library does not exist')
            elif e.msg == "Commit doesn't exist":
                return api_error(status.HTTP_403_FORBIDDEN, msg='History you specified does not exist')
            else:
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, msg='Unknown error')

        return api_response(msg='Snapshot restored successfully.')
