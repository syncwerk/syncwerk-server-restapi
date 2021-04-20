from searching import get_search_results
from restapi.api3.base import APIView
from restapi.api3.authentication import TokenAuthentication
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from restapi.api3.throttling import UserRateThrottle
from drf_yasg.utils import swagger_auto_schema
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema
from drf_yasg import openapi
from synserv import syncwerk_api, get_commits, get_file_id_by_path
from restapi.views import check_folder_permission
from restapi.api3.utils import api_error, api_response


class SearchView(APIView):
    """
    Basic Search View.
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get_dir_info(self, repo_id, dir_path):
        dir_obj = syncwerk_api.get_dirent_by_path(repo_id, dir_path)
        dir_info = {
            'type': 'dir',
            'repo_id': repo_id,
            'parent_dir': os.path.dirname(dir_path.rstrip('/')),
            'name': dir_obj.obj_name,
            'id': dir_obj.obj_id,
            'mtime': timestamp_to_isoformat_timestr(dir_obj.mtime),
            'last_update': translate_restapi_time(dir_obj.mtime),
            'permission': 'rw'
        }

        return dir_info

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Search a folder',
        operation_description='''Search in any folder using query''',
        tags=['search'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='id of the folder to get details'
            ),
            openapi.Parameter(
                name="p",
                in_="query",
                type='string',
                description='path to the subfolder in the folder. Default to "/"'
            ),
            openapi.Parameter(
                name="q",
                in_="query",
                type='string',
                description='The search query'
            ),
            openapi.Parameter(
                name="oid",
                in_="query",
                type='string',
                description='object id of the folder. The object id is the checksum of the directory contents'
            ),
            openapi.Parameter(
                name="t",
                in_="query",
                type='string',
                description='''- "f" : only return files \n
- "d": only return sub folders \n
- not provided: return all files and subfolders.'''
            ),
            openapi.Parameter(
                name="recursive",
                in_="query",
                type='string',
                description='if set t argument as "d" AND this recursive argument as 1, return all dir entries recursively'
            ),
        ],
        responses={
            200: openapi.Response(
                description='Successfully retrieve result.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                            "permission": "rw",
                            "encrypted": False,
                            "dir_perm": "rw",
                            "oid": "ddc397013c0c2b99c9b224801e36bdb03754efc0",
                            "dirent_list": [
                                {
                                    "name": "111",
                                    "permission": "rw",
                                    "last_update": "<time datetime=\"2019-02-11T10:25:08\" is=\"relative-time\" title=\"Mon, 11 Feb 2019 10:25:08 +0000\" >6 days ago</time>",
                                    "mtime": 1549880708,
                                    "type": "dir",
                                    "id": "0000000000000000000000000000000000000000"
                                },
                                {
                                    "lock_time": 0,
                                    "last_update": "<time datetime=\"2019-02-01T02:21:40\" is=\"relative-time\" title=\"Fri, 1 Feb 2019 02:21:40 +0000\" >2019-02-01</time>",
                                    "modifier_email": "admin@alpha.syncwerk.com",
                                    "name": "home.md",
                                    "permission": "rw",
                                    "is_locked": False,
                                    "lock_owner": "",
                                    "mtime": 1548987700,
                                    "modifier_contact_email": "admin@alpha.syncwerk.com",
                                    "starred": False,
                                    "locked_by_me": False,
                                    "type": "file",
                                    "id": "0000000000000000000000000000000000000000",
                                    "modifier_name": "admin",
                                    "size": 0
                                }
                            ],
                            "allow_view_snapshot": True,
                            "allow_view_history": True,
                            "owner": "admin@alpha.syncwerk.com",
                            "allow_restore_snapshot": True,
                            "repo_name": "test wiki 4"
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
                        "detail": "Token invalid"
                    }
                }
            ),
            403: openapi.Response(
                description='You don\'t have permission to perform this operation.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            404: openapi.Response(
                description='Sub folder not found',
                examples={
                    'application/json': {
                        "message": "Folder not found",
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
        path = request.GET.get('p', '/')
        if path[-1] != '/':
            path = path + '/'

        # recource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        try:
            dir_id = syncwerk_api.get_dir_id_by_path(repo_id, path)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # permission check
        if not check_folder_permission(request, repo_id, path):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        username = request.user.username
        if repo.encrypted \
                and not syncwerk_api.is_password_set(repo.id, username):
            err_msg = _(u'Library is encrypted.')
            return api_response(data={'lib_need_decrypt': True, 'repo_name': repo.name}, msg=err_msg)

        if not dir_id:
            error_msg = 'Folder %s not found.' % path
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        old_oid = request.GET.get('oid', None)
        if old_oid and old_oid == dir_id:
            # resp = Response({'success': True})
            resp = {'success': True}
            resp["oid"] = dir_id
            # return resp
            return api_response(status.HTTP_200_OK, '', resp)
        else:
            search_query = request.GET.get('q', None)
            if not search_query:
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            request_type = request.GET.get('t', None)
            if request_type and request_type not in ('f', 'd'):
                error_msg = "'t'(type) should be 'f' or 'd'."
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            # return get_dir_entrys_by_id(request, repo, path, dir_id, request_type)
            # resp = get_dir_entrys_by_id(
            #     request, repo, path, dir_id, request_type)
            resp = get_search_results(request, repo, path, dir_id, search_query)
            resp["user_permission"] = {
                'can_generate_share_link': request.user.permissions.can_generate_share_link(),
                'can_generate_upload_link': request.user.permissions.can_generate_upload_link(),
                # 'can_generate_share_link': False,
                # 'can_generate_upload_link': False
            }
            return api_response(data=resp)
