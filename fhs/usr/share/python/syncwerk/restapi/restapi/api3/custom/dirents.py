import logging
import posixpath
import stat

from functools import wraps

from django.utils.translation import ugettext as _

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from restapi.api3.base import APIView
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

from restapi.utils import check_filename_with_rename
from restapi.views import check_folder_permission, get_unencry_rw_repos_by_user
from synserv import syncwerk_api
from pyrpcsyncwerk import RpcsyncwerkError

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

def dirents_copy_move_common(func):
    """
    Decorator for common logic in copying/moving dirs/files in batch.
    """
    @wraps(func)
    def _decorated(view, request, repo_id, *args, **kwargs):
        result = {}

        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            # result['error'] = _(u'Library does not exist.')
            # return HttpResponse(json.dumps(result), status=400,
            #                     content_type=content_type)
            err_msg = _(u'Library does not exist.')
            return api_error(status.HTTP_400_BAD_REQUEST, err_msg)

        # arguments validation
        parent_dir = request.GET.get('parent_dir')
        obj_file_names = request.POST.getlist('file_names')
        obj_dir_names = request.POST.getlist('dir_names')
        dst_repo_id = request.POST.get('dst_repo')
        dst_path = request.POST.get('dst_path')
        if not (parent_dir and dst_repo_id and dst_path) and \
            not (obj_file_names or obj_dir_names):
            # result['error'] = _('Argument missing')
            # return HttpResponse(json.dumps(result), status=400,
            #                     content_type=content_type)
            err_msg = _(u'Argument missing')
            return api_error(status.HTTP_400_BAD_REQUEST, err_msg)

        # check file path
        for obj_name in obj_file_names + obj_dir_names:
            if len(dst_path+obj_name) > settings.MAX_PATH:
                # result['error'] =  _('Destination path is too long for %s.') % escape(obj_name)
                # return HttpResponse(json.dumps(result), status=400,
                #                     content_type=content_type)
                err_msg = _('Destination path is too long for %s.') % escape(obj_name)
                return api_error(status.HTTP_400_BAD_REQUEST, err_msg)

        # when dst is the same as src
        if repo_id == dst_repo_id and parent_dir == dst_path:
            # result['error'] = _('Invalid destination path')
            # return HttpResponse(json.dumps(result), status=400,
            #                     content_type=content_type)
            err_msg = _('Invalid destination path')
            return api_error(status.HTTP_400_BAD_REQUEST, err_msg)

        # check whether user has write permission to dest repo
        if check_folder_permission(request, dst_repo_id, dst_path) != 'rw':
            # result['error'] = _('Permission denied')
            # return HttpResponse(json.dumps(result), status=403,
            #                     content_type=content_type)
            err_msg = _('Permission denied')
            return api_error(status.HTTP_403_FORBIDDEN, err_msg)

        # Leave src folder/file permission checking to corresponding
        # views, only need to check folder permission when perform 'move'
        # operation, 1), if move file, check parent dir perm, 2), if move
        # folder, check that folder perm.

        file_obj_size = 0
        for obj_name in obj_file_names:
            full_obj_path = posixpath.join(parent_dir, obj_name)
            file_obj_id = syncwerk_api.get_file_id_by_path(repo_id, full_obj_path)
            file_obj_size += syncwerk_api.get_file_size(
                    repo.store_id, repo.version, file_obj_id)

        dir_obj_size = 0
        for obj_name in obj_dir_names:
            full_obj_path = posixpath.join(parent_dir, obj_name)
            dir_obj_id = syncwerk_api.get_dir_id_by_path(repo_id, full_obj_path)
            dir_obj_size += syncwerk_api.get_dir_size(
                    repo.store_id, repo.version, dir_obj_id)

        # check quota
        src_repo_owner = syncwerk_api.get_repo_owner(repo_id)
        dst_repo_owner = syncwerk_api.get_repo_owner(dst_repo_id)
        try:
            # always check quota when copy file
            if view_method.__name__ == 'cp_dirents':
                out_of_quota = syncwerk_api.check_quota(
                        dst_repo_id, delta=file_obj_size + dir_obj_size)
            else:
                # when move file
                if src_repo_owner != dst_repo_owner:
                    # only check quota when src_repo_owner != dst_repo_owner
                    out_of_quota = syncwerk_api.check_quota(
                            dst_repo_id, delta=file_obj_size + dir_obj_size)
                else:
                    # not check quota when src and dst repo are both mine
                    out_of_quota = False
        except Exception as e:
            logger.error(e)
            # result['error'] = _(u'Internal server error')
            # return HttpResponse(json.dumps(result), status=500,
            #                 content_type=content_type)
            err_msg = _(u'Internal server error')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, err_msg)

        if out_of_quota:
            # result['error'] = _('Out of quota.')
            # return HttpResponse(json.dumps(result), status=403,
            #                     content_type=content_type)
            err_msg = _('Out of quota.')
            return api_error(status.HTTP_403_FORBIDDEN, err_msg)

        return func(view, request, repo_id, parent_dir, dst_repo_id,
                            dst_path, obj_file_names, obj_dir_names, *args, **kwargs)


class Dirents(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get file tree dirents',
        operation_description='''Get dirents in a folder for file tree''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_='path',
                type='string',
                description='folder id',
            ),
            openapi.Parameter(
                name='path',
                in_='query',
                type='string',
                description='folder path',
                required=True,
            ),
            openapi.Parameter(
                name='dir_only',
                in_='query',
                type='boolean',
                description='Only retrieve folder',
                required=True
            ),
            openapi.Parameter(
                name='all_dir',
                in_="query",
                type='boolean',
                description='retrieve all folders of all path',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Info retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
                    },
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
                description='Operation not permitted',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            404: openapi.Response(
                description='Not found',
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
        # permission checking
        user_perm = check_folder_permission(request, repo_id, '/')
        if user_perm is None:
            err_msg = _(u"You don't have permission to access the folder.")
            # return HttpResponse(json.dumps({"err_msg": err_msg}), status=403,
            #                     content_type=content_type)
            return api_error(status.HTTP_403_FORBIDDEN, err_msg)

        path = request.GET.get('path', '')
        dir_only = request.GET.get('dir_only', False)
        all_dir = request.GET.get('all_dir', False)
        if not path:
            err_msg = _(u"No path.")
            # return HttpResponse(json.dumps({"error": err_msg}), status=400,
            #                     content_type=content_type)
            return api_error(status.HTTP_400_BAD_REQUEST, err_msg)

        # get dirents for every path element
        if all_dir:
            all_dirents = []
            path_eles = path.split('/')[:-1]
            for i, x in enumerate(path_eles):
                ele_path = '/'.join(path_eles[:i+1]) + '/'
                try:
                    ele_path_dirents = syncwerk_api.list_dir_by_path(repo_id, ele_path.encode('utf-8'))
                except RpcsyncwerkError, e:
                    ele_path_dirents = []
                ds = []
                for d in ele_path_dirents:
                    if stat.S_ISDIR(d.mode):
                        ds.append({
                            'name': d.obj_name,
                            'parent_dir': ele_path 
                        })
                ds.sort(lambda x, y : cmp(x['name'].lower(), y['name'].lower()))
                all_dirents.extend(ds)
            # return HttpResponse(json.dumps(all_dirents), content_type=content_type)
            return api_response(data=all_dirents)

        # get dirents in path
        try:
            dirents = syncwerk_api.list_dir_by_path(repo_id, path.encode('utf-8'))
        except RpcsyncwerkError, e:
            # return HttpResponse(json.dumps({"error": e.msg}), status=500,
            #                     content_type=content_type)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, e.msg)

        d_list = []
        f_list = []
        for dirent in dirents:
            if stat.S_ISDIR(dirent.mode):
                subdir = {
                    'name': dirent.obj_name,
                    'type': 'dir',
                    'parent_dir': path
                }
                d_list.append(subdir)
            else:
                if not dir_only:
                    f = {
                        'name': dirent.obj_name,
                        'type': 'file',
                        'parent_dir': path
                        }
                    f_list.append(f)

        d_list.sort(lambda x, y : cmp(x['name'].lower(), y['name'].lower()))
        f_list.sort(lambda x, y : cmp(x['name'].lower(), y['name'].lower()))
        # return HttpResponse(json.dumps(d_list + f_list), content_type=content_type)
        resp = d_list + f_list
        return api_response(data=resp)


class DirentsDelete(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Multiple delete',
        operation_description='''Delete multi files/folders''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_='path',
                type='string',
                description='folder id',
            ),
            openapi.Parameter(
                name='parent_dir',
                in_='query',
                type='string',
                description='path of the parent folder',
                required=True,
            ),
            openapi.Parameter(
                name='dirents_names',
                in_='formData',
                type='string',
                description='File / Folder name to be deleted. Provide multiple of this param for delete multipe files / folders',
                required=True
            ),
        ],
        responses={
            200: openapi.Response(
                description='Delete successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
                    },
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
    def post(self, request, repo_id, format=None):
        

        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            err_msg = _(u'Library does not exist.')
            # return HttpResponse(json.dumps({'error': err_msg}),
            #         status=400, content_type=content_type)
            return api_error(status.HTTP_400_BAD_REQUEST, err_msg)

        # argument checking
        parent_dir = request.GET.get('parent_dir')
        dirents_names = request.POST.getlist('dirents_names')
        if not (parent_dir and dirents_names):
            err_msg = _(u'Argument missing.')
            # return HttpResponse(json.dumps({'error': err_msg}),
            #         status=400, content_type=content_type)
            return api_error(status.HTTP_400_BAD_REQUEST, err_msg)

        # permission checking
        username = request.user.username
        deleted = []
        undeleted = []

        multi_files = ''
        for dirent_name in dirents_names:
            full_path = posixpath.join(parent_dir, dirent_name)
            if check_folder_permission(request, repo.id, full_path) != 'rw':
                undeleted.append(dirent_name)
                continue

            multi_files += dirent_name + '\t'
            deleted.append(dirent_name)

        try:
            syncwerk_api.del_file(repo_id, parent_dir, multi_files, username)
        except RpcsyncwerkError, e:
            logger.error(e)

        # return HttpResponse(json.dumps({'deleted': deleted, 'undeleted': undeleted}),
        #                     content_type=content_type)
        resp = {
            'deleted': deleted,
            'undeleted': undeleted
        }
        return api_response(data=resp, msg='Deleted items successfully.')


class DirentsMove(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)
    
    @dirents_copy_move_common
    def post(self, request, src_repo_id, src_path, dst_repo_id, dst_path,
                obj_file_names, obj_dir_names, format=None):
        result = {}
        username = request.user.username
        failed = []
        allowed_files = []
        allowed_dirs = []

        # check parent dir perm for files
        if check_folder_permission(request, src_repo_id, src_path) != 'rw':
            allowed_files = []
            failed += obj_file_names
        else:
            allowed_files = obj_file_names

        for obj_name in obj_dir_names:
            src_dir = posixpath.join(src_path, obj_name)
            if dst_path.startswith(src_dir + '/'):
                error_msg = _(u'Can not move directory %(src)s to its subdirectory %(des)s') \
                    % {'src': escape(src_dir), 'des': escape(dst_path)}
                # result['error'] = error_msg
                # return HttpResponse(json.dumps(result), status=400, content_type=content_type)
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            # check every folder perm
            if check_folder_permission(request, src_repo_id, src_dir) != 'rw':
                failed.append(obj_name)
            else:
                allowed_dirs.append(obj_name)

        success = []
        url = None
        for obj_name in allowed_files + allowed_dirs:
            new_obj_name = check_filename_with_rename(dst_repo_id, dst_path, obj_name)
            try:
                res = syncwerk_api.move_file(src_repo_id, src_path, obj_name,
                        dst_repo_id, dst_path, new_obj_name,
                        replace=False, username=username, need_progress=1)
            except RpcsyncwerkError as e:
                logger.error(e)
                res = None

            if not res:
                failed.append(obj_name)
            else:
                success.append(obj_name)

        if len(success) > 0:
            url = reverse("view_common_lib_dir", args=[dst_repo_id, dst_path.strip('/')])

        result = {'success': success, 'failed': failed, 'url': url}
        # return HttpResponse(json.dumps(result), content_type=content_type)
        return api_response(data=result)


class DirentsCopy(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)
    
    @dirents_copy_move_common
    def post(self, request, src_repo_id, src_path, dst_repo_id, dst_path, obj_file_names, obj_dir_names, format=None):
        result = {}
        username = request.user.username

        if check_folder_permission(request, src_repo_id, src_path) is None:
            error_msg = _(u'You do not have permission to copy files/folders in this directory')
            # result['error'] = error_msg
            # return HttpResponse(json.dumps(result), status=403, content_type=content_type)
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        for obj_name in obj_dir_names:
            src_dir = posixpath.join(src_path, obj_name)
            if dst_path.startswith(src_dir):
                error_msg = _(u'Can not copy directory %(src)s to its subdirectory %(des)s') \
                    % {'src': escape(src_dir), 'des': escape(dst_path)}
                # result['error'] = error_msg
                # return HttpResponse(json.dumps(result), status=400, content_type=content_type)
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        failed = []
        success = []
        url = None
        for obj_name in obj_file_names + obj_dir_names:
            new_obj_name = check_filename_with_rename(dst_repo_id, dst_path, obj_name)
            try:
                res = syncwerk_api.copy_file(src_repo_id, src_path, obj_name,
                                    dst_repo_id, dst_path, new_obj_name, username, need_progress=1)
            except RpcsyncwerkError as e:
                logger.error(e)
                res = None

            if not res:
                failed.append(obj_name)
            else:
                success.append(obj_name)

        if len(success) > 0:
            url = reverse("view_common_lib_dir", args=[dst_repo_id, dst_path.strip('/')])

        result = {'success': success, 'failed': failed, 'url': url}
        # return HttpResponse(json.dumps(result), content_type=content_type)
        return api_response(data=result)


class UnEncRWRepos(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get rw unencrypted folders',
        operation_description='''Get a user's unencrypt folders that he/she can read-write.''',
        tags=['folders'],
        responses={
            200: openapi.Response(
                description='List retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
                    },
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
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
        
        acc_repos = get_unencry_rw_repos_by_user(request)

        repo_list = []
        acc_repos = filter(lambda r: not r.is_virtual, acc_repos)
        for repo in acc_repos:
            repo_list.append({"name": repo.name, "id": repo.id})

        repo_list.sort(lambda x, y: cmp(x['name'].lower(), y['name'].lower()))
        # return HttpResponse(json.dumps(repo_list), content_type=content_type)
        return api_response(data=repo_list)
