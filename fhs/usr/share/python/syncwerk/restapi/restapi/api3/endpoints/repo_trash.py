import stat
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.utils.translation import ugettext as _

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

from restapi.utils.timeutils import timestamp_to_isoformat_timestr
from restapi.views import check_folder_permission
from restapi.utils import is_org_context

from synserv import syncwerk_api, get_repo
from pyrpcsyncwerk import RpcsyncwerkError

logger = logging.getLogger(__name__)


from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class RepoTrash(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def get_item_info(self, trash_item):

        item_info = {
            'parent_dir': trash_item.basedir,
            'name': trash_item.obj_name,
            'deleted_time': timestamp_to_isoformat_timestr(trash_item.delete_time),
            'scan_stat': trash_item.scan_stat,
            'commit_id': trash_item.commit_id,
        }

        if stat.S_ISDIR(trash_item.mode):
            is_dir = True
        else:
            is_dir = False

        item_info['is_dir'] = is_dir
        item_info['size'] = trash_item.file_size if not is_dir else ''
        item_info['id'] = trash_item.obj_id if not is_dir else ''

        return item_info

    def get(self, request, repo_id, format=None):
        """ Return deleted files/dirs of a repo/folder

        Permission checking:
        1. all authenticated user can perform this action.

        ---
        # YAML

        type:
          Authorization:
            required: true
            type: string
          repo_id:
            required: true
            type: string
          path:
            required: true
            type: string
          show_days:
            required: false
            type: string
          scan_stat:
            required: false
            type: string

        parameters:
            - name: Authorization
              required: true
              type: string
              paramType: header
            - name: repo_id
              required: true
              type: string
              paramType: path
            - name: path
              required: true
              type: string
              paramType: query
            - name: show_days
              required: false
              type: string
              paramType: query
            - name: scan_stat
              required: false
              type: string
              paramType: query

        responseMessages:
            - code: 400
              message: BAD_REQUEST
            - code: 401
              message: UNAUTHORIZED
            - code: 403
              message: FORBIDDEN
            - code: 404
              message: NOT_FOUND
            - code: 500
              message: INTERNAL_SERVER_ERROR

        consumes:
            - application/json
        produces:
            - application/json
        """

        # argument check
        path = request.GET.get('path', '/')

        # resource check
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

        if not dir_id:
            error_msg = 'Folder %s not found.' % path
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if check_folder_permission(request, repo_id, path) is None:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        try:
            show_days = int(request.GET.get('show_days', '0'))
        except ValueError:
            show_days = 0

        if show_days < 0:
            error_msg = 'show_days invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        scan_stat = request.GET.get('scan_stat', None)
        try:
            # a list will be returned, with at least 1 item in it
            # the last item is not a deleted entry, and it contains an attribute named 'scan_stat'
            deleted_entries = syncwerk_api.get_deleted(repo_id,
                    show_days, path, scan_stat)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        scan_stat = deleted_entries[-1].scan_stat
        more = True if scan_stat is not None else False

        items = []
        if len(deleted_entries) > 1:
            entries_without_scan_stat = deleted_entries[0:-1]

            # sort entry by delete time
            entries_without_scan_stat.sort(lambda x, y : cmp(y.delete_time,
                                                             x.delete_time))

            for item in entries_without_scan_stat:
                item_info = self.get_item_info(item)
                items.append(item_info)

        result = {
            'data': items,
            'more': more,
            'scan_stat': scan_stat,
            'repo_name': repo.name,
            'repo_id': repo.repo_id
        }

        # return Response(result)
        return api_response(data=result)

class RepoTrashClean(APIView):
    
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Clean trash',
        operation_description='''Clean trash''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='keep_days',
                in_="query",
                type='string',
                description='-1 for clearing all. 3,7,30 for clearing entries older than 3,7 or 30 days',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Trash cleaned successfully.',
                examples={
                    'application/json': {
                        "message": "Trash cleaned successfully.",
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

    def post(self, request, repo_id, format=None):
        
        if request.method != 'POST':
            return api_error(status.HTTP_404_NOT_FOUND, '')

        repo = get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_404_NOT_FOUND, '')

        username = request.user.username
        if is_org_context(request):
            repo_owner = syncwerk_api.get_org_repo_owner(repo.id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo.id)
        is_repo_owner = True if repo_owner == username else False
        if not is_repo_owner:
            return api_error(status.HTTP_404_NOT_FOUND, _('Permission denied'))

        day = int(request.POST.get('keep_days'))
        try:
            syncwerk_api.clean_up_repo_history(repo.id, day)
        except RpcsyncwerkError as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, _('Internal server error'))

        return api_response(msg=_('Trash cleaned successfully.'))
