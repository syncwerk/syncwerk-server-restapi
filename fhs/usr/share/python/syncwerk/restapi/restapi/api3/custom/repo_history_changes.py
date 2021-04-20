from django.utils.html import escape
from django.utils.translation import ugettext as _

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response
from restapi.options.models import UserOptions, CryptoOptionNotSetError
from restapi.views import check_folder_permission
from restapi.base.templatetags.restapi_tags import tsstr_sec

import synserv
from synserv import syncwerk_api, is_passwd_set, syncwserv_threaded_rpc

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class RepoHistoryChanges(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get history snapshot details',
        operation_description='''Get all changes in a history snapshot''',
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
                description='id of the snapshot commit',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Snapshot detail retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
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
        changes = {}

        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            err_msg = _(u'Library does not exist.')
            # return HttpResponse(json.dumps({'error': err_msg}),
            #         status=400, content_type=content_type)
            return api_error(status.HTTP_400_BAD_REQUEST, err_msg)

        # perm check
        if check_folder_permission(request, repo_id, '/') is None:
            if request.user.is_staff is True:
                pass # Allow system staff to check repo changes
            else:
                err_msg = _(u"Permission denied")
                # return HttpResponse(json.dumps({"error": err_msg}), status=403,
                #                 content_type=content_type)
                return api_error(status.HTTP_403_FORBIDDEN, err_msg)

        username = request.user.username
        try:
            server_crypto = UserOptions.objects.is_server_crypto(username)
        except CryptoOptionNotSetError:
            # Assume server_crypto is ``False`` if this option is not set.
            server_crypto = False

        if repo.encrypted and \
                (repo.enc_version == 1 or (repo.enc_version == 2 and server_crypto)) \
                and not is_passwd_set(repo_id, username):
            err_msg = _(u'Library is encrypted.')
            # return HttpResponse(json.dumps({'error': err_msg}),
            #                     status=403, content_type=content_type)
            return api_error(status.HTTP_403_FORBIDDEN, err_msg)

        commit_id = request.GET.get('commit_id', '')
        if not commit_id:
            err_msg = _(u'Argument missing')
            # return HttpResponse(json.dumps({'error': err_msg}),
            #                     status=400, content_type=content_type)
            return api_error(status.HTTP_400_BAD_REQUEST, err_msg)

        changes = get_diff(repo_id, '', commit_id)

        c = synserv.get_commit(repo.id, repo.version, commit_id)
        if c.parent_id is None:
            # A commit is a first commit only if it's parent id is None.
            changes['cmt_desc'] = repo.desc
        elif c.second_parent_id is None:
            # Normal commit only has one parent.
            if c.desc.startswith('Changed library'):
                changes['cmt_desc'] = _('Changed library name or description')
        else:
            # A commit is a merge only if it has two parents.
            changes['cmt_desc'] = _('No conflict in the merge.')

        changes['date_time'] = tsstr_sec(c.ctime)

        # return HttpResponse(json.dumps(changes), content_type=content_type)
        return api_response(data=changes)

def get_diff(repo_id, arg1, arg2):
    lists = {'new': [], 'removed': [], 'renamed': [], 'modified': [],
             'newdir': [], 'deldir': []}

    diff_result = syncwserv_threaded_rpc.get_diff(repo_id, arg1, arg2)
    if not diff_result:
        return lists

    for d in diff_result:
        if d.status == "add":
            lists['new'].append(escape(d.name))
        elif d.status == "del":
            lists['removed'].append(escape(d.name))
        elif d.status == "mov":
            lists['renamed'].append(escape(d.name) + " ==> " + escape(d.name))
        elif d.status == "mod":
            lists['modified'].append(escape(d.name))
        elif d.status == "newdir":
            lists['newdir'].append(escape(d.name))
        elif d.status == "deldir":
            lists['deldir'].append(escape(d.name))

    return lists
