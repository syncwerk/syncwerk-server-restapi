import logging
import os

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response, get_user_common_info

from restapi.utils import get_file_type_and_ext
from restapi.views import check_folder_permission, validate_owner, check_file_lock, gen_path_link

import synserv
from synserv import get_repo, syncwerk_api
from pyrpcsyncwerk import RpcsyncwerkError

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class FileRevisions(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get file revisons',
        operation_description='''Get file revison list''',
        tags=['files'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='folder id.',
            ),
            openapi.Parameter(
                name='p',
                in_="path",
                type='string',
                description='path to the file.',
                required=True,
            ),
            openapi.Parameter(
                name='days',
                in_="query",
                type='string',
                description='All of the revisons within this duration will be retrieved. Default to 7. Set this to -1 for all',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Revison list retrived successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "is_owner": True,
                            "commits": [
                                {
                                    "rev_file_size": 42,
                                    "is_first_commit": True,
                                    "rev_file_id": "96030283fc3f5f6112efaf65f076b55e449cb7f5",
                                    "ctime": 1548314320,
                                    "creator": {
                                        "login_id": "",
                                        "avatar_size": 80,
                                        "name": "admin",
                                        "nick_name": None,
                                        "is_default_avatar": False,
                                        "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                        "email": "admin@alpha.syncwerk.com"
                                    },
                                    "path": "/email.csv",
                                    "rev_renamed_old_path": None,
                                    "id": "ea4cf7770857da7a08dde837e4eb90fc23476eab"
                                }
                            ],
                            "days": 7,
                            "path": "/email.csv",
                            "zipped": [
                                [
                                    "My Folder",
                                    "/"
                                ],
                                [
                                    "email.csv",
                                    "/email.csv"
                                ]
                            ],
                            "can_revert_file": True,
                            "u_filename": "email.csv",
                            "can_compare": True
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
            404: openapi.Response(
                description='File not found',
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
        repo = get_repo(repo_id)
        if not repo:
            # raise Http404
            return api_error(status.HTTP_404_NOT_FOUND, '')

        # perm check
        if check_folder_permission(request, repo_id, '/') is None:
            # raise Http404
            return api_error(status.HTTP_404_NOT_FOUND, '')

        days_str = request.GET.get('days', '')
        try:
            days = int(days_str)
        except ValueError:
            days = 7

        path = request.GET.get('p', '/')
        if path[-1] == '/':
            path = path[:-1]
        u_filename = os.path.basename(path)

        if not path:
            # return render_error(request)
            return api_error(status.HTTP_400_BAD_REQUEST, '')

        repo = get_repo(repo_id)
        if not repo:
            # error_msg = _(u"Library does not exist")
            # return render_error(request, error_msg)
            return api_error(status.HTTP_404_NOT_FOUND, 'Library does not exist')

        filetype = get_file_type_and_ext(u_filename)[0].lower()
        if filetype == 'text' or filetype == 'markdown':
            can_compare = True
        else:
            can_compare = False

        try:
            commits = syncwerk_api.get_file_revisions(repo_id, repo.head_cmmt_id, path, -1)
        except RpcsyncwerkError, e:
            logger.error(e.msg)
            # return render_error(request, e.msg)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, e.msg)

        if not commits:
            # return render_error(request, _(u'No revisions found'))
            return api_error(status.HTTP_404_NOT_FOUND, 'No revisions found')

        # Check whether user is repo owner
        if validate_owner(request, repo_id):
            is_owner = True
        else:
            is_owner = False

        cur_path = path
        for commit in commits:
            commit.path = cur_path
            if commit.rev_renamed_old_path:
                cur_path = '/' + commit.rev_renamed_old_path

        zipped = gen_path_link(path, repo.name)

        can_revert_file = True
        username = request.user.username

        is_locked, locked_by_me = check_file_lock(repo_id, path, username)
        if syncwerk_api.check_permission_by_path(repo_id, path, username) != 'rw' or \
            (is_locked and not locked_by_me):
            can_revert_file = False

        commits[0].is_first_commit = True

        # for 'go back'
        # referer = request.GET.get('referer', '')

        # return render_to_response('file_revisions.html', {
        #     'repo': repo,
        #     'path': path,
        #     'u_filename': u_filename,
        #     'zipped': zipped,
        #     'commits': commits,
        #     'is_owner': is_owner,
        #     'can_compare': can_compare,
        #     'can_revert_file': can_revert_file,
        #     'days': days,
        #     'referer': referer,
        #     }, context_instance=RequestContext(request))
        list_commits = []
        for c in commits[0:-1]:
            list_commits.append({
                'ctime': c.props.ctime,
                'is_first_commit': c.is_first_commit,
                'rev_renamed_old_path': c.rev_renamed_old_path,
                'creator': get_user_common_info(c.creator_name),
                'rev_file_size': c.rev_file_size,
                'rev_file_id': c.rev_file_id,
                'id': c.id,
                'path': c.path 
            })
        resp = {
            'repo_id': repo.id,
            'path': path,
            'u_filename': u_filename,
            'zipped': zipped,
            'commits': list_commits,
            'is_owner': is_owner,
            'can_compare': can_compare,
            'can_revert_file': can_revert_file,
            'days': days,
            # 'referer': referer,
        }
        return api_response(data=resp)
