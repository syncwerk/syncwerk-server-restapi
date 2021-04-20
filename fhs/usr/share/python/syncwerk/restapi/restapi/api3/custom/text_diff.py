import chardet
import logging
import os
import urllib2

from django.utils.translation import ugettext as _

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from restapi.api3.base import APIView
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

from synserv import syncwerk_api
from synserv import get_repo, syncwserv_threaded_rpc

from restapi.base.templatetags.restapi_tags import email2nickname
from restapi.profile.models import Profile
from restapi.settings import FILE_ENCODING_LIST, FILE_ENCODING_TRY_LIST
from restapi.utils import HtmlDiff, EMPTY_SHA1, gen_inner_file_get_url
from restapi.utils.timeutils import timestamp_to_isoformat_timestr
from restapi.views import check_folder_permission

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class TextDiffView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get text file diff',
        operation_description='''Get diff details for text file''',
        tags=['files'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_='path',
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='p',
                in_='query',
                type='string',
                description='path of the file',
                required=True,
            ),
            openapi.Parameter(
                name='commit',
                in_='query',
                type='string',
                description='commit id',
                required=True
            ),
            openapi.Parameter(
                name='file_enc',
                in_="query",
                type='string',
                description='file encoding. Default to "auto"',
            ),
        ],
        responses={
            200: openapi.Response(
                description='File diff retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "current_commit": {
                                "commit_id": "ef8a7b1a600de4ddfc98e4dfab9ae02758f7a14a",
                                "contact_email": "admin@alpha.syncwerk.com",
                                "name": "admin",
                                "time": "2019-02-20T02:42:15+00:00",
                                "client_version": None,
                                "device_name": None,
                                "email": "admin@alpha.syncwerk.com",
                                "description": "Modified \"test.csv\""
                            },
                            "path": "/test.csv",
                            "zipped": [
                                [
                                    "My Folder",
                                    "/"
                                ],
                                [
                                    "test.csv",
                                    "/test.csv"
                                ]
                            ],
                            "diff_result_table": "            <tr><td class=\"diff-header\"></td><td></td><td class=\"diff-header\">1</td><td class=diff-add>fewfwefwef,</td></tr>\n            <tr><td class=\"diff-header\"></td><td></td><td class=\"diff-header\">2</td><td class=diff-add>fewfewfewf,</td></tr>\n            <tr><td class=\"diff-header\"></td><td></td><td class=\"diff-header\">3</td><td class=diff-add>fewfwegtewtert</td></tr>\n",
                            "prev_commit": {
                                "commit_id": "a1c88ed0d8d1db400a911aa31e624b2cfa5de450",
                                "contact_email": "admin@alpha.syncwerk.com",
                                "name": "admin",
                                "time": "2019-02-19T10:46:46+00:00",
                                "client_version": None,
                                "device_name": None,
                                "email": "admin@alpha.syncwerk.com",
                                "description": "Modified \"email.csv\""
                            },
                            "u_filename": "test.csv",
                            "is_new_file": False
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
        
        commit_id = request.GET.get('commit', '')
        path = request.GET.get('p', '')
        u_filename = os.path.basename(path)
        file_enc = request.GET.get('file_enc', 'auto')
        if not file_enc in FILE_ENCODING_LIST:
            file_enc = 'auto'

        if not (commit_id and path):
            # return render_error(request, 'bad params')
            return api_error(status.HTTP_400_BAD_REQUEST, 'bad params')

        repo = get_repo(repo_id)
        if not repo:
            # return render_error(request, 'bad repo')
            return api_error(status.HTTP_400_BAD_REQUEST, 'bad repo')

        current_commit = syncwserv_threaded_rpc.get_commit(repo.id, repo.version, commit_id)
        if not current_commit:
            # return render_error(request, 'bad commit id')
            return api_error(status.HTTP_400_BAD_REQUEST, 'bad commit id')

        prev_commit = syncwserv_threaded_rpc.get_commit(repo.id, repo.version, current_commit.parent_id)
        if not prev_commit:
            # return render_error('bad commit id')
            return api_error(status.HTTP_400_BAD_REQUEST, 'bad commit id')

        path = path.encode('utf-8')

        current_content, err = get_file_content_by_commit_and_path(request, \
                                        repo_id, current_commit.id, path, file_enc)
        if err:
            # return render_error(request, err)
            return api_error(status.HTTP_400_BAD_REQUEST, err)

        prev_content, err = get_file_content_by_commit_and_path(request, \
                                        repo_id, prev_commit.id, path, file_enc)
        if err:
            # return render_error(request, err)
            return api_error(status.HTTP_400_BAD_REQUEST, err)

        is_new_file = False
        diff_result_table = ''
        if prev_content == '' and current_content == '':
            is_new_file = True
        else:
            diff = HtmlDiff()
            diff_result_table = diff.make_table(prev_content.splitlines(),
                                            current_content.splitlines(), True)

        zipped = gen_path_link(path, repo.name)

        # referer = request.GET.get('referer', '')

        # return render_to_response('text_diff.html', {
        #     'u_filename':u_filename,
        #     'repo': repo,
        #     'path': path,
        #     'zipped': zipped,
        #     'current_commit': current_commit,
        #     'prev_commit': prev_commit,
        #     'diff_result_table': diff_result_table,
        #     'is_new_file': is_new_file,
        #     'referer': referer,
        # }, context_instance=RequestContext(request))
        resp = {
            'u_filename':u_filename,
            'repo_id': repo.id,
            'path': path,
            'zipped': zipped,
            'current_commit': get_commit_info(current_commit),
            'prev_commit': get_commit_info(prev_commit),
            'diff_result_table': diff_result_table,
            'is_new_file': is_new_file,
        }
        return api_response(data=resp)


def get_file_content_by_commit_and_path(request, repo_id, commit_id, path, file_enc):
    try:
        obj_id = syncwserv_threaded_rpc.get_file_id_by_commit_and_path( \
                                        repo_id, commit_id, path)
    except:
        return None, 'bad path'

    if not obj_id or obj_id == EMPTY_SHA1:
        return '', None
    else:
        permission = check_folder_permission(request, repo_id, '/')
        if permission:
            # Get a token to visit file
            token = syncwerk_api.get_fileserver_access_token(repo_id,
                    obj_id, 'view', request.user.username)

            if not token:
                return None, 'FileServer access token invalid'

        else:
            return None, 'permission denied'

        filename = os.path.basename(path)
        inner_path = gen_inner_file_get_url(token, filename)

        try:
            err, file_content, encoding = repo_file_get(inner_path, file_enc)
        except Exception, e:
            return None, 'error when read file from fileserver: %s' % e
        return file_content, err


def repo_file_get(raw_path, file_enc):
    """
    Get file content and encoding.
    """
    err = ''
    file_content = ''
    encoding = None
    if file_enc != 'auto':
        encoding = file_enc

    try:
        file_response = urllib2.urlopen(raw_path)
        content = file_response.read()
    except urllib2.HTTPError, e:
        logger.error(e)
        err = _(u'HTTPError: failed to open file online')
        return err, '', None
    except urllib2.URLError as e:
        logger.error(e)
        err = _(u'URLError: failed to open file online')
        return err, '', None
    else:
        if encoding:
            try:
                u_content = content.decode(encoding)
            except UnicodeDecodeError:
                err = _(u'The encoding you chose is not proper.')
                return err, '', encoding
        else:
            for enc in FILE_ENCODING_TRY_LIST:
                try:
                    u_content = content.decode(enc)
                    encoding = enc
                    break
                except UnicodeDecodeError:
                    if enc != FILE_ENCODING_TRY_LIST[-1]:
                        continue
                    else:
                        encoding = chardet.detect(content)['encoding']
                        if encoding:
                            try:
                                u_content = content.decode(encoding)
                            except UnicodeDecodeError:
                                err = _(u'Unknown file encoding')
                                return err, '', ''
                        else:
                            err = _(u'Unknown file encoding')
                            return err, '', ''

        file_content = u_content

    return err, file_content, encoding


def gen_path_link(path, repo_name):
    """
    Generate navigate paths and links in repo page.

    """
    if path and path[-1] != '/':
        path += '/'

    paths = []
    links = []
    if path and path != '/':
        paths = path[1:-1].split('/')
        i = 1
        for name in paths:
            link = '/' + '/'.join(paths[:i])
            i = i + 1
            links.append(link)
    if repo_name:
        paths.insert(0, repo_name)
        links.insert(0, '/')

    zipped = zip(paths, links)

    return zipped


def get_commit_info(commit):
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
