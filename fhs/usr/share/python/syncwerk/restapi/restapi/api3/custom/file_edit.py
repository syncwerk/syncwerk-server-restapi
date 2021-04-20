import sys
import chardet
import logging
import os
import urllib2
import hashlib

from django.utils.translation import ugettext as _
from django.utils.encoding import force_bytes

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

from restapi.utils import get_file_type_and_ext, gen_inner_file_get_url, mkstemp, gen_file_get_url
from restapi.views import check_folder_permission, check_file_lock

from synserv import get_repo, get_file_id_by_path, syncwserv_threaded_rpc, syncwerk_api
from pyrpcsyncwerk import RpcsyncwerkError

import restapi.settings as settings
from restapi.settings import FILE_ENCODING_LIST, FILE_ENCODING_TRY_LIST
from restapi.utils.file_types import (IMAGE, PDF, DOCUMENT, SPREADSHEET, AUDIO,
                                     MARKDOWN, TEXT, VIDEO)

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class FileEditView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get file edit params',
        operation_description='''Get file edit params''',
        tags=['files'],
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
                description='path of the file',
                required=True,
            ),
            openapi.Parameter(
                name='file_enc',
                in_="query",
                type='string',
                description='file encoding. Default is "auto"',
            ),
            openapi.Parameter(
                name='from',
                in_="query",
                type='string',
                description='from',
            ),
            openapi.Parameter(
                name='gid',
                in_="query",
                type='string',
                description='gid',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Params retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "encoding": "utf-8",
                            "head_id": "a1c88ed0d8d1db400a911aa31e624b2cfa5de450",
                            "filetype": "Text",
                            "path": "/test.csv",
                            "file_encoding_list": [
                                "auto",
                                "utf-8",
                                "gbk",
                                "ISO-8859-1",
                                "ISO-8859-5"
                            ],
                            "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                            "from": "",
                            "err": "",
                            "file_content": "",
                            "u_filename": "test.csv",
                            "fileext": "csv",
                            "gid": "",
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
                            "op": None
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

        path = request.GET.get('p', '/')
        if path[-1] == '/':
            path = path[:-1]
        u_filename = os.path.basename(path)
        filename = urllib2.quote(u_filename.encode('utf-8'))
        parent_dir = os.path.dirname(path)

        if check_folder_permission(request, repo.id, parent_dir) != 'rw':
            # return render_permission_error(request, _(u'Unable to edit file'))
            return api_error(status.HTTP_401_UNAUTHORIZED, 'Unable to edit file')

        head_id = repo.head_cmmt_id

        obj_id = get_file_id_by_path(repo_id, path)
        if not obj_id:
            # return render_error(request, _(u'The file does not exist.'))
            return api_error(status.HTTP_404_NOT_FOUND, 'The file does not exist.')

        doc_key = hashlib.md5(force_bytes(repo_id + path + obj_id)).hexdigest()[:20]

        token = syncwerk_api.get_fileserver_access_token(repo_id,
                obj_id, 'view', request.user.username)

        if not token:
            # return render_error(request, _(u'Unable to view file'))
            return api_error(status.HTTP_401_UNAUTHORIZED, 'Unable to view file')

        doc_url = gen_file_get_url(token, u_filename)

        # generate path and link
        zipped = gen_path_link(path, repo.name)

        filetype, fileext = get_file_type_and_ext(filename)

        op = None
        err = ''
        file_content = None
        encoding = None
        file_encoding_list = FILE_ENCODING_LIST
        if filetype == TEXT or filetype == MARKDOWN:
            if repo.encrypted:
                repo.password_set = syncwerk_api.is_password_set(repo_id, request.user.username)
                if not repo.password_set:
                    op = 'decrypt'
            if not op:
                inner_path = gen_inner_file_get_url(token, filename)
                file_enc = request.GET.get('file_enc', 'auto')
                if not file_enc in FILE_ENCODING_LIST:
                    file_enc = 'auto'
                err, file_content, encoding = repo_file_get(inner_path, file_enc)
                if encoding and encoding not in FILE_ENCODING_LIST:
                    file_encoding_list.append(encoding)
        else:
            err = _(u'Edit online is not offered for this type of file.')

        # Redirect to different place according to from page when user click
        # cancel button on file edit page.
        # cancel_url = reverse('view_lib_file', args=[repo.id, path])
        page_from = request.GET.get('from', '')
        gid = request.GET.get('gid', '')
        # wiki_name = os.path.splitext(u_filename)[0]
        # if page_from == 'wiki_page_edit' or page_from == 'wiki_page_new':
        #     cancel_url = reverse('group_wiki', args=[gid, wiki_name])
        # elif page_from == 'personal_wiki_page_edit' or page_from == 'personal_wiki_page_new':
        #     cancel_url = reverse('personal_wiki', args=[wiki_name])

        # return render_to_response('file_edit.html', {
        #     'repo':repo,
        #     'u_filename':u_filename,
        #     'wiki_name': wiki_name,
        #     'path':path,
        #     'zipped':zipped,
        #     'filetype':filetype,
        #     'fileext':fileext,
        #     'op':op,
        #     'err':err,
        #     'file_content':file_content,
        #     'encoding': encoding,
        #     'file_encoding_list':file_encoding_list,
        #     'head_id': head_id,
        #     'from': page_from,
        #     'gid': gid,
        #     'cancel_url': cancel_url,
        # }, context_instance=RequestContext(request))
        resp = {
            'repo_id': repo.id,
            'u_filename': u_filename,
            # 'wiki_name': wiki_name,
            'path': path,
            'zipped': zipped,
            'filetype': filetype,
            'fileext': fileext,
            'op': op,
            'err': err,
            'file_content': file_content,
            'encoding': encoding,
            'file_encoding_list': file_encoding_list,
            'head_id': head_id,
            'from': page_from,
            'gid': gid,
            'doc_key': doc_key,
            'doc_url': doc_url
            # 'cancel_url': cancel_url,
        }
        return api_response(data=resp)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Submit file edit',
        operation_description='''Submit file edit''',
        tags=['files'],
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
                description='path of the file',
                required=True,
            ),
            openapi.Parameter(
                name='head',
                in_="query",
                type='string',
                description='file head id',
                required=True
            ),
            openapi.Parameter(
                name='from',
                in_="query",
                type='string',
                description='from',
            ),
            openapi.Parameter(
                name='gid',
                in_="query",
                type='string',
                description='gid',
            ),
            openapi.Parameter(
                name='content',
                in_="formData",
                type='string',
                description='content to update',
                required=True,
            ),
            openapi.Parameter(
                name='encoding',
                in_="query",
                type='string',
                description='file encode. Default to "auto"',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Edit file successfully',
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
        
        path = request.GET.get('p')
        username = request.user.username
        parent_dir = os.path.dirname(path)

        # edit file, so check parent_dir's permission
        if check_folder_permission(request, repo_id, parent_dir) != 'rw':
            # return error_json(_(u'Permission denied'))
            return api_error(status.HTTP_400_BAD_REQUEST, 'Permission denied')

        is_locked, locked_by_me = check_file_lock(repo_id, path, username)
        if (is_locked, locked_by_me) == (None, None):
            # return error_json(_(u'Check file lock error'))
            return api_error(status.HTTP_400_BAD_REQUEST, 'Check file lock error')

        if is_locked and not locked_by_me:
            # return error_json(_(u'File is locked'))
            return api_error(status.HTTP_400_BAD_REQUEST, 'File is locked')

        repo = get_repo(repo_id)
        if not repo:
            # return error_json(_(u'The library does not exist.'))
            return api_error(status.HTTP_400_BAD_REQUEST, _(u'The library does not exist.'))
        if repo.encrypted:
            repo.password_set = syncwerk_api.is_password_set(repo_id, username)
            if not repo.password_set:
                # return error_json(_(u'The library is encrypted.'), 'decrypt')
                return api_error(status.HTTP_400_BAD_REQUEST, 'The library is encrypted.', {'op':'decrypt'})

        content = request.POST.get('content')
        encoding = request.POST.get('encoding')

        if content is None or not path or encoding not in FILE_ENCODING_LIST:
            # return error_json(_(u'Invalid arguments.'))
            return api_error(status.HTTP_400_BAD_REQUEST, _(u'Invalid arguments.'))
        head_id = request.GET.get('head', None)

        # first dump the file content to a tmp file, then update the file
        fd, tmpfile = mkstemp()
        def remove_tmp_file():
            try:
                os.remove(tmpfile)
            except:
                pass

        if encoding == 'auto':
            encoding = sys.getfilesystemencoding()

        try:
            content = content.encode(encoding)
        except UnicodeEncodeError as e:
            remove_tmp_file()
            # return error_json(_(u'The encoding you chose is not proper.'))
            return api_error(status.HTTP_400_BAD_REQUEST, 'The encoding you chose is not proper.')

        try:
            bytesWritten = os.write(fd, content)
        except:
            bytesWritten = -1
        finally:
            os.close(fd)

        if bytesWritten != len(content):
            remove_tmp_file()
            # return error_json()
            return api_error(status.HTTP_400_BAD_REQUEST, '')

        req_from = request.GET.get('from', '')
        # if req_from == 'wiki_page_edit' or req_from == 'wiki_page_new':
        #     try:
        #         gid = int(request.GET.get('gid', 0))
        #     except ValueError:
        #         gid = 0

        #     wiki_name = os.path.splitext(os.path.basename(path))[0]
        #     next = reverse('group_wiki', args=[gid, wiki_name])
        # elif req_from == 'personal_wiki_page_edit' or req_from == 'personal_wiki_page_new':
        #     wiki_name = os.path.splitext(os.path.basename(path))[0]
        #     next = reverse('personal_wiki', args=[wiki_name])
        # else:
        #     next = reverse('view_lib_file', args=[repo_id, path])

        parent_dir = os.path.dirname(path).encode('utf-8')
        filename = os.path.basename(path).encode('utf-8')
        try:
            syncwserv_threaded_rpc.put_file(repo_id, tmpfile, parent_dir,
                                    filename, username, head_id)
            remove_tmp_file()
            # return HttpResponse(json.dumps({'href': next}),
            #                     content_type=content_type)
            return api_response()
        except RpcsyncwerkError, e:
            remove_tmp_file()
            # return error_json(str(e))
            return api_error(status.HTTP_400_BAD_REQUEST, str(e))


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
