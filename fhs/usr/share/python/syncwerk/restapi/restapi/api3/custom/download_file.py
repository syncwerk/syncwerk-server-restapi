import os
import stat

from django.http import Http404
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

import restapi.settings as settings
from restapi.views import check_folder_permission
from restapi.utils import gen_file_get_url

from synserv import syncwerk_api, get_repo

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class DownloadFile(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
	
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get file download link in snapshot',
        operation_description='''Get download link of a file in a history snapshot''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='obj_id',
                in_="path",
                type='string',
                description='object id of the file',
            ),
            openapi.Parameter(
                name='p',
                in_="query",
                type='string',
                description='file path',
            ),
        ],
        responses={
            200: openapi.Response(
                description='retrived download link successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "download_link": "https://file/download/link"
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
    def get(self, request, repo_id, obj_id, format=None):
        
        username = request.user.username
        repo = get_repo(repo_id)
        if not repo:
            # raise Http404
            return api_error(status.HTTP_404_NOT_FOUND, 'Repo is not exist')

        if repo.encrypted and not syncwerk_api.is_password_set(repo_id, username):
            # return HttpResponseRedirect(reverse('view_common_lib_dir', args=[repo_id, '']))
            return api_error(status.HTTP_403_FORBIDDEN, 'Password protected')

        # only check the permissions at the repo level
        # to prevent file can not be downloaded on the history page
        # if it has been renamed
        if check_folder_permission(request, repo_id, '/'):
            # Get a token to access file
            token = syncwerk_api.get_fileserver_access_token(repo_id,
                    obj_id, 'download', username)

            if not token:
                return api_error(status.HTTP_404_NOT_FOUND, 'Unable to download file')
        else:
            return api_error(status.HTTP_404_NOT_FOUND, 'Unable to download file')

        path = request.GET.get('p', '')
        # send_file_access_msg(request, repo, path, 'web') # send stats message
        file_name = os.path.basename(path.rstrip('/'))
        redirect_url = gen_file_get_url(token, file_name) # generate download link

        resp = {
            'download_link': redirect_url
        }
        return api_response(data=resp)
