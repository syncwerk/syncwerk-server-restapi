# Copyright (c) 2012-2016 Seafile Ltd.
import logging
import os
import json
import posixpath

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from django.conf import settings

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response
from restapi.api2.models import Token, TokenV2
from restapi.profile.models import Profile
from restapi.base.accounts import User

from restapi.views.file import send_file_access_msg
from restapi.share.models import FileShare
from restapi.utils import is_windows_operating_system, \
    is_pro_version, gen_dir_zip_download_url

import synserv
from synserv import syncwerk_api

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)

def isUserAuthenticated(request):
    key = request.COOKIES.get('token')

    if not key:
        return False
    if ' ' in key:
        return False

    try:
        token = Token.objects.get(key=key)
    except Token.DoesNotExist:
        return False

    try:
        username = Profile.objects.get_username_by_login_id(token.user)
        if username is None:
            email = token.user
        else:
            email = username
        user = User.objects.get(email=email)
        if not user.is_active:
            return False
        return True
    except User.DoesNotExist:
        return False

class ShareLinkZipTaskView(APIView):

    throttle_classes = (UserRateThrottle,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get url for zipping / multi-download in public share',
        operation_description='''Only used for download folder when view foler share link from web.''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='share_link_token',
                in_="query",
                type='string',
                description='share link token.',
                required=True,
            ),
            openapi.Parameter(
                name='path',
                in_="query",
                type='string',
                description='path for download.',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Url retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "url": "https://alpha.syncwerk.com/seafhttp/zip/908d6753-3f23-47bb-8927-25ed07553ebe",
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

        # permission check
        if is_pro_version() and settings.ENABLE_SHARE_LINK_AUDIT:
            if not isUserAuthenticated(request) and \
                not request.session.get('anonymous_email'):
                # if anonymous user has passed email code check,
                # then his/her email info will be in session.

                error_msg = 'Permission denied.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # argument check
        share_link_token = request.GET.get('share_link_token', None)
        if not share_link_token:
            error_msg = 'share_link_token invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        req_path = request.GET.get('path', None)
        if not req_path:
            error_msg = 'path invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # recourse check
        fileshare = FileShare.objects.get_valid_dir_link_by_token(share_link_token)
        if not fileshare:
            error_msg = 'share_link_token %s not found.' % share_link_token
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if req_path[-1] != '/':
            req_path += '/'

        if req_path == '/':
            real_path = fileshare.path
        else:
            real_path = posixpath.join(fileshare.path, req_path.lstrip('/'))

        if real_path[-1] != '/':
            real_path += '/'

        repo_id = fileshare.repo_id
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        dir_id = syncwerk_api.get_dir_id_by_path(repo_id, real_path)
        if not dir_id:
            error_msg = 'Folder %s not found.' % real_path
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # get file server access token
        dir_name = repo.name if real_path == '/' else \
                os.path.basename(real_path.rstrip('/'))

        dir_size = syncwerk_api.get_dir_size(
                repo.store_id, repo.version, dir_id)
        if dir_size > synserv.MAX_DOWNLOAD_DIR_SIZE:
            error_msg = 'Unable to download directory "%s": size is too large.' % dir_name
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            synserv.send_message('restapi.stats', 'dir-download\t%s\t%s\t%s\t%s' %
                                 (repo_id, fileshare.username, dir_id, dir_size))
        except Exception as e:
            logger.error(e)

        is_windows = 0
        if is_windows_operating_system(request):
            is_windows = 1

        fake_obj_id = {
            'obj_id': dir_id,
            'dir_name': dir_name,
            'is_windows': is_windows
        }

        username = request.user.username
        try:
            # zip_token = syncwerk_api.get_fileserver_access_token(
            #         repo_id, json.dumps(fake_obj_id), 'download-dir', username)
            zip_token = syncwerk_api.get_fileserver_access_token(
                repo_id, json.dumps(fake_obj_id), 'download-dir-link',
                fileshare.username, use_onetime=False
            )
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if not zip_token:
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if request.session.get('anonymous_email'):
            request.user.username = request.session.get('anonymous_email')

        send_file_access_msg(request, repo, real_path, 'share-link')

        # return Response({'zip_token': zip_token})
        url = gen_dir_zip_download_url(zip_token)
        resp = {'url': url}
        return api_response(data=resp)
