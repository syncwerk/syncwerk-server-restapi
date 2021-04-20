import json
import logging
import os

from django.conf import settings as dj_settings
from django.db.models import F
from django.utils.translation import ugettext as _

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from restapi.api3.base import APIView
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response
from restapi.api3.utils.file import get_max_upload_file_size

from restapi.share.models import UploadLinkShare
from restapi.views import check_folder_permission
from restapi.utils import gen_file_upload_url, is_pro_version

import synserv
from synserv import syncwerk_api, check_quota
from pyrpcsyncwerk import RpcsyncwerkError

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema


HTTP_520_OPERATION_FAILED = 520

logger = logging.getLogger(__name__)


class UploadLinkView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get upload link',
        operation_description='''Get links for uploading a file / folder''',
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
                name='from',
                in_="query",
                type='string',
                description='"api" or "web"',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Upload link retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "url": "https://the/upload/link",
                            "max_upload_file_size": 209715200
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
        
        # recourse check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        parent_dir = request.GET.get('p', '/')
        dir_id = syncwerk_api.get_dir_id_by_path(repo_id, parent_dir)
        if not dir_id:
            error_msg = 'Folder %s not found.' % parent_dir
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if check_folder_permission(request, repo_id, parent_dir) != 'rw':
            return api_error(status.HTTP_403_FORBIDDEN, 'You do not have permission to access this folder.')

        if check_quota(repo_id) < 0:
            return api_error(HTTP_520_OPERATION_FAILED, _('Above quota'))

        token = syncwerk_api.get_fileserver_access_token(repo_id, 'dummy', 'upload', request.user.username, use_onetime=False)

        if not token:
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        req_from = request.GET.get('from', 'api')
        if req_from == 'api':
            url = gen_file_upload_url(token, 'upload-api')
        elif req_from == 'web':
            url = gen_file_upload_url(token, 'upload-aj')
        else:
            error_msg = 'from invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # return Response(url)
        repo_owner = syncwerk_api.get_repo_owner(repo_id)
        print repo_owner  # this is already an email string
        repo_owner_storage_quota = syncwerk_api.get_user_quota(repo_owner)
        repo_owner_storage_used = syncwerk_api.get_user_self_usage(repo_owner)
        resp = { 
            'url': url,
            'max_upload_file_size': get_max_upload_file_size(),
            'storage_usage': repo_owner_storage_used,
            'storage_quota': repo_owner_storage_quota
        }
        return api_response(data=resp)


class UploadLinkSharedView(APIView):
    throttle_classes = (UserRateThrottle,)
    
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Get upload url in upload link',
        operation_description='''Get links for uploading a file / folder in upload link''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Upload link retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "url": "https://the/upload/link",
                            "max_upload_file_size": 209715200
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
    def get(self, request, token, format=None):
        uls = UploadLinkShare.objects.get_valid_upload_link_by_token(token)
        if uls is None:
            # return HttpResponse(json.dumps({"error": _("Bad upload link token.")}),
            #                     status=400, content_type=content_type)
            return api_error(code=status.HTTP_400_BAD_REQUEST, msg=_(u'Bad upload link token.'))

        repo_id = uls.repo_id
        shared_by = uls.username
        r = request.GET.get('repo_id', '')
        if repo_id != r:            # perm check
            # return HttpResponse(json.dumps({"error": _("Bad repo id in upload link.")}),
            #                     status=403, content_type=content_type)
            return api_error(code=status.HTTP_403_FORBIDDEN, msg=_(u'Bad repo id in upload link.'))

        # username = request.user.username or request.session.get('anonymous_email') or ''
        dir_id = syncwerk_api.get_dir_id_by_path(uls.repo_id, uls.path)
        # args = [repo_id, json.dumps({'anonymous_user': username}), 'upload', '']
        
        # Disable creator name for audit log, upload file via public upload should be null
        args = [repo_id, dir_id, 'upload-link', '']
        # args = [repo_id, dir_id, 'upload-link', shared_by]
        kwargs = {
            'use_onetime': False,
        }
        # if (is_pro_version() and dj_settings.ENABLE_UPLOAD_LINK_VIRUS_CHECK):
        #     kwargs.update({'check_virus': True})

        try:
            acc_token = syncwerk_api.get_fileserver_access_token(*args, **kwargs)
        except RpcsyncwerkError as e:
            logger.error(e)
            # return HttpResponse(json.dumps({"error": _("Internal Server Error")}),
            #                     status=500, content_type=content_type)
            return api_error(code=status.HTTP_500_INTERNAL_SERVER_ERROR, msg=_(u'Internal Server Error'))

        if not acc_token:
            # return HttpResponse(json.dumps({"error": _("Internal Server Error")}),
            #                     status=500, content_type=content_type)
            return api_error(code=status.HTTP_500_INTERNAL_SERVER_ERROR, msg=_(u'Internal Server Error'))

        url = gen_file_upload_url(acc_token, 'upload-aj')
        # return HttpResponse(json.dumps({"url": url}), content_type=content_type)
        # return Response(url)
        repo_owner = syncwerk_api.get_repo_owner(repo_id)
        print repo_owner  # this is already an email string
        repo_owner_storage_quota = syncwerk_api.get_user_quota(repo_owner)
        repo_owner_storage_used = syncwerk_api.get_user_self_usage(repo_owner)
        resp = { 
            'url': url,
            'max_upload_file_size': get_max_upload_file_size(),
            'storage_usage': repo_owner_storage_used,
            'storage_quota': repo_owner_storage_quota
        }
        # resp = {
        #     'url': url,
        #     'max_upload_file_size': get_max_upload_file_size(),
        # }
        return api_response(data=resp)
