import logging
import os

from django.http import HttpResponse

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.utils import api_error
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle

from restapi.thumbnail.utils import generate_thumbnail
from restapi.settings import THUMBNAIL_EXTENSION, THUMBNAIL_ROOT, ENABLE_THUMBNAIL
from restapi.views import check_folder_permission, get_system_default_repo_id

from synserv import syncwerk_api, get_repo, get_file_id_by_path

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class ThumbnailView(APIView):

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get thumbnail for image files',
        operation_description='''Get thumbnail for image file''',
        tags=['files'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='repo id that the file is in.',
            ),
            openapi.Parameter(
                name='p',
                in_="query",
                type='string',
                description='path to the image file to retriving thumbnail.',
                required=True,
            ),
            openapi.Parameter(
                name='size',
                in_="query",
                type='string',
                description='size of the thumbnail.',
            ),
            openapi.Parameter(
                name='obj_id',
                in_="query",
                type='string',
                description='object id.',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Thumbnail retrieved successfully.',
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
    def get(self, request, repo_id, format=None):
        repo = get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')

        size = request.GET.get('size', None)
        if size is None:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Size is missing.')

        try:
            size = int(size)
        except ValueError as e:
            logger.error(e)
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid size.')

        path = request.GET.get('p', None)
        obj_id = get_file_id_by_path(repo_id, path)
        if obj_id is None:
            obj_id = request.GET.get('obj_id', None)
        if path is None or obj_id is None:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Wrong path.')

        # username = request.user.username
        # if (repo.encrypted and not syncwerk_api.is_password_set(repo.id, username)) or \
        #     not ENABLE_THUMBNAIL or \
        #     repo.id == get_system_default_repo_id() or\
        #     check_folder_permission(request, repo_id, path) is None:
        #     return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')

        thumbnail_dir = os.path.join(THUMBNAIL_ROOT, str(size))
        if not os.path.exists(thumbnail_dir):
            os.makedirs(thumbnail_dir)
        thumbnail_file = os.path.join(thumbnail_dir, obj_id)
        if os.path.exists(thumbnail_file):
            success, status_code = (True, 200)
        else:
            success, status_code = generate_thumbnail(request, repo_id, size, path)
        if success:
            thumbnail_dir = os.path.join(THUMBNAIL_ROOT, str(size))
            thumbnail_file = os.path.join(thumbnail_dir, obj_id)
            try:
                with open(thumbnail_file, 'rb') as f:
                    thumbnail = f.read()
                return HttpResponse(thumbnail, 'image/' + THUMBNAIL_EXTENSION)
            except IOError as e:
                logger.error(e)
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Failed to get thumbnail.')
        else:
            if status_code == 400:
                return api_error(status.HTTP_400_BAD_REQUEST, "Invalid argument")
            if status_code == 403:
                return api_error(status.HTTP_403_FORBIDDEN, 'Forbidden')
            if status_code == 500:
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Failed to generate thumbnail.')
