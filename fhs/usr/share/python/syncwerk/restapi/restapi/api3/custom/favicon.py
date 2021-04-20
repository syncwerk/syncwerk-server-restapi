import os
import logging

from django.http import HttpResponse

from rest_framework.views import APIView

from restapi.settings import MEDIA_ROOT

from restapi.api3.utils import api_error
from restapi.api3.endpoints.admin.favicon import CUSTOM_FAVICON_PATH

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class Favicon(APIView):

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Get page favicon',
        operation_description='''Get page favicon''',
        tags=['other'],
        responses={
            200: openapi.Response(
                description='Page favicon retrieved successfully',
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
    def get(self, request):
        favicon_path = os.path.join(MEDIA_ROOT, 'img/favicon.ico')
        if os.path.isfile(os.path.join(MEDIA_ROOT, CUSTOM_FAVICON_PATH)):
            favicon_path = os.path.join(MEDIA_ROOT, CUSTOM_FAVICON_PATH)
        try:
            with open(favicon_path, 'rb') as f:
                favicon = f.read()
            return HttpResponse(favicon, 'image/' + 'ico')
        except IOError as e:
                logger.error(e)
                return api_error(code=500, msg='Failed to get favicon.')
