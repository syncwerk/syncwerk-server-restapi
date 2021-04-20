import os
import logging

from django.http import HttpResponse

from rest_framework.views import APIView

from restapi.settings import MEDIA_ROOT

from restapi.api3.utils import api_error
from restapi.api3.endpoints.admin.logo import CUSTOM_LOGO_PATH

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class Logo(APIView):
    
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Get page logo',
        operation_description='''Get page logo''',
        tags=['other'],
        responses={
            200: openapi.Response(
                description='Page logo retrieved successfully',
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
        logo_path = os.path.join(MEDIA_ROOT, 'img/syncwerk-logo.png')
        if os.path.isfile(os.path.join(MEDIA_ROOT, CUSTOM_LOGO_PATH)):
            logo_path = os.path.join(MEDIA_ROOT, CUSTOM_LOGO_PATH)
        try:
            with open(logo_path, 'rb') as f:
                logo = f.read()
            return HttpResponse(logo, 'image/' + 'png')
        except IOError as e:
                logger.error(e)
                return api_error(code=500, msg='Failed to get thumbnail.')
