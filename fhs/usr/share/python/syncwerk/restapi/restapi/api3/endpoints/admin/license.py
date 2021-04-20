import os
import logging
import ConfigParser

from django.utils.translation import ugettext as _

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from synserv import ccnet_api

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error
from restapi.settings import LICENSE_PATH, SYNCWERK_SERVER_EXEC
from shutil import copyfile

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class AdminLicense(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle, )
    permission_classes = (IsAdminUser,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Upload license file',
        operation_description='''Upload license file''',
        tags=['admin-system'],
        manual_parameters=[
            openapi.Parameter(
                name='license',
                in_="formData",
                type='file',
                description='Syncwerk license file',
            ),
        ],
        responses={
            200: openapi.Response(
                description='License update successfully',
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
    def post(self, request):
        # Check if authorization file is in the request
        license_file = request.FILES.get('license', None)
        license_text = request.data.get('license_text', None)
        if not license_file and not license_text:
            error_msg = _('Please provide authorization file or text.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
        # Copy lic file to tmp folder for validation
        with open('/tmp/syncwerk-server.key', 'w') as fd:
            fd.write(license_file.read() if license_file else license_text)
        # Call the c++ syncwerk-server to check if the authorization file is valid or not
        lic_file_validate_result = os.system(SYNCWERK_SERVER_EXEC+' check-authorization-key /tmp/syncwerk-server.key')
        if lic_file_validate_result == 1:
            # os.remove('/tmp/syncwerk-server.key')
            error_msg = _('authorization file invalid')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        license_dir = os.path.dirname(LICENSE_PATH)
        try:
            if not os.path.exists(license_dir):
                error_msg = 'path %s invalid.' % LICENSE_PATH
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
            # Get the current number of user in the system
            active_db_users = ccnet_api.count_emailusers('DB')
            # inactive_db_users = ccnet_api.count_inactive_emailusers('DB')
            number_of_user = active_db_users
            # Parse the authorization file & get the number of allowed users
            config = ConfigParser.ConfigParser()
            config.read("/tmp/syncwerk-server.key")
            no_licensed_users = config.getint('SYNCWERK-SERVER', 'allowed_users')
            # check if there's currently more users than the authorization allows
            if number_of_user > no_licensed_users:
                error_msg = _('You currently have more active users than the authorization allows.')
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
            copyfile('/tmp/syncwerk-server.key', LICENSE_PATH)
            os.remove('/tmp/syncwerk-server.key')

            # ccnet_api.reload_license()
        except Exception as e:
            logger.error(e)
            error_msg = _('Internal Server Error')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)
        # Count number of current user
        return Response({'success': True, 'message': _('Authorization file uploaded')}, status=status.HTTP_200_OK)
