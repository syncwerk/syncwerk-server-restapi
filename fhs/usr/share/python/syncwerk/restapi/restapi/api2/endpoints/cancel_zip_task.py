# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from restapi.api2.throttling import UserRateThrottle
from restapi.api2.utils import api_error

from synserv import syncwerk_api

logger = logging.getLogger(__name__)


class CancelZipTaskView(APIView):

    throttle_classes = (UserRateThrottle, )

    def post(self, request, format=None):
        """ stop progress when download dir/multi.
        Permission checking:
        """
        token = request.POST.get('token', None)
        if not token:
            error_msg = 'token invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            process = syncwerk_api.cancel_zip_task(token)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return Response({'success': True})
