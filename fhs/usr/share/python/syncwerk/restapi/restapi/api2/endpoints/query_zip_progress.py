# Copyright (c) 2012-2016 Seafile Ltd.
import logging
import json

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from restapi.api2.throttling import UserRateThrottle
from restapi.api2.utils import api_error

from synserv import syncwerk_api

logger = logging.getLogger(__name__)

class QueryZipProgressView(APIView):

    throttle_classes = (UserRateThrottle, )

    def get(self, request, format=None):
        """ check progress when download dir/multi.

        Permission checking:
        """

        token = request.GET.get('token', None)
        if not token:
            error_msg = 'token invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            progress = syncwerk_api.query_zip_progress(token)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return Response(json.loads(progress))
