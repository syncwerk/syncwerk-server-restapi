# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.utils.translation import ugettext as _

from restapi.api2.throttling import UserRateThrottle
from restapi.api2.authentication import TokenAuthentication
from restapi.api2.utils import api_error

from synserv import syncwerk_api

logger = logging.getLogger(__name__)

class QueryCopyMoveProgressView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        """ Fetch progress of file/dir mv/cp.

        Permission checking:
        1. user login;
        """

        # argument check
        task_id = request.GET.get('task_id')
        if not task_id:
            error_msg = 'task_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            res = syncwerk_api.get_copy_task(task_id)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # res can be None
        if not res:
            error_msg = _(u'Error')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        result = {}
        result['done'] = res.done
        result['total'] = res.total
        result['canceled'] = res.canceled
        result['failed'] = res.failed
        result['successful'] = res.successful
        return Response(result)
