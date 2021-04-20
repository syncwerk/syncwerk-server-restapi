import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.utils.translation import ugettext as _

from pyrpcsyncwerk import RpcsyncwerkError
from synserv import syncwerk_api

from restapi.api2.authentication import TokenAuthentication
from restapi.api2.throttling import UserRateThrottle
from restapi.api2.utils import api_error

from constance import config

logger = logging.getLogger(__name__)


class AdminLibraryHistoryLimit(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )

    def get(self, request, repo_id, format=None):

        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # no settings for virtual repo
        if repo.is_virtual:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        try:
            keep_days = syncwerk_api.get_repo_history_limit(repo_id)
            return Response({'keep_days': keep_days})
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

    def put(self, request, repo_id, format=None):

        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # no settings for virtual repo
        if repo.is_virtual:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # check arg validation
        keep_days = request.data.get('keep_days', None)
        if not keep_days:
            error_msg = 'keep_days invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            keep_days = int(keep_days)
        except ValueError:
            error_msg = 'keep_days invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            # days <= -1, keep full history
            # days = 0, not keep history
            # days > 0, keep a period of days
            res = syncwerk_api.set_repo_history_limit(repo_id, keep_days)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if res == 0:
            new_limit = syncwerk_api.get_repo_history_limit(repo_id)
            return Response({'keep_days': new_limit})
        else:
            error_msg = 'Failed to set library history limit.'
            return api_error(status.HTTP_520_OPERATION_FAILED, error_msg)
