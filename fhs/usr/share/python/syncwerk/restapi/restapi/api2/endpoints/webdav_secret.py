# Copyright (c) 2012-2016 Seafile Ltd.
import logging
from django.conf import settings
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from restapi.api2.authentication import TokenAuthentication
from restapi.api2.throttling import UserRateThrottle
from restapi.api2.utils import api_error
from restapi.options.models import UserOptions
from restapi.utils.hasher import AESPasswordHasher

# Get an instance of a logger
logger = logging.getLogger(__name__)


class WebdavSecretView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def get(self, request, format=None):
        if not settings.ENABLE_WEBDAV_SECRET:
            return api_error(status.HTTP_403_FORBIDDEN,
                             'Feature is not enabled.')

        username = request.user.username
        decoded = UserOptions.objects.get_webdav_decoded_secret(username)

        return Response({
            'secret': decoded,
        })

    def put(self, request, format=None):
        if not settings.ENABLE_WEBDAV_SECRET:
            return api_error(status.HTTP_403_FORBIDDEN,
                             'Feature is not enabled.')

        aes = AESPasswordHasher()

        username = request.user.username
        secret = request.data.get("secret", None)

        if secret:
            encoded = aes.encode(secret)
            UserOptions.objects.set_webdav_secret(username, encoded)
        else:
            UserOptions.objects.unset_webdav_secret(username)

        return self.get(request, format)
