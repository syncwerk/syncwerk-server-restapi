# Copyright (c) 2012-2016 Seafile Ltd.
from rest_framework import status
from rest_framework.permissions import IsAuthenticated

from synserv import syncwerk_api
from restapi import settings
from restapi.api2.base import APIView
from restapi.api2.throttling import AnonRateThrottle, UserRateThrottle
from restapi.api2.utils import json_response, api_error
from restapi.api2.authentication import TokenAuthentication
from restapi.api2.models import Token, TokenV2
from restapi.base.models import ClientLoginToken
from restapi.utils import gen_token
from restapi.utils.two_factor_auth import has_two_factor_auth, two_factor_auth_enabled

class LogoutDeviceView(APIView):
    """Removes the api token of a device that has already logged in. If the device
    is a desktop client, also remove all sync tokens of repos synced on that
    client .
    """
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @json_response
    def post(self, request, format=None):
        auth_token = request.auth
        if isinstance(auth_token, TokenV2) and auth_token.is_desktop_client():
            syncwerk_api.delete_repo_tokens_by_peer_id(request.user.username, auth_token.device_id)
        auth_token.delete()
        return {}

class ClientLoginTokenView(APIView):
    """Generate a token which can be used later to login directly.

    This is used to quickly login to restapi from desktop clients. The token
    can only be used once, and would only be valid in 30 seconds after
    creation.
    """
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @json_response
    def post(self, request, format=None):
        if has_two_factor_auth() and two_factor_auth_enabled(request.user):
            return {}
        randstr = gen_token(max_length=32)
        token = ClientLoginToken(token=randstr, username=request.user.username)
        token.save()
        return {'token': randstr}
