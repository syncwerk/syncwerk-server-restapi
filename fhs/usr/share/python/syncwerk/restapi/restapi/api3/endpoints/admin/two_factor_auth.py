# Copyright (c) 2012-2016 Seafile Ltd.
from rest_framework import status
from rest_framework.permissions import IsAdminUser
from rest_framework.authentication import SessionAuthentication
from rest_framework.response import Response

from restapi.base.accounts import User
from restapi.api2.base import APIView
from restapi.api2.throttling import UserRateThrottle
from restapi.api2.utils import json_response, api_error
from restapi.api2.authentication import TokenAuthentication
from restapi.utils.two_factor_auth import has_two_factor_auth, two_factor_auth_enabled


class TwoFactorAuthView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)

    def delete(self, request, email):
        if not email:
            error_msg = "email can not be empty"
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
        try:
            _user = User.objects.get(email=email)
        except User.DoesNotExist:
            error_msg = "User %s not found" % email
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        from restapi_extra.two_factor import devices_for_user
        devices = devices_for_user(_user)
        if devices:
            for device in devices:
                device.delete()
        return Response({'success':True}, status=status.HTTP_200_OK)
