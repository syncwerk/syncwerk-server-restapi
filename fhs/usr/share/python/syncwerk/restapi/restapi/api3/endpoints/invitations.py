# Copyright (c) 2012-2016 Seafile Ltd.

from django.utils.translation import ugettext as _
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from restapi.api2.authentication import TokenAuthentication
from restapi.api2.permissions import CanInviteGuest
from restapi.api2.throttling import UserRateThrottle
from restapi.api2.utils import api_error
from restapi.base.accounts import User
from restapi.utils import is_valid_email
from restapi.invitations.models import Invitation
from restapi.invitations.utils import block_accepter

json_content_type = 'application/json; charset=utf-8'


class InvitationsView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, CanInviteGuest)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, format=None):
        # List invitations sent by user.
        username = request.user.username

        invitations = []
        for e in Invitation.objects.get_by_inviter(username):
            invitations.append(e.to_dict())

        return Response(invitations)

    def post(self, request, format=None):
        # Send invitation.
        itype = request.data.get('type', '').lower()
        if not itype or itype != 'guest':
            return api_error(status.HTTP_400_BAD_REQUEST, 'type invalid.')

        accepter = request.data.get('accepter', '').lower()
        if not accepter:
            return api_error(status.HTTP_400_BAD_REQUEST, 'accepter invalid.')

        if not is_valid_email(accepter):
            return api_error(status.HTTP_400_BAD_REQUEST,
                             _('Email %s invalid.') % accepter)

        if block_accepter(accepter):
            return api_error(status.HTTP_400_BAD_REQUEST,
                             _('The email address is not allowed to be invited as a guest.'))

        if Invitation.objects.filter(inviter=request.user.username,
                                     accepter=accepter).count() > 0:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             _('%s is already invited.') % accepter)

        try:
            User.objects.get(accepter)
            user_exists = True
        except User.DoesNotExist:
            user_exists = False

        if user_exists:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             _('User %s already exists.') % accepter)

        i = Invitation.objects.add(inviter=request.user.username,
                                   accepter=accepter)
        i.send_to(email=accepter)

        return Response(i.to_dict(), status=201)
