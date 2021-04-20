# Copyright (c) 2012-2016 Seafile Ltd.
import os
import logging

from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from django.utils.translation import ugettext as _
from django.template.defaultfilters import filesizeformat

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response

from restapi.avatar.models import Avatar
from restapi.avatar.signals import avatar_updated
from restapi.avatar.settings import (AVATAR_MAX_AVATARS_PER_USER,
                                     AVATAR_MAX_SIZE, AVATAR_ALLOWED_FILE_EXTS)

logger = logging.getLogger(__name__)

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema
from rest_framework import parsers


class UpdateUserAvatarView(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Update avatar',
        operation_description='Update user avatar',
        tags=['user'],
        manual_parameters=[
            openapi.Parameter(
                name='avatar',
                in_="formData",
                type='file',
                description='Image file to set as user avatar',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Update avatar successfully.',
                examples={
                    'application/json': {
                        "message": "Updated avatar successfully.",
                        "data": None
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
                    }
                }
            ),
            401: openapi.Response(
                description='Unauthenticated / unauthorized.',
                examples={
                    'application/json': {
                        "detail": "Invalid token"
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error',
                examples={
                    'application/json': {
                        "message": "Internal server error"
                    }
                }
            )
        }
    )
    def post(self, request):
        image_file = request.data.get('avatar', None)
        if not image_file:
            error_msg = 'avatar invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        (root, ext) = os.path.splitext(image_file.name.lower())
        if AVATAR_ALLOWED_FILE_EXTS and ext not in AVATAR_ALLOWED_FILE_EXTS:
            error_msg = _(u"%(ext)s is an invalid file extension. Authorized extensions are : %(valid_exts_list)s") % {
                'ext': ext, 'valid_exts_list': ", ".join(AVATAR_ALLOWED_FILE_EXTS)}
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if image_file.size > AVATAR_MAX_SIZE:
            error_msg = _(u"Your file is too big (%(size)s), the maximum allowed size is %(max_valid_size)s") % {
                'size': filesizeformat(image_file.size), 'max_valid_size': filesizeformat(AVATAR_MAX_SIZE)}
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        username = request.user.username
        count = Avatar.objects.filter(emailuser=username).count()
        if AVATAR_MAX_AVATARS_PER_USER > 1 and count >= AVATAR_MAX_AVATARS_PER_USER:
            error_msg = _(u"You already have %(nb_avatars)d avatars, and the maximum allowed is %(nb_max_avatars)d.") % {
                'nb_avatars': count, 'nb_max_avatars': AVATAR_MAX_AVATARS_PER_USER}
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            avatar = Avatar(
                emailuser=username,
                primary=True,
            )
            avatar.avatar.save(image_file.name, image_file)
            avatar.save()
            avatar_updated.send(
                sender=Avatar, user=request.user, avatar=avatar)
        except Exception as e:
            logger.error(e)
            error_msg = _('Internal Server Error')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return api_response(msg=_('Updated avatar successfully.'))

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Remove avatar',
        operation_description='Remove user avatar',
        tags=['user'],
        responses={
            200: openapi.Response(
                description='Remove avatar successfully. Will also return this status even if current user avatar is already removed or not exists',
                examples={
                    'application/json': {
                        "message": "Delete avatar successfully.",
                        "data": None
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / unauthorized.',
                examples={
                    'application/json': {
                        "detail": "Invalid token"
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error',
                examples={
                    'application/json': {
                        "message": "Internal server error"
                    }
                }
            )
        }
    )
    def delete(self, request):
        username = request.user.username
        try:
            avatars = Avatar.objects.filter(emailuser=username)
            if len(avatars) == 0:
                return api_response(msg=_('Avatar does not exist or already deleted.'))
            avatar = avatars[0]
            storage, path = avatar.avatar.storage, avatar.avatar.path
            avatar.delete()
            storage.delete(path)
            # avatar_updated.send(sender=Avatar, user=request.user, avatar=avatar)
        except Exception as e:
            logger.error(e)
            error_msg = _('Internal Server Error')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return api_response(msg=_('Deleted avatar successfully.'))
