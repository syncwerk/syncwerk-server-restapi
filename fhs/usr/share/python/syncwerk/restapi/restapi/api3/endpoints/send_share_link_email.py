import os
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.utils.translation import ugettext as _

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response, gen_shared_link_webapp
from restapi.utils import IS_EMAIL_CONFIGURED, is_valid_username, \
    is_valid_email, string2list, send_html_email
from restapi.share.models import FileShare
from restapi.settings import REPLACE_FROM_EMAIL, ADD_REPLY_TO_HEADER, SITE_NAME
from restapi.profile.models import Profile
from restapi.api3.models import KanbanShareLink

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)

class SendShareLinkView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication )
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.JSONParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Send share link',
        operation_description='''Send share link to emails''',
        tags=['shares'],
        request_body=openapi.Schema(
            type="object",
            properties={
                "token": openapi.Schema(
                    type='string',
                    description='share link token. Required',
                ),
                "email": openapi.Schema(
                    type='string',
                    description='email to send the link to. Required',
                ),
                "extra_msg": openapi.Schema(
                    type='string',
                    description='additional message for email',
                ),
                "expire_days": openapi.Schema(
                    type='number',
                    description='days before the link is expired. 0 means the link will not expire (default)',
                ),
            }
        ),
        responses={
            200: openapi.Response(
                description='Send link completed.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "failed": [],
                            "success": [
                                "test2@grr.las"
                            ]
                        }
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
                        "detail": "Token invalid"
                    }
                }
            ),
            403: openapi.Response(
                description='You don\'t have permission to perform this operation.',
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
        if not IS_EMAIL_CONFIGURED:
            error_msg = _(u'Sending shared link failed. Email service is not properly configured, please contact administrator.')
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # check args
        email = request.data.get('email', None)
        if not email:
            error_msg = 'email invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        token = request.data.get('token', None)
        if not token:
            error_msg = 'token invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        extra_msg = request.data.get('extra_msg', '')

        # check if token exists
        try:
            link = FileShare.objects.get(token=token)
            name = os.path.basename(link.path.rstrip('/'))
        except FileShare.DoesNotExist:
            try:
                link = KanbanShareLink.objects.get(token=token)
                name = link.project.project_name
            except KanbanShareLink.DoesNotExist:
                error_msg = 'token %s not found.' % token
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # check if is share link owner
        username = request.user.username
        if not link.is_owner(username):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        result = {}
        result['failed'] = []
        result['success'] = []
        to_email_list = string2list(email)
        # use contact_email, if present
        useremail = Profile.objects.get_contact_email_by_user(request.user.username)
        for to_email in to_email_list:

            failed_info = {}

            if not is_valid_email(to_email):
                failed_info['email'] = to_email
                failed_info['error_msg'] = 'email invalid.'
                result['failed'].append(failed_info)
                continue

            # prepare basic info
            c = {
                'email': username,
                'to_email': to_email,
                'extra_msg': extra_msg,
                'expire_days': request.data.get('expire_days', 0)
            }

            if REPLACE_FROM_EMAIL:
                from_email = useremail
            else:
                from_email = None  # use default from email

            if ADD_REPLY_TO_HEADER:
                reply_to = useremail
            else:
                reply_to = None

            c['file_shared_link'] = gen_shared_link_webapp(request, token, link.s_type, '/share-link')
            c['file_shared_name'] = name
            template = 'shared_link_email.html'

            if link.s_type == 'f':
                c['file_shared_type'] = _(u"file")
                title = _(u'A file is shared to you on %s') % SITE_NAME
            elif link.s_type == 'k':
                c['file_shared_type'] = _(u"project")
                title = _(u'A project is shared to you on %s') % SITE_NAME
            else:
                c['file_shared_type'] = _(u"directory")
                title = _(u'A directory is shared to you on %s') % SITE_NAME

            # send email
            try:
                send_html_email(title, template, c, from_email, [to_email], reply_to=reply_to,request=request)
                result['success'].append(to_email)
            except Exception as e:
                logger.error(e)
                failed_info['email'] = to_email
                failed_info['error_msg'] = 'Internal Server Error'
                result['failed'].append(failed_info)

        # return Response(result)
        return api_response(data=result)
