import datetime

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.utils import api_error, api_response
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle

from restapi.avatar.templatetags.avatar_tags import api_avatar_url, avatar
from restapi.base.templatetags.restapi_tags import translate_commit_desc_escape, translate_restapi_time, email2nickname
from restapi.utils import EVENTS_ENABLED, is_org_context, get_org_user_events, get_user_events, convert_cmmt_desc_link
from restapi.utils.timeutils import utc_to_local

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class EventsView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get files activities',
        operation_description='''This api will only return first 15 records of activities. if want get more, pass start parameter''',
        tags=['files'],
        manual_parameters=[
            openapi.Parameter(
                name='start',
                in_="query",
                type='string',
                description='result offset',
            ),
            openapi.Parameter(
                name='size',
                in_="query",
                type='string',
                description='size of user avatar. 36 is default',
            ),
        ],
        responses={
            200: openapi.Response(
                description='File activity list retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": []
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
            404: openapi.Response(
                description='Folder not found',
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
    def get(self, request, format=None):
        if not EVENTS_ENABLED:
            events = None
            return api_error(status.HTTP_404_NOT_FOUND, 'Events not enabled.')

        start = request.GET.get('start', '')

        if not start:
            start = 0
        else:
            try:
                start = int(start)
            except ValueError:
                return api_error(status.HTTP_400_BAD_REQUEST, 'Start id must be integer')

        email = request.user.username
        events_count = 15

        if is_org_context(request):
            org_id = request.user.org.org_id
            events, events_more_offset = get_org_user_events(org_id, email,
                                                             start,
                                                             events_count)
        else:
            events, events_more_offset = get_user_events(email, start,
                                                         events_count)
        events_more = True if len(events) == events_count else False

        l = []
        for e in events:
            d = dict(etype=e.etype)
            l.append(d)
            if e.etype == 'repo-update':
                d['author'] = e.commit.creator_name
                d['time'] = e.commit.ctime
                d['desc'] = e.commit.desc
                d['repo_id'] = e.repo.id
                d['repo_name'] = e.repo.name
                d['commit_id'] = e.commit.id
                d['converted_cmmt_desc'] = translate_commit_desc_escape(convert_cmmt_desc_link(e.commit))
                d['more_files'] = e.commit.more_files
                d['repo_encrypted'] = e.repo.encrypted
            else:
                d['repo_id'] = e.repo_id
                d['repo_name'] = e.repo_name
                if e.etype == 'repo-create':
                    d['author'] = e.creator
                else:
                    d['author'] = e.repo_owner

                epoch = datetime.datetime(1970, 1, 1)
                local = utc_to_local(e.timestamp)
                time_diff = local - epoch
                d['time'] = time_diff.seconds + (time_diff.days * 24 * 3600)

            size = request.GET.get('size', 36)
            url, is_default, date_uploaded = api_avatar_url(d['author'], size)
            d['nick'] = email2nickname(d['author'])
            d['name'] = email2nickname(d['author'])
            d['avatar'] = avatar(d['author'], size)
            d['avatar_url'] = request.build_absolute_uri(url)
            d['time_relative'] = translate_restapi_time(utc_to_local(e.timestamp))
            d['date'] = utc_to_local(e.timestamp).strftime("%Y-%m-%d")

        ret = {
            'events': l,
            'more': events_more,
            'more_offset': events_more_offset,
            }
        return api_response(data=ret)
