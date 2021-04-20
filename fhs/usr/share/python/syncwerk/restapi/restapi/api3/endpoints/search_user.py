import json

from constance import config

from django.db.models import Q
from django.http import HttpResponse

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status

import synserv

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response
from restapi.utils import is_valid_email, is_org_context
from restapi.base.accounts import User
from restapi.base.templatetags.restapi_tags import email2nickname
from restapi.profile.models import Profile
from restapi.contacts.models import Contact
from restapi.avatar.templatetags.avatar_tags import api_avatar_url

from drf_yasg.utils import swagger_auto_schema, no_body
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

from restapi.settings import ENABLE_GLOBAL_ADDRESSBOOK, \
    ENABLE_SEARCH_FROM_LDAP_DIRECTLY

try:
    from restapi.settings import CLOUD_MODE
except ImportError:
    CLOUD_MODE = False

class SearchUser(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )

    def _can_use_global_address_book(self, request):

        return request.user.permissions.can_use_global_address_book()

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Search user',
        operation_description='Search all users',
        tags=['user'],
        manual_parameters=[
            openapi.Parameter(
                name='q',
                in_="query",
                type='string',
                description='Query string',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Successfully retrieve search result.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "users": [
                                {
                                    "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                    "contact_email": "test10@grr.la",
                                    "email": "test10@grr.la",
                                    "name": "test10@grr.la"
                                },
                                {
                                    "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                    "contact_email": "test1@grr.la",
                                    "email": "test1@grr.la",
                                    "name": "test1@grr.la"
                                },
                                {
                                    "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                    "contact_email": "test11@grr.la",
                                    "email": "test11@grr.la",
                                    "name": "test11"
                                }
                            ]
                        }
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthorized / Unauthenticated',
                examples={
                    'application/json': {
                        "details": "Invalid token"
                    }
                }
            ),
        }
    )
    def get(self, request, format=None):
        q = request.GET.get('q', None)
        if not q:
            return api_error(status.HTTP_400_BAD_REQUEST, 'q invalid.')

        email_list = []
        username = request.user.username

        if self._can_use_global_address_book(request):
            # check user permission according to user's role(default, guest, etc.)
            # if current user can use global address book
            if CLOUD_MODE:
                if is_org_context(request):
                    # search from org
                    email_list += search_user_from_org(request, q)

                    # search from profile, limit search range in all org users
                    limited_emails = []
                    url_prefix = request.user.org.url_prefix
                    all_org_users = synserv.get_org_users_by_url_prefix(url_prefix, -1, -1)
                    for user in all_org_users:
                        limited_emails.append(user.email)

                    email_list += search_user_from_profile_with_limits(q, limited_emails)

                elif config.ENABLE_GLOBAL_ADDRESSBOOK:
                    # search from ccnet
                    email_list += search_user_from_ccnet(q)

                    # search from profile, NOT limit search range
                    email_list += search_user_from_profile(q)
                else:
                    # in cloud mode, user will be added to Contact when share repo
                    # search user from user's contacts
                    email_list += search_user_when_global_address_book_disabled(request, q)
            else:
                # not CLOUD_MODE
                # search from ccnet
                email_list += search_user_from_ccnet(q)

                # search from profile, NOT limit search range
                email_list += search_user_from_profile(q)
        else:
            # if current user can NOT use global address book,
            # he/she can also search `q` from Contact,
            # search user from user's contacts
            email_list += search_user_when_global_address_book_disabled(request, q)

        ## search finished
        # remove duplicate emails
        email_list = {}.fromkeys(email_list).keys()

        email_result = []
        # remove nonexistent or inactive user
        for email in email_list:
            try:
                user = User.objects.get(email=email)
                if user.is_active:
                    email_result.append(email)
            except User.DoesNotExist:
                continue

        # check if include myself in user result
        try:
            include_self = int(request.GET.get('include_self', 1))
        except ValueError:
            include_self = 1

        if include_self == 0 and username in email_result:
            # reomve myself
            email_result.remove(username)

        # format user result
        try:
            size = int(request.GET.get('avatar_size', 32))
        except ValueError:
            size = 32

        formated_result = format_searched_user_result(
                request, email_result[:10], size)

        # return HttpResponse(json.dumps({"users": formated_result}),
        #         status=200, content_type='application/json; charset=utf-8')
        resp = { "users": formated_result }
        return api_response(data=resp)

def format_searched_user_result(request, users, size):
    results = []

    for email in users:
        url, is_default, date_uploaded = api_avatar_url(email, size)
        results.append({
            "email": email,
            # "avatar_url": request.build_absolute_uri(url),
            'avatar_url': '%s%s' % (config.SERVICE_URL, url),
            "name": email2nickname(email),
            "contact_email": Profile.objects.get_contact_email_by_user(email),
        })

    return results

def search_user_from_org(request, q):

    # get all org users
    url_prefix = request.user.org.url_prefix
    all_org_users = synserv.get_org_users_by_url_prefix(url_prefix, -1, -1)

    # search user from org users
    email_list = []
    for org_user in all_org_users:
        if q in org_user.email:
            email_list.append(org_user.email)

    return email_list

def search_user_from_ccnet(q):
    users = []

    db_users = synserv.ccnet_threaded_rpc.search_emailusers('DB', q, 0, 10)
    users.extend(db_users)

    count = len(users)
    if count < 10:
        ldap_imported_users = synserv.ccnet_threaded_rpc.search_emailusers('LDAP', q, 0, 10 - count)
        users.extend(ldap_imported_users)

    count = len(users)
    if count < 10 and ENABLE_SEARCH_FROM_LDAP_DIRECTLY:
        all_ldap_users = synserv.ccnet_threaded_rpc.search_ldapusers(q, 0, 10 - count)
        users.extend(all_ldap_users)

    # `users` is already search result, no need search more
    email_list = []
    for user in users:
        email_list.append(user.email)

    return email_list

def search_user_from_profile(q):
    # 'nickname__icontains' for search by nickname
    # 'contact_email__icontains' for search by contact email
    users = Profile.objects.filter(Q(nickname__icontains=q) | \
            Q(contact_email__icontains=q)).values('user')

    email_list = []
    for user in users:
        email_list.append(user['user'])

    return email_list

def search_user_from_profile_with_limits(q, limited_emails):
    # search within limited_emails
    users = Profile.objects.filter(Q(user__in=limited_emails) &
            (Q(nickname__icontains=q) | Q(contact_email__icontains=q))).values('user')

    email_list = []
    for user in users:
        email_list.append(user['user'])

    return email_list

def search_user_when_global_address_book_disabled(request, q):

    email_list = []
    username = request.user.username

    # search from contact
    # get user's contact list
    contacts = Contact.objects.get_contacts_by_user(username)
    for contact in contacts:
        # search user from contact list
        if q in contact.contact_email:
            email_list.append(contact.contact_email)

    # search from profile, limit search range in user's contacts
    limited_emails = []
    for contact in contacts:
        limited_emails.append(contact.contact_email)

    email_list += search_user_from_profile_with_limits(q, limited_emails)

    if is_valid_email(q):
        # if `q` is a valid email
        email_list.append(q)

        # get user whose `contact_email` is `q`
        users = Profile.objects.filter(contact_email=q).values('user')
        for user in users:
            email_list.append(user['user'])

    return email_list
