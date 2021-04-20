import logging
import synserv

from django.utils.translation import ugettext as _

from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser

from synserv import ccnet_threaded_rpc, syncwserv_threaded_rpc, \
    syncwerk_api, get_group, get_group_members, ccnet_api, \
    get_related_users_by_repo, get_related_users_by_org_repo

from restapi.base.accounts import User
from restapi.share.models import FileShare, UploadLinkShare

from restapi.api3.utils import api_error, api_response
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle

try:
    from restapi.settings import ENABLE_TRIAL_ACCOUNT
except:
    ENABLE_TRIAL_ACCOUNT = False
if ENABLE_TRIAL_ACCOUNT:
    from restapi_extra.trialaccount.models import TrialAccount
try:
    from restapi.settings import MULTI_TENANCY
except ImportError:
    MULTI_TENANCY = False

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema


def remove_group_common(group_id, username, org_id=None):
    """Common function to remove a group, and it's repos,
    If ``org_id`` is provided, also remove org group.

    Arguments:
    - `group_id`:
    """
    synserv.ccnet_threaded_rpc.remove_group(group_id, username)
    synserv.syncwserv_threaded_rpc.remove_repo_group(group_id)
    if org_id is not None and org_id > 0:
        synserv.ccnet_threaded_rpc.remove_org_group(org_id, group_id)

class AdminUserOwnedLibs(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Users - Transfer a folder to others.',
        operation_description='''Users - Transfer a folder to others.''',
        tags=['admin-users'],
        manual_parameters=[
            openapi.Parameter(
                name='email',
                in_="formData",
                type='string',
                description='email of the new owner',
                required=True,
            ),
            openapi.Parameter(
                name='repo_id',
                in_="formData",
                type='string',
                description='id of the folder to be transfered',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Folder transfered successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
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
                        "detail": "Token invalid",
                    }
                }
            ),
            403: openapi.Response(
                description='Operation not permitted',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            404: openapi.Response(
                description='Folder / user not found',
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
        
        repo_id = request.POST.get('repo_id', None)
        new_owner = request.POST.get('email', None)

        if not (repo_id and new_owner):
            return api_error(code=400, msg=_(u'Failed to transfer, invalid arguments.'))

        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            return api_error(code=404, msg=_(u'Library does not exist.'))
        try:
            User.objects.get(email=new_owner)
        except User.DoesNotExist:
            return api_error(code=404, msg=_(u'Failed to transfer, user %s not found') % new_owner)

        if MULTI_TENANCY:
            try:
                if syncwserv_threaded_rpc.get_org_id_by_repo_id(repo_id) > 0:
                    return api_error(code=400, msg=_(u'Can not transfer organization library'))

                if ccnet_api.get_orgs_by_user(new_owner):
                    return api_error(code=400, msg=_(u'Can not transfer library to organization user %s') % new_owner)
            except Exception as e:
                logger.error(e)
                return api_error(code=500, msg=_(u'Internal Server Error'))

        repo_owner = syncwerk_api.get_repo_owner(repo_id)

        # get repo shared to user/group list
        shared_users = syncwerk_api.list_repo_shared_to(
                repo_owner, repo_id)
        shared_groups = syncwerk_api.list_repo_shared_group_by_user(
                repo_owner, repo_id)

        # get all pub repos
        pub_repos = []
        if not request.cloud_mode:
            pub_repos = syncwerk_api.list_inner_pub_repos_by_owner(repo_owner)

        # transfer repo
        syncwerk_api.set_repo_owner(repo_id, new_owner)

        # reshare repo to user
        for shared_user in shared_users:
            shared_username = shared_user.user

            if new_owner == shared_username:
                continue

            syncwerk_api.share_repo(repo_id, new_owner,
                    shared_username, shared_user.perm)

        # reshare repo to group
        for shared_group in shared_groups:
            shared_group_id = shared_group.group_id

            if not ccnet_api.is_group_user(shared_group_id, new_owner):
                continue

            syncwerk_api.set_group_repo(repo_id, shared_group_id,
                    new_owner, shared_group.perm)

        # check if current repo is pub-repo
        # if YES, reshare current repo to public
        for pub_repo in pub_repos:
            if repo_id != pub_repo.id:
                continue

            syncwerk_api.add_inner_pub_repo(repo_id, pub_repo.permission)

            break
        return api_response(msg=_(u'Successfully transferred.'))

class AdminUserSharedLinkRemovePublicLink(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )
    
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Users - Remove public share link.',
        operation_description='''Users - Remove public share link.''',
        tags=['admin-users'],
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_="path",
                type='string',
                description='link token',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Link removed successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
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
                        "detail": "Token invalid",
                    }
                }
            ),
            403: openapi.Response(
                description='Operation not permitted',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
        }
    )
    def delete(self, request, token):
        
        if not token:
            return api_error(code=400, msg=_(u"Argument missing"))

        FileShare.objects.filter(token=token).delete()
        return api_response(msg=_(u'Download link was removed successfully.'))

class AdminUserSharedLinkRemoveUploadLink(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Users - Remove upload link.',
        operation_description='''Users - Remove upload link.''',
        tags=['admin-users'],
        manual_parameters=[
            openapi.Parameter(
                name='token',
                in_="path",
                type='string',
                description='link token',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Link removed successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
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
                        "detail": "Token invalid",
                    }
                }
            ),
            403: openapi.Response(
                description='Operation not permitted',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
        }
    )
    def delete(self, request, token):
        if not token:
            return api_error(code=400, msg=_(u"Argument missing"))

        UploadLinkShare.objects.filter(token=token).delete()
        return api_response(msg=_(u'Upload link was removed successfully.'))

class AdminUserGroups(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )
    
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Users - Remove group.',
        operation_description='''Users - Remove group''',
        tags=['admin-users'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='group id to be removed',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Link removed successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
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
                        "detail": "Token invalid",
                    }
                }
            ),
            403: openapi.Response(
                description='Operation not permitted',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
        }
    )
    def delete(self, request, group_id):
        try:
            group_id_int = int(group_id)
        except ValueError:
            return api_error(code=400, msg=_(u'Group id is not valid.'))

        remove_group_common(group_id_int, request.user.username)

        return api_response(msg=_(u'Group was removed successfully.'))
