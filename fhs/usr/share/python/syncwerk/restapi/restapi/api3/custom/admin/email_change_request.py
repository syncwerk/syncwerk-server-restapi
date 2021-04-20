import logging

from django.utils.translation import ugettext as _
from django.utils import timezone
from django.db import transaction, connections
from django.db.models import Q

from constance import config

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.permissions import IsAdminUser

from restapi.api3.base import APIView
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response, get_request_domain, send_html_email
from restapi.api3.models import EmailChangingRequest

logger = logging.getLogger(__name__)

def change_user_email(old_email, new_email, request_id):
    ccnet_cursor = connections['ccnet'].cursor()
    syncwerk_server_cursor = connections['syncwerk-server'].cursor()
    rest_api_cursor = connections['default'].cursor()
    try:
        with transaction.atomic():
            logger.info('Replacing email in ccnet')
            ccnet_cursor.execute("UPDATE  `Binding` set `email` = %s where `email` LIKE %s;", [new_email, old_email] )
            ccnet_cursor.execute("UPDATE  `EmailUser` set `email` = %s where `email` LIKE %s;", [new_email, old_email] )
            ccnet_cursor.execute("UPDATE  `Group` set `creator_name` = %s where `creator_name` LIKE %s;", [new_email, old_email] )
            ccnet_cursor.execute("UPDATE  `GroupUser` set `user_name` = %s where `user_name` LIKE %s;", [new_email, old_email] )
            ccnet_cursor.execute("UPDATE  `Organization` set `creator` = %s where `creator` LIKE %s;", [new_email, old_email] )
            ccnet_cursor.execute("UPDATE  `OrgUser` set `email` = %s where `email` LIKE %s;", [new_email, old_email] )
            ccnet_cursor.execute("UPDATE  `UserRole` set `email` = %s where `email` LIKE %s;", [new_email, old_email] )
            logger.info('Replacing email in syncwerk-server')
            syncwerk_server_cursor.execute("UPDATE  `FileLocks` set `user_name` = %s where `user_name` LIKE %s", [new_email, old_email] )
            syncwerk_server_cursor.execute("UPDATE  `OrgUserQuota` set `user` = %s where `user` LIKE %s", [new_email, old_email] )
            syncwerk_server_cursor.execute("UPDATE  `RepoGroup` set `user_name` = %s where `user_name` LIKE %s", [new_email, old_email] )
            syncwerk_server_cursor.execute("UPDATE  `RepoInfo` set `last_modifier` = %s where `last_modifier` LIKE %s", [new_email, old_email] )
            syncwerk_server_cursor.execute("UPDATE  `RepoOwner` set `owner_id` = %s where `owner_id` LIKE %s", [new_email, old_email] )
            syncwerk_server_cursor.execute("UPDATE  `RepoTrash` set `owner_id` = %s where `owner_id` LIKE %s", [new_email, old_email] )
            syncwerk_server_cursor.execute("UPDATE  `RepoUserToken` set `email` = %s where `email` LIKE %s", [new_email, old_email] )
            syncwerk_server_cursor.execute("UPDATE  `SharedRepo` set `from_email` = %s where `from_email` LIKE %s", [new_email, old_email] )
            syncwerk_server_cursor.execute("UPDATE  `SharedRepo` set `to_email` = %s where `to_email` LIKE %s", [new_email, old_email] )
            syncwerk_server_cursor.execute("UPDATE  `UserQuota` set `user` = %s where `user` LIKE %s", [new_email, old_email] )
            syncwerk_server_cursor.execute("UPDATE  `UserShareQuota` set `user` = %s where `user` LIKE %s", [new_email, old_email] )
            logger.info('Replacing email in syncwerk-restapi')
            rest_api_cursor.execute("UPDATE  `admin_log_adminlog` set `email` = %s where `email` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `api2_token` set `user` = %s where `user` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `api2_tokenv2` set `user` = %s where `user` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `api3_token` set `user` = %s where `user` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `api3_tokenv2` set `user` = %s where `user` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `auth_user` set `username` = %s where `username` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `auth_user_groups` set `user_id` = %s where `user_id` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `auth_user_user_permissions` set `user_id` = %s where `user_id` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `avatar_avatar` set `emailuser` = %s where `emailuser` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `base_clientlogintoken` set `username` = %s where `username` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `base_devicetoken` set `user` = %s where `user` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `base_filecomment` set `author` = %s where `author` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `base_innerpubmsg` set `from_email` = %s where `from_email` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `base_innerpubmsgreply` set `from_email` = %s where `from_email` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `base_userenabledmodule` set `username` = %s where `username` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `base_userlastlogin` set `username` = %s where `username` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `base_userstarredfiles` set `email` = %s where `email` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `contacts_contact` set `user_email` = %s where `user_email` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `group_groupmessage` set `from_email` = %s where `from_email` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `group_messagereply` set `from_email` = %s where `from_email` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `invitations_invitation` set `inviter` = %s where `inviter` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `invitations_invitation` set `accepter` = %s where `accepter` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `MonthlyUserTraffic` set `user` = %s where `user` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `notifications_usernotification` set `to_user` = %s where `to_user` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `options_useroptions` set `email` = %s where `email` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `profile_detailedprofile` set `user` = %s where `user` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `profile_profile` set `user` = %s where `user` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `revision_tag_revisiontags` set `username` = %s where `username` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `role_permissions_adminrole` set `email` = %s where `email` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `share_anonymousshare` set `repo_owner` = %s where `repo_owner` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `share_extrasharepermission` set `share_to` = %s where `share_to` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `share_fileshare` set `username` = %s where `username` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `share_privatefiledirshare` set `from_user` = %s where `from_user` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `share_privatefiledirshare` set `to_user` = %s where `to_user` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `share_uploadlinkshare` set `username` = %s where `username` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `sysadmin_extra_userloginlog` set `username` = %s where `username` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `tags_filetag` set `username` = %s where `username` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `tenants_tenantadmin` set `user` = %s where `user` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `termsandconditions_usertermsandconditions` set `username` = %s where `username` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `two_factor_phonedevice` set `user` = %s where `user` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `two_factor_staticdevice` set `user` = %s where `user` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `two_factor_totpdevice` set `user` = %s where `user` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `wiki_personalwiki` set `username` = %s where `username` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `wiki_wiki` set `username` = %s where `username` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `MeetingRooms` set `owner_id` = %s where `owner_id` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `BBBPrivateSettings` set `user_id` = %s where `user_id` LIKE %s", [new_email, old_email] )
            rest_api_cursor.execute("UPDATE  `MeetingRoomShares` set `share_to_user` = %s where `share_to_user` LIKE %s", [new_email, old_email] )

            rest_api_cursor.execute("UPDATE  `EmailChangingRequest` set request_token = null, request_token_expire_time = null, request_completed = true where `id` = %s", [request_id])
        return True
    except Exception as e:
        logger.error(e)
        logger.info('There is error while changing email. Rolling back transaction')
        return False
    finally:
        ccnet_cursor.close()
        syncwerk_server_cursor.close()
        rest_api_cursor.close()


class AdminUserEmailChangeRequests(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)

    def get(self, request):
        search_query = request.GET.get('s', '')
        limit = int(request.GET.get('per_page', 10))
        page = int(request.GET.get('page', 1))
        order_by = request.GET.get('order_by', None)
        order_direction = request.GET.get('order_type', 'desc')
        
        start = (page - 1) * limit
        end = start + limit

        # Get the list of email change request
        request_list = EmailChangingRequest.objects.filter(
            Q(user_id__icontains=search_query) | Q(new_email__icontains=search_query)
        )
        if order_by is None:
            if order_direction == 'desc':
                request_list = request_list.order_by('-created_at')
            else:
                request_list = request_list.order_by('created_at')
        else:
            if order_direction == 'desc':
                request_list = request_list.order_by('-{}'.format(order_by))
            else:
                request_list = request_list.order_by(order_by)
        total_result = request_list.count()
        request_list = request_list[start:end]

        response = {
            'total_result': total_result,
            'request_list': []
        }

        for email_change_request in request_list:
            request_entry = {
                'id': email_change_request.id,
                'user_id': email_change_request.user_id,
                'new_email': email_change_request.new_email,
                'new_email_confirmed': email_change_request.new_email_confirmed,
                'request_completed': email_change_request.request_completed,
                'created_date': email_change_request.created_at,
            }
            response['request_list'].append(request_entry)
        
        return api_response(code=200, data=response)
        
class AdminUserEmailChangeRequest(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)

    def post(self, request, request_id):
        if request_id is None:
            return api_error(code=400, msg=_('Please include "request_id" in your request.'))
        try:
            inprogress_request = EmailChangingRequest.objects.get(
                request_completed=False,
                new_email_confirmed=True,
                id=request_id
            )
            if inprogress_request is None:
                return api_error(code=400, msg=_('Invalid request.'))
        except Exception as e:
            return api_error(code=400, msg=_('Invalid request.'))
        # The request is correct. Begin changing email
        change_email_result = change_user_email(inprogress_request.user_id, inprogress_request.new_email, inprogress_request.id)
        if change_email_result == False:
            return api_error(code=500, msg=_("There is error while changing email. Please try again later."))
        # Send email to user to notify successfully email change
        email_content = {
            'new_email': inprogress_request.new_email,
            'old_email': inprogress_request.user_id
        }
        send_html_email('Email changed successfully',
            'api3/change_email_request_success.html', email_content, None, [inprogress_request.new_email],request=request)
        return api_response(code=200, msg=_("Change email complete successfully"))

    def delete(self, request, request_id):
        if request_id is None:
            return api_error(code=400, msg=_('Please include "request_id" in your request.'))
        ## Remove request
        try:
            EmailChangingRequest.objects.filter(id=request_id).delete()
            return api_response(code=200, msg=_("Request removed successfully."))
        except Exception as e:
            logger.error(e)
            return api_error(code=500, msg=_("Internal server error. Please try again later."))