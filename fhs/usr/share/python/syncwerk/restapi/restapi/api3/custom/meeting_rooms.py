import datetime
import logging
import uuid
import random
import string
import os
import requests

import sys

import synserv

from django.utils.translation import ugettext as _
from django.shortcuts import redirect
from django.db.models import Q

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.permissions import IsAdminUser
from rest_framework.views import APIView
from rest_framework import status

from restapi.base.templatetags.restapi_tags import email2nickname
from restapi.base.accounts import User
from restapi.tenants.models import (Tenant, TenantAdmin,
                                        TenantQuota)
from restapi.utils import gen_file_get_url

from restapi.api3.utils import api_error, api_response

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication

from restapi.api3.models import MeetingRoom, MeetingRoomShare, BBBPrivateSetting, ProfileSetting, MeetingRoomFile

from restapi.api3.utils.BBBmeeting import BBBMeeting

from restapi.api3.endpoints.groups import get_group_admins
from restapi.api3.endpoints.admin.groups import get_group_info

from urlparse import urlparse

from constance import config

## TODO: B3 Meetings model
# from restapi.helpers import B3MettingHelpers

## For testing BBB
import requests
import hashlib
import urllib



logger = logging.getLogger(__name__)

reload(sys)
sys.setdefaultencoding('utf-8')

def getBBBInstance(config_id=-1):
    BBBMeetingInstace = BBBMeeting.getInstance()
    if config_id == -1:
        BBBMeetingInstace.setServerURL(config.BBB_SERVER_URL)
        BBBMeetingInstace.setSecret(config.BBB_SECRET_KEY)
        return BBBMeetingInstace
    try:
        private_setting = BBBPrivateSetting.objects.get(id=config_id, is_active=True)
    except BBBPrivateSetting.DoesNotExist:
        return None
    
    BBBMeetingInstace.setServerURL(private_setting.bbb_server)
    BBBMeetingInstace.setSecret(private_setting.bbb_secret)
    BBBMeetingInstace.setLiveStreamToken(private_setting.live_stream_token)
    BBBMeetingInstace.setLiveStreamServer(private_setting.live_stream_server)

    return BBBMeetingInstace

def getCorrespondingRoleForGroupMeeting(user, group_id):
    group_admins = get_group_admins(group_id)
    if user.email in group_admins:
        return 'MODERATOR'
    return 'ATTENDEE'

def getMeetingRoomRoleForSharedRoom(user, shared_entry):
    meeting_role = None
    if shared_entry.share_type == 'SHARED_TO_USER':
        meeting_role = shared_entry.user_role
    elif shared_entry.share_type == 'SHARED_TO_GROUP':
        meeting_role = getCorrespondingRoleForGroupMeeting(user, shared_entry.group_id)
    return meeting_role

def getMeetingRoomRole(user, meeting_room_id):
    # Check if the user is the owner
    try:
        own_meeting_rooms = MeetingRoom.objects.get(
            id=meeting_room_id,
            owner_id=user.email
        )
        return 'MODERATOR'
    except MeetingRoom.DoesNotExist:
        pass
    # User is not the owner of the meeting. But is the user is one of the meeting moderator????
    # Check the case of the meeting was privately shared to the user
    # try:
    user_groups = synserv.get_personal_groups_by_user(user.email)
    user_groups_id = []
    # Get all the groups that user belongs to
    for group in user_groups:
        user_groups_id.append(group.id)

    shared_meeting_rooms = MeetingRoomShare.objects.filter(
        Q(share_to_user=user.email, meeting_room_id = meeting_room_id, share_type="SHARED_TO_USER") |
        Q(meeting_room_id = meeting_room_id, group_id__in=user_groups_id, share_type="SHARED_TO_GROUP")
    )

    if len(shared_meeting_rooms) <= 0:
        return None

    shared_roles = [];
    for shared_entry in shared_meeting_rooms:
        shared_roles.append(getMeetingRoomRoleForSharedRoom(user, shared_entry))
    if 'MODERATOR' in shared_roles:
        return 'MODERATOR'
    else:
        return 'ATTENDEE'

def getFileDownloadLinkForMeeting(useremail, file_path=None):
    if file_path is None or file_path == "":
        return None
    file_path_arr = file_path.split('/')
    repo_id = file_path_arr[0]
    file_path_arr.pop(0)
    path = "/" + "/".join(file_path_arr)
    obj_id = synserv.get_file_id_by_path(repo_id, path)
    if not obj_id:
        return None
    token = synserv.syncwerk_api.get_fileserver_access_token(repo_id,
                obj_id, 'view', useremail, use_onetime=False)
    if not token:
        return None
    u_filename = os.path.basename(path)
    dl_url = gen_file_get_url(token, u_filename)
    return dl_url

def getMeetingFilesDownloadLink(meeting_room_id, meeting_room_owner):
    meeting_files = MeetingRoomFile.objects.filter(meeting_room_id=meeting_room_id).order_by('id')
    result = []
    for meeting_file in meeting_files:
        dl_link = getFileDownloadLinkForMeeting(meeting_room_owner, meeting_file.presentation_file)
        if not dl_link:
            pass
        else:
            result.append(dl_link)
    return result


def search_group_id_by_exact_name(search_query, username):
    groups = synserv.get_personal_groups_by_user(username)
    result = -1
    for group in groups:
        group_name = group.group_name
        if not group_name:
            continue
        # if is_group_owner(group.id, request.user.email) is False:
        #     continue
        if search_query == group_name:
            result = group.id
            break
    return result


class MeetingRoomsView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def randomPassword(self, stringLength=12):
        letters = string.ascii_letters + string.digits
        return ''.join(random.choice(letters) for i in range(stringLength))

    def get(self, request):

        user_groups = synserv.get_personal_groups_by_user(request.user.username)
        user_groups_id = []
        # Get all the groups that user belongs to
        for group in user_groups:
            user_groups_id.append(group.id)

        # Begin to get meeting rooms
        meetings_rooms = []
        # Get user own meeting rooms
        owned_meeting_rooms = MeetingRoom.objects.filter(owner_id=request.user.email)
        owned_meeting_rooms_id = []
        for r in owned_meeting_rooms:
            owned_meeting_rooms_id.append(r.id)

            file_objects = MeetingRoomFile.objects.filter(meeting_room_id=r.id)
            files = list(map(lambda x: x.presentation_file, file_objects))

            meetings_rooms.append({
                "id": r.id,
                "room_name": r.room_name,
                "status": r.status,
                "owner_id": email2nickname(r.owner_id),
                "updated_at": r.updated_at,
                "created_at": r.created_at,
                "meeting_role": 'MODERATOR',
                "room_share_type": 'OWN',
                "all_users_join_as_mod": r.all_users_join_as_mod,
                "allow_any_user_start": r.allow_any_user_start,
                "private_setting_id": r.private_setting_id,
                "require_meeting_password": r.require_meeting_password,
                "files": files,
                "live_stream_active": r.live_stream_active,
                "live_stream_feedback_active": r.live_stream_feedback_active
            })
        # Get all the meeting rooms that shared to this user
        shared_meeting_entries = MeetingRoomShare.objects.filter(
            Q(share_to_user=request.user.email, share_type="SHARED_TO_USER") |
            Q(group_id__in=user_groups_id, share_type="SHARED_TO_GROUP")
        ).exclude(meeting_room_id__in=owned_meeting_rooms_id)
        # shared_meeting_entries = MeetingRoomShare.objects.filter(share_to_user=request.user.email, share_type="SHARED_TO_USER")
        shared_meeting_room_ids = []
        for shared_entry in shared_meeting_entries:
            try:
                shared_room = MeetingRoom.objects.get(id=shared_entry.meeting_room_id)

                file_objects = MeetingRoomFile.objects.filter(meeting_room_id=shared_entry.meeting_room_id)
                files = list(map(lambda x: x.presentation_file, file_objects))

                meetings_rooms.append({
                    "id": shared_room.id,
                    "room_name": shared_room.room_name,
                    "status": shared_room.status,
                    "owner_id": email2nickname(shared_room.owner_id),
                    "updated_at": shared_room.updated_at,
                    "created_at": shared_room.created_at,
                    "meeting_role": getMeetingRoomRoleForSharedRoom(request.user, shared_entry),
                    "room_share_type": shared_entry.share_type,
                    "all_users_join_as_mod": shared_room.all_users_join_as_mod,
                    "allow_any_user_start": shared_room.allow_any_user_start,
                    "private_setting_id": shared_room.private_setting_id,
                    "require_meeting_password": shared_room.require_meeting_password,
                    "live_stream_active": shared_room.live_stream_active,
                    "live_stream_feedback_active": shared_room.live_stream_feedback_active,
                    "files": files
                })
            except MeetingRoom.DoesNotExist:
                    pass
        # Get meeting rooms privare setting type
        for meeting_room in meetings_rooms:
            if meeting_room["private_setting_id"] == -1:
                meeting_room["private_setting_name"] = _("System setting")
                meeting_room["private_setting_url"] = urlparse(config.BBB_SERVER_URL).netloc if urlparse(config.BBB_SERVER_URL).netloc != '' else config.BBB_SERVER_URL
            else:
                try:
                    meeting_bbb_private_setting = BBBPrivateSetting.objects.get(id=meeting_room["private_setting_id"])
                    meeting_room["private_setting_name"] = meeting_bbb_private_setting.setting_name
                    meeting_room["private_setting_url"] = urlparse(meeting_bbb_private_setting.bbb_server).netloc if urlparse(meeting_bbb_private_setting.bbb_server).netloc != '' else meeting_bbb_private_setting.bbb_server
                    # urllib.parse.urlparse(meeting_bbb_private_setting.bbb_url)
                except BBBPrivateSetting.DoesNotExist:
                    meeting_room["private_setting_name"] = '(not found)'
                    meeting_room["private_setting_url"] = '(not found)'
        result = {
            "meeting_rooms": meetings_rooms
        }

        return api_response(code=200, data=result, msg=_('Get list of meetings successfully.'))

    def post(self, request):
        room_name = request.POST.get('name', None)
        attendee_password = request.POST.get('attendee_password', None)
        moderator_password = request.POST.get('moderator_password', None)
        private_bbb_settting_id = request.POST.get('private_setting_id', -1)

        if room_name is None :
            return api_error(code=400, msg=_('Please provide the name for the meeting.'))
        try:
            if int(request.POST.get('max_number_of_participants', 0)) < 0:
                return api_error(code=400, msg=_('Max number of participants must be larger than 0.'))
        except Exception:
            return api_error(code=400, msg=_('Max number of participants must be a number larger than 0.'))
        

        # Count current user created meetings
        number_of_meeting_room_created = MeetingRoom.objects.filter(owner_id=request.user.email).count()
        profile_setting = ProfileSetting.objects.get_profile_setting_by_user(request.user.email)
        max_meetings = profile_setting.max_meetings if profile_setting and profile_setting.max_meetings else config.BBB_MAX_MEETINGS_PER_USER
        if number_of_meeting_room_created >= max_meetings:
            return api_error(code=400, msg=_("You can\'t create more than {} meeting(s). Please remove some of your meeting(s) and try again.".format(max_meetings)))
        
        if attendee_password is None or attendee_password == '':
            attendee_password = self.randomPassword(12)
        elif len(attendee_password.strip()) < 6:
            return api_error(code=400, msg=_('The PIN for attendee should be at least 6 characters.'))

        if moderator_password is None or moderator_password == '':
            moderator_password = self.randomPassword(12)
        elif len(moderator_password.strip()) < 6:
            return api_error(code=400, msg=_('The PIN for moderator should be at least 6 characters.'))

        # request_url = request.build_absolute_uri('/')[:-1].strip("/")
        syncwerk_url = request.META['HTTP_HOST'].split(':')[0]

        new_meeting_room = MeetingRoom()
        # new_meeting.b3_meeting_id = b3_meeting_info['meetingID']
        new_meeting_room.room_name = room_name
        new_meeting_room.attendee_pw = attendee_password
        new_meeting_room.moderator_pw = moderator_password
        new_meeting_room.owner_id = request.user.email
        new_meeting_room.status = "STOPPED"
        new_meeting_room.b3_meeting_id = "{}-{}".format(syncwerk_url, uuid.uuid4())
        new_meeting_room.mute_participants_on_join = request.POST.get('mute_participants_on_join', 'false') == "true"
        new_meeting_room.require_mod_approval = request.POST.get('require_mod_approval', 'false') == "true"
        new_meeting_room.allow_any_user_start = request.POST.get('allow_any_user_start', 'false') == "true"
        new_meeting_room.all_users_join_as_mod = request.POST.get('all_users_join_as_mod', 'false') == "true"
        new_meeting_room.allow_recording = request.POST.get('allow_recording', 'false') == "true"
        new_meeting_room.require_meeting_password = request.POST.get('require_meeting_password', 'false') == "true"
        new_meeting_room.max_number_of_participants = request.POST.get('max_number_of_participants', 0)
        new_meeting_room.welcome_message = request.POST.get('welcome_message', '')
        new_meeting_room.private_setting_id = int(private_bbb_settting_id)
        new_meeting_room.presentation_file = request.POST.get('presentation_file', None)
        new_meeting_room.live_stream_active = request.POST.get('live_stream_active', 'false') == "true"
        new_meeting_room.live_stream_feedback_active = request.POST.get('live_stream_feedback_active', 'false') == "true"

        new_meeting_room.save()

        # if (new_meeting_room.private_setting_id != -1):
        #     private_setting = BBBPrivateSetting.objects.get(id=new_meeting_room.private_setting_id)
        #     if private_setting.group_id is not None:
        #         new_share = MeetingRoomShare()
        #         new_share.meeting_room_id = new_meeting_room.id
        #         new_share.group_id = private_setting.group_id
        #         new_share.share_type="SHARED_TO_GROUP"

        #         new_share.save()

        files = request.POST.getlist('files', None)
        if files is not None:
            for f in files:
                new_file = MeetingRoomFile()
                new_file.meeting_room_id = new_meeting_room.id
                new_file.presentation_file = f
                new_file.save()

        result = {
            "id": new_meeting_room.id,
            "meeting_name": new_meeting_room.room_name,
            "status": new_meeting_room.status,
            "owner_id": new_meeting_room.owner_id,
            "share_token": new_meeting_room.share_token,
        }

        # new_meeting_info = {
        #     "meeting_name": meeting_name,
        # }

        return api_response(code=200, data=result, msg=_('Meeting created successfully.'))

class MeetingRoomView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def get(self, request, meeting_room_id):
        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id.'))

        try:
            meeting_room = MeetingRoom.objects.get(
                id=meeting_room_id,
                owner_id=request.user.email
            )
            meeting_room_private_setting = {

            }

            file_objects = MeetingRoomFile.objects.filter(meeting_room_id=meeting_room_id)
            files = list(map(lambda x: x.presentation_file, file_objects))

            return_data = {
                'id': meeting_room.id,
                'room_name': meeting_room.room_name,
                'attendee_pw': meeting_room.attendee_pw, 
                'moderator_pw': meeting_room.moderator_pw,
                'owner_id': meeting_room.owner_id,
                'status': meeting_room.status,
                'mute_participants_on_join': meeting_room.mute_participants_on_join,
                'require_mod_approval': meeting_room.require_mod_approval,
                'allow_any_user_start': meeting_room.allow_any_user_start,
                'all_users_join_as_mod': meeting_room.all_users_join_as_mod,
                'allow_recording': meeting_room.allow_recording,
                'max_number_of_participants': meeting_room.max_number_of_participants,
                'welcome_message': meeting_room.welcome_message,
                'public_share_token': meeting_room.share_token,
                "meeting_role": 'MODERATOR',
                "room_share_type": 'OWN',
                "private_setting": meeting_room.private_setting_id,
                "require_meeting_password": meeting_room.require_meeting_password,
                "live_stream_active": meeting_room.live_stream_active,
                "live_stream_feedback_active": meeting_room.live_stream_feedback_active,
                "files": files
            }
            if meeting_room.private_setting_id == -1:
                meeting_room_private_setting = {
                    "id": -1,
                    "setting_name": _("System setting")
                }
            else:
                try:
                    meeting_room_private_setting_entry = BBBPrivateSetting.objects.get(id=meeting_room.private_setting_id)
                    meeting_room_private_setting = {
                        "id": meeting_room_private_setting_entry.id,
                        "setting_name": meeting_room_private_setting_entry.setting_name
                    }
                    
                except BBBPrivateSetting.DoesNotExist:
                    meeting_room_private_setting = None
            
            return_data["private_setting_info"] = meeting_room_private_setting
            return api_response(code=200, data=return_data)
        except MeetingRoom.DoesNotExist:
            pass
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))

        # User is not the owner of the meeting. But is the user is one of the meeting moderator????
        # Check the case of the meeting was privately shared to the user
        # try:

        shared_meeting_role = getMeetingRoomRole(request.user, meeting_room_id)

        if shared_meeting_role is None:
            return api_error(code=404, msg=_('Meeting not found.'))
        
        meeting_room = MeetingRoom.objects.get(
            id=meeting_room_id,
        )

        file_objects = MeetingRoomFile.objects.filter(meeting_room_id=meeting_room_id)
        files = list(map(lambda x: x.presentation_file, file_objects))

        return_data = {
            'id': meeting_room.id,
            'room_name': meeting_room.room_name,
            'attendee_pw': meeting_room.attendee_pw, 
            'moderator_pw': meeting_room.moderator_pw,
            'owner_id': meeting_room.owner_id,
            'status': meeting_room.status,
            'mute_participants_on_join': meeting_room.mute_participants_on_join,
            'require_mod_approval': meeting_room.require_mod_approval,
            'allow_any_user_start': meeting_room.allow_any_user_start,
            'all_users_join_as_mod': meeting_room.all_users_join_as_mod,
            'allow_recording': meeting_room.allow_recording,
            'max_number_of_participants': meeting_room.max_number_of_participants,
            'welcome_message': meeting_room.welcome_message,
            'public_share_token': meeting_room.share_token,
            "meeting_role": shared_meeting_role,
            "room_share_type": 'SHARED',
            "private_setting": meeting_room.private_setting_id,
            "require_meeting_password": meeting_room.require_meeting_password,
            "live_stream_active": meeting_room.live_stream_active,
            "live_stream_feedback_active": meeting_room.live_stream_feedback_active,
            "files": files
        }
        
        if meeting_room.private_setting_id == -1:
            meeting_room_private_setting = {
                "id": -1,
                "setting_name": _("System setting")
            }
        else:
            try:
                meeting_room_private_setting_entry = BBBPrivateSetting.objects.get(id=meeting_room.private_setting_id)
                meeting_room_private_setting = {
                    "id": meeting_room_private_setting_entry.id,
                    "setting_name": meeting_room_private_setting_entry.setting_name
                }
                
            except BBBPrivateSetting.DoesNotExist:
                meeting_room_private_setting = None
        
        return_data["private_setting_info"] = meeting_room_private_setting



        # try:
        #     user_groups = synserv.get_personal_groups_by_user(request.user.username)
        #     user_groups_id = []
        #     # Get all the groups that user belongs to
        #     for group in user_groups:
        #         user_groups_id.append(group.id)

        #     shared_meeting_room = MeetingRoomShare.objects.get(
        #         Q(share_to_user=request.user.email, meeting_room_id = meeting_room_id, share_type="SHARED_TO_USER") |
        #         Q(meeting_room_id = meeting_room_id, group_id__in=user_groups_id, share_type="SHARED_TO_GROUP")
        #     )
        #     meeting_room = None
        #     if shared_meeting_room.share_type == 'SHARED_TO_USER':
        #         meeting_room = MeetingRoom.objects.get(id=shared_meeting_room.meeting_room_id)
        #         return_data = {
        #             'id': meeting_room.id,
        #             'room_name': meeting_room.room_name,
        #             'attendee_pw': meeting_room.attendee_pw, 
        #             'moderator_pw': meeting_room.moderator_pw,
        #             'owner_id': meeting_room.owner_id,
        #             'status': meeting_room.status,
        #             'mute_participants_on_join': meeting_room.mute_participants_on_join,
        #             'require_mod_approval': meeting_room.require_mod_approval,
        #             'allow_any_user_start': meeting_room.allow_any_user_start,
        #             'all_users_join_as_mod': meeting_room.all_users_join_as_mod,
        #             'allow_recording': meeting_room.allow_recording,
        #             'max_number_of_participants': meeting_room.max_number_of_participants,
        #             'welcome_message': meeting_room.welcome_message,
        #             'public_share_token': meeting_room.share_token,
        #             "meeting_role": shared_meeting_room.user_role,
        #             "room_share_type": shared_meeting_room.share_type,
        #             "require_meeting_password": meeting_room.require_meeting_password,
        #             "private_setting" : meeting_room.private_setting_id,
        #         }
        #     elif shared_meeting_room.share_type == 'SHARED_TO_GROUP':
        #         meeting_role = getCorrespondingRoleForGroupMeeting(request.user, shared_meeting_room.group_id)
        #         meeting_room = MeetingRoom.objects.get(id=shared_meeting_room.meeting_room_id)
        #         if meeting_role == "ATTENDEE":
        #             return_data = {
        #                 'id': meeting_room.id,
        #                 'room_name': meeting_room.room_name,
        #                 'owner_id': meeting_room.owner_id,
        #                 'status': meeting_room.status,
        #                 'mute_participants_on_join': meeting_room.mute_participants_on_join,
        #                 'require_mod_approval': meeting_room.require_mod_approval,
        #                 'allow_any_user_start': meeting_room.allow_any_user_start,
        #                 'all_users_join_as_mod': meeting_room.all_users_join_as_mod,
        #                 'allow_recording': meeting_room.allow_recording,
        #                 'max_number_of_participants': meeting_room.max_number_of_participants,
        #                 'welcome_message': meeting_room.welcome_message,
        #                 "meeting_role": meeting_role,
        #                 "room_share_type": shared_meeting_room.share_type,
        #                 "require_meeting_password": meeting_room.require_meeting_password,
        #                 "private_setting" : meeting_room.private_setting_id,
        #             }
        #         else:  
        #             return_data = {
        #                 'id': meeting_room.id,
        #                 'room_name': meeting_room.room_name,
        #                 'attendee_pw': meeting_room.attendee_pw, 
        #                 'moderator_pw': meeting_room.moderator_pw,
        #                 'owner_id': meeting_room.owner_id,
        #                 'status': meeting_room.status,
        #                 'mute_participants_on_join': meeting_room.mute_participants_on_join,
        #                 'require_mod_approval': meeting_room.require_mod_approval,
        #                 'allow_any_user_start': meeting_room.allow_any_user_start,
        #                 'all_users_join_as_mod': meeting_room.all_users_join_as_mod,
        #                 'allow_recording': meeting_room.allow_recording,
        #                 'max_number_of_participants': meeting_room.max_number_of_participants,
        #                 'welcome_message': meeting_room.welcome_message,
        #                 'public_share_token': meeting_room.share_token,
        #                 "meeting_role": meeting_role,
        #                 "room_share_type": shared_meeting_room.share_type,
        #                 "require_meeting_password": meeting_room.require_meeting_password,
        #                 "private_setting" : meeting_room.private_setting_id,
        #             }
        #     if meeting_room.private_setting_id == -1:
        #         meeting_room_private_setting = {
        #             "id": -1,
        #             "setting_name": _("System setting")
        #         }
        #     else:
        #         try:
        #             meeting_room_private_setting_entry = BBBPrivateSetting.objects.get(id=meeting_room.private_setting_id)
        #             meeting_room_private_setting = {
        #                 "id": meeting_room_private_setting_entry.id,
        #                 "setting_name": meeting_room_private_setting_entry.setting_name
        #             }
                    
        #         except BBBPrivateSetting.DoesNotExist:
        #             meeting_room_private_setting = None
            
        #     return_data["private_setting_info"] = meeting_room_private_setting

        # except MeetingRoomShare.DoesNotExist:
        #     return api_error(code=404, msg=_('Meeting not found.'))
        # except Exception as e:
        #     return api_error(code=500, msg=_('Internal server error.'))

        return api_response(code=200, data=return_data)
        
    def put(self, request, meeting_room_id):
        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id for edit.'))

        room_name = request.POST.get('name', None)
        attendee_password = request.POST.get('attendee_password', None)
        moderator_password = request.POST.get('moderator_password', None)
        private_bbb_settting_id = request.POST.get('private_setting_id', -1)

        meeting_role = getMeetingRoomRole(request.user, meeting_room_id)
        
        if meeting_role is None:
            return api_error(code=404, msg=_('Meeting not found.'))
            
        meeting_room = MeetingRoom.objects.get(
            id=meeting_room_id,
        )  
        # All good. Begin edit
        if attendee_password is None:
            attendee_password = self.randomPassword(12)
        
        if moderator_password is None:
            moderator_password = self.randomPassword(12)

        meeting_room.room_name = room_name
        meeting_room.attendee_pw = attendee_password
        meeting_room.moderator_pw = moderator_password
        meeting_room.mute_participants_on_join = request.POST.get('mute_participants_on_join', 'false') == "true"
        meeting_room.require_mod_approval = request.POST.get('require_mod_approval', 'false') == "true"
        meeting_room.allow_any_user_start = request.POST.get('allow_any_user_start', 'false') == "true"
        meeting_room.all_users_join_as_mod = request.POST.get('all_users_join_as_mod', 'false') == "true"
        meeting_room.allow_recording = request.POST.get('allow_recording', 'false') == "true"
        meeting_room.require_meeting_password = request.POST.get('require_meeting_password', 'false') == "true"
        meeting_room.max_number_of_participants = request.POST.get('max_number_of_participants', 0)
        meeting_room.welcome_message = request.POST.get('welcome_message', '')
        meeting_room.private_setting_id = int(private_bbb_settting_id)
        meeting_room.updated_at = datetime.datetime.now()
        meeting_room.live_stream_active = request.POST.get('live_stream_active', 'false') == "true"
        meeting_room.live_stream_feedback_active = request.POST.get('live_stream_feedback_active', 'false') == "true"

        meeting_room.save()

        files = request.POST.getlist('files', None)
        if files is not None:
            MeetingRoomFile.objects.filter(meeting_room_id=meeting_room_id).delete()
            for f in files:
                new_file = MeetingRoomFile()
                new_file.meeting_room_id = meeting_room_id
                new_file.presentation_file = f
                new_file.save()

        return api_response(code=200, data=None, msg=_('Meeting updated successfully. Changes will be applied next time you start the meeting'))

    def delete(self, request, meeting_room_id):
        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id for delete.'))
        
        try:
            meeting_room = MeetingRoom.objects.get(
                id=meeting_room_id,
                owner_id=request.user.email
            )
            if meeting_room is None:
                return api_error(code=404, msg=_('Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))

        if meeting_room.status == 'IN_PROGRESS':
            return api_error(code=400, msg=_('The meeting is still in progress. You need to stop the meeting before removing it.'))

        ## delete all the share entries
        MeetingRoomShare.objects.filter(meeting_room_id=meeting_room.id).delete()
        ## delete all the file entries
        MeetingRoomFile.objects.filter(meeting_room_id=meeting_room.id).delete()
        ## delete the meeting room themself
        meeting_room.delete()
        
        return api_response(code=200, data=None, msg=_('Delete meeting successfully'))

class StartMeetingView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def post (self, request, meeting_room_id):
        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id for starting.'))
        
        meeting_role = getMeetingRoomRole(request.user, meeting_room_id)

        if meeting_role is None:
            return api_error(code=404, msg=_('Meeting not found.'))

        try:
            meeting_room = MeetingRoom.objects.get(id=meeting_room_id)
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('Meeting not found.'))
        
        if meeting_room.allow_any_user_start == False:
            if meeting_role == 'ATTENDEE' and meeting_room.status != "IN_PROGRESS":
                return api_error(code=404, msg=_('Meeting not found.'))
        
        # Check if the room is required for password
        meeting_password = request.POST.get('meeting_password', '')
        if meeting_room.owner_id != request.user.email and meeting_room.require_meeting_password == True:
            if meeting_password == '':
                return api_error(code=400, msg=_('Please provide password for the meeting.'))
            # Check the corresponding password based on user role in the meeting
            if meeting_role == 'MODERATOR' and (meeting_password != meeting_room.moderator_pw and meeting_password != meeting_room.attendee_pw):
                return api_error(code=400, msg=_('Incorrect password.'))
            if meeting_role == 'ATTENDEE' and meeting_password != meeting_room.attendee_pw:
                return api_error(code=400, msg=_('Incorrect password.'))
        
        # Good to start meeting
        request_url = request.build_absolute_uri('/')[:-1].strip("/")
        end_meeting_callback_url = request_url + '/api3/meeting-rooms/bbb-callback/end-meeting?meetingID='+meeting_room.b3_meeting_id

        BBBInstance = getBBBInstance(meeting_room.private_setting_id)
        if BBBInstance is None:
            return api_error(code=400, msg=_('BBB server config of this meeting is not found or not available'))

        try:
            if meeting_room.live_stream_active:
                if BBBInstance.getLiveStreamToken() is not None:
                    api_url = "https://" + str(BBBInstance.getLiveStreamServer()) + "/api/info/"
                    result = requests.post(api_url,
                                           data={
                                               "api_token": BBBInstance.getLiveStreamToken(),
                                               "bbb_server": BBBInstance.getServerURL()
                                           })
                    result_dict = result.json()
                    if not result_dict['IsAllowed']:
                        return api_error(code=400, msg=_(
                            'Maximum concurrent streams reached. Please disable streaming to be able to start this meeting'))

        except Exception as e:
            return api_error(code=400, msg=_(
                'Error checking for maximum concurrent streams:' + str(e) ))

        meeting_files = getMeetingFilesDownloadLink(meeting_room.id, meeting_room.owner_id)

        xml_for_download_links = ''
        if len(meeting_files) > 0:
            for meeting_file_url in meeting_files:
                xml_for_download_links = xml_for_download_links + "  <module name='presentation'> <document url='"+meeting_file_url+"' />  </module>  "

        xml_for_presentation_file = "<?xml version='1.0' encoding='UTF-8'?><modules>	"+ xml_for_download_links +" </modules>"
        
        allow_recording = False

        if config.BBB_ALLOW_MEETING_RECORDINGS == 1 or config.BBB_ALLOW_MEETING_RECORDINGS == '1':
            allow_recording = meeting_room.allow_recording

        bbb_create_meeting_result = BBBInstance.createNewBBBMeeting({
            'name': meeting_room.room_name,
            'attendeePW': meeting_room.attendee_pw,
            'moderatorPW': meeting_room.moderator_pw,
            'meetingID': meeting_room.b3_meeting_id,
            'logoutURL': request_url + '/end-meeting',
            'meta_endCallbackUrl': end_meeting_callback_url,
            'allowModsToUnmuteUsers': True,
            'muteOnStart': meeting_room.mute_participants_on_join,
            'guestPolicy': 'ASK_MODERATOR' if meeting_room.require_mod_approval == True else 'ALWAYS_ACCEPT',
            'allowStartStopRecording': False,
            'autoStartRecording': True,
            'record': allow_recording,
            'maxParticipants': meeting_room.max_number_of_participants + 1 if meeting_room.max_number_of_participants != 0 else 0,
            'welcome': meeting_room.welcome_message,
        }, xml_for_presentation_file)

        if bbb_create_meeting_result == False:
            return api_error(code=500, msg=_('Failed to start the meeting'))
        
        bbbMeetingInfo = BBBInstance.getBBBMeetingInfo(meeting_room.b3_meeting_id)
        if int(bbbMeetingInfo['participantCount']) >= meeting_room.max_number_of_participants and meeting_room.max_number_of_participants != 0:
            return api_error(code=400, msg=_('The meeting is full'))

        meeting_room.status = "IN_PROGRESS"
        meeting_room.save()

        # generate URL for joinning meeting as mod

        join_password = meeting_room.attendee_pw
        if meeting_room.owner_id == request.user.email:
            join_password = meeting_room.moderator_pw
        elif meeting_room.all_users_join_as_mod == True:
            join_password = meeting_room.moderator_pw
        elif meeting_role == 'MODERATOR':
            join_password = meeting_room.moderator_pw

        join_url = BBBInstance.joinMeeting({
            'fullName': email2nickname(request.user.email),
            'meetingID': meeting_room.b3_meeting_id,
            'password': join_password,
            'xml': "<modules>	<module name='presentation'> <document url='https://scholar.harvard.edu/files/torman_personal/files/samplepptx.pptx' /> </module></modules>"
        })

        return api_response(code=200, data={"join_url": join_url}, msg=_('Meeting started successfully'))


class StopMeetingView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def post(self, request, meeting_room_id):
        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id for stopping.'))
        
        try:
            meeting_room = MeetingRoom.objects.get(
                id=meeting_room_id
            )
            if meeting_room is None:
                return api_error(code=404, msg=_('Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))
        
        if meeting_room.status == "STOPPED":
            return api_error(code=400, msg=_('The meeting was already stopped.'))
        
        # Do a call to BBB here to end the meeting
        BBBInstance = getBBBInstance(meeting_room.private_setting_id)
        if BBBInstance is None:
            return api_error(code=400, msg=_('BBB server config of this meeting is not found or not available'))

        BBBInstance.endMeeting(meeting_room.b3_meeting_id, meeting_room.moderator_pw)

        meeting_room.status = "STOPPED"
        meeting_room.save()

        return api_response(code=200, data=None, msg=_('Meeting stopped successfully'))

class MeetingRoomByShareTokenView(APIView):

    def get(self, request, share_meeting_room_token):
        if share_meeting_room_token is None:
            return api_error(code=400, msg=_('Invalid meeting code'))
        
        try:
            meeting_room = MeetingRoom.objects.get(
                share_token=share_meeting_room_token
            )
            if meeting_room is None:
                return api_error(code=404, msg=_('Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))
        
        result = {
            "id": meeting_room.id,
            "room_name": meeting_room.room_name,
            "status": meeting_room.status,
            "owner_id": meeting_room.owner_id,
            "updated_at": meeting_room.updated_at,
            "require_meeting_password": meeting_room.require_meeting_password,
        }
        return api_response(code=200, data=result, msg=_('Get meeting successfully'))
    
    def post(self, request, share_meeting_room_token):
        full_name = request.POST.get('fullName', '')

        if full_name is None or full_name == '':
            return api_error(code=400, msg=_('You need to provide your fullname.'))

        try:
            meeting_room = MeetingRoom.objects.get(
                share_token=share_meeting_room_token
            )
            if meeting_room is None:
                return api_error(code=404, msg=_('Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))
        
        join_password = request.POST.get('joinPassword', '')
        if meeting_room.require_meeting_password == True:
            if join_password != meeting_room.attendee_pw and join_password != meeting_room.moderator_pw:
                return api_error(code=400, msg=_('Incorrect join password.'))
        else:
            join_password = meeting_room.attendee_pw
        request_url = request.build_absolute_uri('/')[:-1].strip("/")
        
        ## Contact BBB
        BBBInstance = getBBBInstance(meeting_room.private_setting_id)
        if BBBInstance is None:
            return api_error(code=400, msg=_('BBB server config of this meeting is not found or not available'))
        if meeting_room.allow_any_user_start == True or (meeting_room.require_meeting_password == True and join_password == meeting_room.moderator_pw):
            bbb_meeting_info = BBBInstance.getBBBMeetingInfo(meeting_room.b3_meeting_id)
            if bbb_meeting_info == False:
                end_meeting_callback_url = request_url + '/api3/meeting-rooms/bbb-callback/end-meeting?meetingID='+meeting_room.b3_meeting_id
                
                meeting_files = getMeetingFilesDownloadLink(meeting_room.id, meeting_room.owner_id)

                xml_for_download_links = ''
                if len(meeting_files) > 0:
                    for meeting_file_url in meeting_files:
                        xml_for_download_links = xml_for_download_links + "  <module name='presentation'> <document url='"+meeting_file_url+"' />  </module>  "

                xml_for_presentation_file = "<?xml version='1.0' encoding='UTF-8'?><modules>	"+ xml_for_download_links +" </modules>"
                
                allow_recording = False

                if config.BBB_ALLOW_MEETING_RECORDINGS == 1 or config.BBB_ALLOW_MEETING_RECORDINGS == '1':
                    allow_recording = meeting_room.allow_recording

                bbb_create_meeting_result = BBBInstance.createNewBBBMeeting({
                    'name': meeting_room.room_name,
                    'attendeePW': meeting_room.attendee_pw,
                    'moderatorPW': meeting_room.moderator_pw,
                    'meetingID': meeting_room.b3_meeting_id,
                    'logoutURL': request_url + '/end-meeting',
                    'meta_endCallbackUrl': end_meeting_callback_url,
                    'allowModsToUnmuteUsers': True,
                    'muteOnStart': meeting_room.mute_participants_on_join,
                    'guestPolicy': 'ASK_MODERATOR' if meeting_room.require_mod_approval == True else 'ALWAYS_ACCEPT',
                    'allowStartStopRecording': False,
                    'autoStartRecording': True,
                    'record': allow_recording,
                    'maxParticipants': meeting_room.max_number_of_participants + 1 if meeting_room.max_number_of_participants != 0 else 0,
                    'welcome': meeting_room.welcome_message,
                }, xml_for_presentation_file)
                
                if bbb_create_meeting_result == False:
                    return api_error(code=500, msg=_('Failed to start the meeting'))

                meeting_room.status = "IN_PROGRESS"
                meeting_room.save()

        bbbMeetingInfo = BBBInstance.getBBBMeetingInfo(meeting_room.b3_meeting_id)
        if bbbMeetingInfo != False:
            if int(bbbMeetingInfo['participantCount']) >= meeting_room.max_number_of_participants and meeting_room.max_number_of_participants != 0 :
                return api_error(code=400, msg=_('The meeting is full'))

        join_params = {
            'fullName': full_name,
            'meetingID': meeting_room.b3_meeting_id,
            'password': meeting_room.moderator_pw if meeting_room.all_users_join_as_mod == True else join_password,
        }
        join_url = BBBInstance.joinMeeting(join_params)
        if join_url == False:
            return api_error(code=200, data= { "success": False, }, msg=_('The meeting hasn\'t started yet.'))

        return api_response(code=200, data= { "success": True, "join_url": join_url, }, msg=_(''))
        
class EndMeetingCallbackForBBB(APIView):
    def get(self, request):
        bbb_meeting_id = request.GET.get("meetingID")
        try:    
            meeting_room = MeetingRoom.objects.get(
                b3_meeting_id=bbb_meeting_id
            )
            if meeting_room is None:
                return api_response(code=200, msg=_('Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=200, msg=_('Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))
        
        meeting_room.status = "STOPPED"
        meeting_room.save()

        return api_response(code=200, data=None, msg=_('Meeting stopped successfully'))

class MeetingRecordings(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def get(self, request, meeting_room_id):
        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id for getting records.'))

        meeting_role = getMeetingRoomRole(request.user, meeting_room_id)

        if meeting_role is None:
            return api_error(code=404, msg=_('Meeting not found.'))
        
        meeting_room = MeetingRoom.objects.get(
            id=meeting_room_id,
        )
        BBBInstance = getBBBInstance(meeting_room.private_setting_id)
        if BBBInstance is None:
            return api_error(code=400, msg=_('BBB server config of this meeting is not found or not available'))
        if meeting_role == 'MODERATOR':
            meeting_records = BBBInstance.getBBBRecordings({
                "meetingID": meeting_room.b3_meeting_id,
            })
        else:
            meeting_records = BBBInstance.getBBBRecordings({
                "meetingID": meeting_room.b3_meeting_id,
                "state": 'published'
            })

        return_data = {
            "recordings": [],
        }

        if meeting_records == False:
            return api_error(code=500, msg=_('Failed to retrieve record list'))

        if meeting_records["recordings"] is None:
            pass

        elif isinstance(meeting_records["recordings"]["recording"], dict):
            return_data["recordings"].append({
                "bbb_meeting_id": meeting_records["recordings"]["recording"]["meetingID"],
                "meeting_id": meeting_room.id,
                "meeting_owner": email2nickname(meeting_room.owner_id),
                "record_id": meeting_records["recordings"]["recording"]["recordID"],
                "preview_link": meeting_records["recordings"]["recording"]["playback"]["format"]["url"],
                "size": meeting_records["recordings"]["recording"]["size"],
                "end_time": meeting_records["recordings"]["recording"]["endTime"],
                "start_time": meeting_records["recordings"]["recording"]["startTime"],
                "room_name": meeting_room.room_name,
                # "thumbnail": meeting_records["recordings"]["recording"]["playback"]["format"]["preview"]["images"]["image"][0] if meeting_records["recordings"]["recording"]["playback"]["format"]["type"]=="presentation" and "preview" in meeting_records["recordings"]["recording"]["playback"]["format"] else None,
                "thumbnail": None,
                "number_of_participants": meeting_records["recordings"]["recording"]["participants"],
                "status": meeting_records["recordings"]["recording"]["state"],
                "playback_info": meeting_records["recordings"]["recording"]["playback"]
            })
        else:
            for recording in meeting_records["recordings"]["recording"]:
                return_data["recordings"].append({
                    "bbb_meeting_id": recording["meetingID"],
                    "meeting_id": meeting_room.id,
                    "meeting_owner": email2nickname(meeting_room.owner_id),
                    "record_id": recording["recordID"],
                    "preview_link": recording["playback"]["format"]["url"],
                    "size": recording["size"],
                    "end_time": recording["endTime"],
                    "start_time": recording["startTime"],
                    "room_name": meeting_room.room_name,
                    # "thumbnail": recording["playback"]["format"]["preview"]["images"]["image"][0] if recording["playback"]["format"]["type"]=="presentation" and "preview" in recording["playback"]["format"] else None,
                    "thumbnail": None,
                    "number_of_participants": recording["participants"],
                    "status": recording["state"],
                    "playback_info": recording["playback"]
                })

        return api_response(code=200, data=return_data, msg=_('Get meeting records successfully'))

class MeetingRecording(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def put(self, request, meeting_room_id, recording_id):

        publish = request.POST.get('publish', None)

        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id for publishing recordings.'))
        if recording_id is None :
            return api_error(code=400, msg=_('Please provide the recording_id for publishing.'))

        if publish != 'true' and publish != 'false':
            return api_error(code=400, msg=_('publish must be "true" or "false".'))
        
        meeting_role = getMeetingRoomRole(request.user, meeting_room_id)

        if meeting_role is None:
            return api_error(code=404, msg=_('Meeting not found'))
        if meeting_role != 'MODERATOR':
            return api_error(code=404, msg=_('Meeting not found'))

        meeting_room = MeetingRoom.objects.get(id=meeting_room_id)

        BBBInstance = getBBBInstance(meeting_room.private_setting_id)
        if BBBInstance is None:
            return api_error(code=400, msg=_('BBB server config of this meeting is not found or not available'))
            
        meeting_records = BBBInstance.getBBBRecordings({
            "meetingID": meeting_room.b3_meeting_id,
            "recordID": recording_id,
        });

        if meeting_records["recordings"] is None:
            return api_error(code=404, msg=_('Recording not found.'))

        message = ''

        if publish == 'true':
            BBBInstance.publishBBBRecordings(recording_id)
            message = _('Meeting recording published')
        else:
            BBBInstance.unpublishBBBRecordings(recording_id)
            message = _('Meeting recording unpublished')
        
        return api_response(code=200, msg=message)

    def delete(self, request, meeting_room_id, recording_id):
        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id for deleting records.'))
        if recording_id is None :
            return api_error(code=400, msg=_('Please provide the recording_id for deleting records.'))
        
        try:
            meeting_room = MeetingRoom.objects.get(
                id=meeting_room_id,
                owner_id=request.user.email
            )
            if meeting_room is None:
                return api_error(code=404, msg=_('Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))

        BBBInstance = getBBBInstance(meeting_room.private_setting_id)
        if BBBInstance is None:
            return api_error(code=400, msg=_('BBB server config of this meeting is not found or not available'))

        meeting_records = BBBInstance.getBBBRecordings({
            "meetingID": meeting_room.b3_meeting_id,
            "recordID": recording_id,
        });

        if meeting_records["recordings"] is None:
            return api_error(code=404, msg=_('Recording not found.'))
        
        BBBInstance.deleteBBBRecordings(recording_id)

        return api_response(code=200, msg=_('Meeting recording is deleted successfully.'))
        
class TestBBBConnection(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def get(self, request):
        if config.BBB_SERVER_URL == "" or config.BBB_SECRET_KEY == "":
            return api_error(code=400, data=None, msg=_('You need to provide both URL and sceret key of BBB before continuing.'))
        BBBInstance = getBBBInstance(-1);
        if BBBInstance.testConnection() == False:
            return api_error(code=400, msg=_('Failed to connect to BBB. Please check your configurations again.'))

        ## Try to create & stop meeting
        bbb_create_meeting_result = BBBInstance.createNewBBBMeeting({
            'name': 'Syncwerk Test Connection Room',
            'meetingID': 'syncwerk-test-connection-room',
            'moderatorPW': 'syncwerk-test-bbb'
        })
        
        if bbb_create_meeting_result == False:
            return api_error(code=400, msg=_('Failed to connect to BBB. Please check your configurations again.'))

        bbb_end_meeting_result = BBBInstance.endMeeting('syncwerk-test-connection-room', 'syncwerk-test-bbb')
        if bbb_end_meeting_result == False:
            return api_error(code=400, msg=_('Failed to connect to BBB. Please check your configuration again'))

        return api_error(code=200, msg=_('Test connection to BBB successfully.'))

class TestPrivateBBBSettingConnection(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def post(self, request):
        bbb_url = request.POST.get('bbb_url', '')
        bbb_secret = request.POST.get('bbb_secret', '')

        if bbb_url == '' or bbb_secret == '':
            return api_error(code=400, msg=_('Please provide the BBB URL and BBB secret for testing connection.'))
        
        meeting_id = "syncwerk-{}".format(uuid.uuid4())

        BBBInstance = getBBBInstance(-1)
            
        BBBInstance.setServerURL(bbb_url)
        BBBInstance.setSecret(bbb_secret)

        ## Try to create & stop meeting
        try:
            bbb_create_meeting_result = BBBInstance.createNewBBBMeeting({
                'name': 'Syncwerk Test Connection Room',
                'meetingID': meeting_id,
                'moderatorPW': 'syncwerk-test-bbb'
            })
            
            if bbb_create_meeting_result == False:
                return api_error(code=400, msg=_('Failed to connect to BBB. Please check your configurations again.'))
        except Exception:
            return api_error(code=400, msg=_('Failed to connect to BBB. Please check your configurations again.'))

        try:
            bbb_end_meeting_result = BBBInstance.endMeeting(meeting_id, 'syncwerk-test-bbb')
            if bbb_end_meeting_result == False:
                return api_error(code=400, msg=_('Failed to connect to BBB. Please check your configuration again'))
        except Exception:
            return api_error(code=400, msg=_('Failed to connect to BBB. Please check your configurations again.'))

        return api_error(code=200, msg=_('Test connection to BBB successfully.'))
        
class ShareMeetingRoomPublic(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def randomShareToken(self, stringLength=24):
        letters = string.ascii_letters + string.digits
        return ''.join(random.choice(letters) for i in range(stringLength))

    def post(self, request, meeting_room_id):
        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id.'))

        try:
            meeting_room = MeetingRoom.objects.get(
                id=meeting_room_id,
                owner_id=request.user.email
            )
            if meeting_room is None:
                return api_error(code=404, msg=_('Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))
        
        meeting_room.share_token = self.randomShareToken()
        meeting_room.save()

        return api_response(code=200, msg=_('Public link created successfully'))

    def delete(self, request, meeting_room_id):
        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id.'))

        try:
            meeting_room = MeetingRoom.objects.get(
                id=meeting_room_id,
                owner_id=request.user.email
            )
            if meeting_room is None:
                return api_error(code=404, msg=_('Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))
        
        meeting_room.share_token = None
        meeting_room.save()

        return api_response(code=200, msg=_('Public link removed successfully'))

class ShareMeetingRoomToUsersEntries(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def get(self, request, meeting_room_id):
        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id.'))
        try:
            meeting_room = MeetingRoom.objects.get(
                id=meeting_room_id,
                owner_id=request.user.email
            )
            if meeting_room is None:
                return api_error(code=404, msg=_('Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))

        all_shares_to_user_entries = MeetingRoomShare.objects.filter(meeting_room_id=meeting_room.id, share_type="SHARED_TO_USER")

        all_shares_result = []

        for share_entry in all_shares_to_user_entries:
            all_shares_result.append(
                {
                    "id": share_entry.id,
                    "meeting_room_id": share_entry.meeting_room_id,
                    "role": share_entry.user_role,
                    "created_at": share_entry.created_at,
                    "email": share_entry.share_to_user,
                    "nickname": email2nickname(share_entry.share_to_user)
                }
            )
        return api_response(code=200, data={ "success": True, "data": all_shares_result }, msg='')

    def post(self, request, meeting_room_id):
        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id.'))

        share_to_str = request.POST.get('share_to', None)
        share_role = request.POST.get('role', '')

        if share_role != 'ATTENDEE' and share_role != 'MODERATOR':
            return api_error(code=400, msg=_('Role must be ATTENDEE or MODERATOR'))

        if share_to_str is None:
            return api_error(code=400, msg=_('Please provide the user list to share the meeting.'))
        
        list_share_to = share_to_str.split(',')
        if len(list_share_to) == 0:
            return api_error(code=400, msg=_('Please provide the user list to share the meeting.'))
        
        for user in list_share_to:
            if request.user.email == user:
                return api_error(code=400, msg=_('You cannot share the meeting to yourself'))
            try:
                User.objects.get(email=user)
            except User.DoesNotExist:
                error_msg = 'User %s not found.' % user
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)
            try:
                MeetingRoomShare.objects.get(share_to_user=user, meeting_room_id=meeting_room_id, share_type="SHARED_TO_USER")
                # Error
                return api_error(code=400, msg=_('This room was already shared to user %s.' % user))
            except MeetingRoomShare.DoesNotExist:
                pass
        
        try:
            meeting_room = MeetingRoom.objects.get(
                id=meeting_room_id,
                owner_id=request.user.email
            )
            if meeting_room is None:
                return api_error(code=404, msg=_('Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))

        # Validation is good. Create the shares now
        for user in list_share_to:
            new_share = MeetingRoomShare()
            new_share.meeting_room_id = meeting_room.id
            new_share.share_to_user = user
            new_share.user_role = share_role
            new_share.share_type = "SHARED_TO_USER"

            new_share.save()
        
        return api_response(code=200, msg=_('Share to users successfully'))
    
class ShareMeetingRoomToUsersEntry(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def put(self, request, meeting_room_id, share_entry_id):

        share_role = request.POST.get('role', '')

        if share_role != 'ATTENDEE' and share_role != 'MODERATOR':
            return api_error(code=400, msg=_('Role must be ATTENDEE or MODERATOR'))

        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id.'))
        if share_entry_id is None :
            return api_error(code=400, msg=_('Please provide the share_entry_id.'))
        try:
            meeting_room = MeetingRoom.objects.get(
                id=meeting_room_id,
                owner_id=request.user.email
            )
            if meeting_room is None:
                return api_error(code=404, msg=_('Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))
        
        # all good, remove the entry
        try:
            share_entry = MeetingRoomShare.objects.get(id=share_entry_id)
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('Share not found.'))
        
        share_entry.user_role = share_role
        share_entry.save()

        return api_response(code=200, msg=_('Change role successfully'))
    
    def delete(self, request, meeting_room_id, share_entry_id):
        
        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id.'))
        if share_entry_id is None :
            return api_error(code=400, msg=_('Please provide the share_entry_id.'))
        try:
            meeting_room = MeetingRoom.objects.get(
                id=meeting_room_id,
                owner_id=request.user.email
            )
            if meeting_room is None:
                return api_error(code=404, msg=_('Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))
        
        # all good, remove the entry
        MeetingRoomShare.objects.filter(id=share_entry_id).delete()
        return api_response(code=200, msg=_('Share removed successfully'))

class MeetingSearchGroupToShare(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def get(self, request):
        query = request.GET.get('q', '')

        username = request.user.username

        user_groups = synserv.get_personal_groups_by_user(username)

        groups = []

        for g in user_groups:
            group_info = get_group_info(g.id)
            if query in group_info["name"]:
                groups.append(group_info)
        
        return api_response(data=groups)

class ShareMeetingRoomToGroupEntries(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def get(self, request, meeting_room_id):
        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id.'))
        try:
            meeting_room = MeetingRoom.objects.get(
                id=meeting_room_id,
                owner_id=request.user.email
            )
            if meeting_room is None:
                return api_error(code=404, msg=_('Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))

        all_share_to_group_entries = MeetingRoomShare.objects.filter(meeting_room_id=meeting_room.id, share_type="SHARED_TO_GROUP")

        all_shares_result = []

        for share_entry in all_share_to_group_entries:
            group_info = get_group_info(share_entry.group_id)
            all_shares_result.append(
                {
                    "id": share_entry.id,
                    "meeting_room_id": share_entry.meeting_room_id,
                    "group_name": group_info["name"],
                    "group_id": share_entry.group_id
                }
            )
        return api_response(code=200, data={ "success": True, "data": all_shares_result }, msg='')

    def post(self, request, meeting_room_id):
        username = request.user.username
        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id.'))

        share_to_str = request.POST.get('share_to', None)

        if share_to_str is None:
            return api_error(code=400, msg=_('Please provide the group list to share the meeting.'))
        
        list_share_to = share_to_str.split(',')
        if len(list_share_to) == 0:
            return api_error(code=400, msg=_('Please provide the group list to share the meeting.'))
        
        for group in list_share_to:
            try:
                group_id = search_group_id_by_exact_name(group, username)
                if group_id == -1:
                    return api_error(code=400, msg=_('Please provide a valid group to share the meeting.'))
                MeetingRoomShare.objects.get(group_id=group_id, meeting_room_id=meeting_room_id, share_type="SHARED_TO_GROUP")
                group_info = get_group_info(int(group_id))
                # Error
                return api_error(code=400, msg=_('This room was already shared to group %s.' % group_info["name"]))
            except MeetingRoomShare.DoesNotExist:
                pass
        
        try:
            meeting_room = MeetingRoom.objects.get(
                id=meeting_room_id,
                owner_id=request.user.email
            )
            if meeting_room is None:
                return api_error(code=404, msg=_('Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))

        # Validation is good. Create the shares now
        for group in list_share_to:
            group_id = search_group_id_by_exact_name(group, username)
            new_share = MeetingRoomShare()
            new_share.meeting_room_id = meeting_room.id
            new_share.group_id = group_id
            new_share.share_type="SHARED_TO_GROUP"

            new_share.save()
        
        return api_response(code=200, msg=_('Share to groups successfully'))

class ShareMeetingRoomToGroupEntry(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def delete(self, request, meeting_room_id, share_entry_id):
        
        if meeting_room_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_room_id.'))
        if share_entry_id is None :
            return api_error(code=400, msg=_('Please provide the share_entry_id.'))
        try:
            meeting_room = MeetingRoom.objects.get(
                id=meeting_room_id,
                owner_id=request.user.email
            )
            if meeting_room is None:
                return api_error(code=404, msg=_('Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))
        
        # all good, remove the entry
        MeetingRoomShare.objects.filter(id=share_entry_id).delete()
        return api_response(code=200, msg=_('Share removed successfully'))

class BBBPrivateSettingList(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def get(self, request):
        all_user_settings = BBBPrivateSetting.objects.filter(user_id=request.user.email)
        setting_list = [
            {
                "id": -1,
                "setting_name": _("System setting"),
                "bbb_server_domain_name": urlparse(config.BBB_SERVER_URL).netloc if urlparse(config.BBB_SERVER_URL).netloc != '' else config.BBB_SERVER_URL
            }
        ]
        for setting in all_user_settings:
            setting_list.append({
                "id": setting.id,
                "setting_name": setting.setting_name,
                "bbb_server_domain_name": urlparse(setting.bbb_server,).netloc if urlparse(setting.bbb_server,).netloc != '' else setting.bbb_server,
            })
        return api_response(code=200, data=setting_list)

    # def get(self, request):
    #     # Get all the groups that user belongs to
    #     user_groups = synserv.get_personal_groups_by_user(request.user.username)
    #     user_groups_id = []
    #     # Get all the groups that the user is the owner
    #     for group in user_groups:
    #         group_info = get_group_info(group.id)
    #         if request.user.email == group_info["owner"]["email"]:
    #             user_groups_id.append(group.id)

    #     # Get the tenant that the user is the admin (remember, 1 user can only be in 1 tenant at a time)
    #     try:
    #         tenant_admin = TenantAdmin.objects.get(user=request.user.email)
    #         tenant_id = tenant_admin.tenant_id
    #     except TenantAdmin.DoesNotExist:
    #         tenant_id = -1

        
    #     # Get all the private BBB setting in the list
    #     print tenant_id
    #     print 'HOHOOHOHO'
    #     all_private_settings = BBBPrivateSetting.objects.filter(
    #         (
    #            Q(user_id=request.user.email) |
    #            Q(group_id__in=user_groups_id) |
    #            Q(tenant_id=1)
    #         ) &
    #         Q(is_active=True)
    #     )
    #     print len(all_private_settings)
    #     config_list = [{
    #         "id": -1,
    #         "type": "SYSTEM",
    #         "user_id": None,
    #         "group_name": None,
    #         "tenant_name": None,
    #     }]
    #     for setting in all_private_settings:
    #         print setting
    #         if setting.user_id is not None and setting.user_id != '':
    #             if config.BBB_ALLOW_USER_PRIVATE_SERVER == 1:
    #                 config_list.append({
    #                     "id": setting.id,
    #                     "type": "PERSONAL",
    #                     "user_id": email2nickname(setting.user_id),
    #                     "group_name": None,
    #                     "tenant_name": None,
    #                 })
    #         elif setting.group_id is not None:
    #             if config.BBB_ALLOW_GROUPS_PRIVATE_SERVER == 1:
    #                 group_info = get_group_info(setting.group_id)
    #                 config_list.append({
    #                     "id": setting.id,
    #                     "type": "GROUP",
    #                     "user_id": None,
    #                     "group_name": group_info["name"],
    #                     "tenant_name": None,
    #                 })
    #         elif setting.tenant_id is not None:
    #             if config.BBB_ALLOW_TENANTS_PRIVATE_SERVER == 1:
    #                 tenant_info = Tenant.objects.get(id=setting.tenant_id)
    #                 config_list.append({
    #                     "id": setting.id,
    #                     "type": "TENANT",
    #                     "user_id": None,
    #                     "group_name": None,
    #                     "tenant_name": tenant_info.name,
    #                     "is_active": setting.is_active
    #                 })
        
    #     return api_response(code=200, data=config_list)

class BBBPrivateSettingEntries(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def get(self, request):
        current_user_private_bbb_settings = BBBPrivateSetting.objects.filter(user_id=request.user.email).order_by('setting_name')
        result = []
        for setting in current_user_private_bbb_settings:
            number_of_meetings = MeetingRoom.objects.filter(private_setting_id=setting.id).count()
            result.append({
                'id': setting.id,
                'setting_name': setting.setting_name,
                'bbb_server': urlparse(setting.bbb_server,).netloc if urlparse(setting.bbb_server,).netloc != '' else setting.bbb_server,
                'created_at': setting.created_at,
                'number_of_meetings': number_of_meetings,
            })

        return api_response(code=200, data=result, msg="")

    def post(self, request):
        config_name = request.POST.get('bbb_config_name', '')
        bbb_server = request.POST.get('bbb_server', '')
        bbb_secret = request.POST.get('bbb_secret', '')
        live_stream_token = request.POST.get('live_stream_token', '')
        live_stream_server = request.POST.get('live_stream_server', '')

        if config_name.strip() == '':
            return api_error(code=400, msg=_("Please provide the configuration name."))
        if len(config_name) > 255:
            return api_error(code=400, msg=_("Configuration name can only be 255 character max."))
        if bbb_server.strip() == '':
            return api_error(code=400, msg=_("Please provide the url of the BBB server."))
        if bbb_secret == '':
            return api_error(code=400, msg=_("Please provide the shared secret of the BBB server."))

        # Validation done. Prepare to create the new one
        new_bbb_setting = BBBPrivateSetting()
        new_bbb_setting.setting_name = config_name
        new_bbb_setting.bbb_server = bbb_server
        new_bbb_setting.bbb_secret = bbb_secret
        new_bbb_setting.user_id = request.user.email
        new_bbb_setting.is_active = True
        new_bbb_setting.live_stream_token = live_stream_token
        new_bbb_setting.live_stream_server = live_stream_server

        new_bbb_setting.save()

        return api_response(code=200, msg="BBB Configuration created successfully.")


class BBBPrivateSettingEntry(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def get(self, request, setting_id):
        try:
            setting_entry = BBBPrivateSetting.objects.get(
                id=setting_id,
                user_id=request.user.email
            )
        except BBBPrivateSetting.DoesNotExist:
            return api_error(code=404, msg=_("BBB configuration not found"))

        return_data = {
            'id': setting_entry.id,
            'setting_name': setting_entry.setting_name,
            'bbb_server': setting_entry.bbb_server,
            'bbb_secret': setting_entry.bbb_secret,
            'created_at': setting_entry.created_at,
        }

        return api_response(code=200, data=return_data)

    def put(self, request, setting_id):
        config_name = request.POST.get('bbb_config_name', '')
        bbb_server = request.POST.get('bbb_server', '')
        bbb_secret = request.POST.get('bbb_secret', '')

        if config_name.strip() == '':
            return api_error(code=400, msg=_("Please provide the configuration name."))
        if len(config_name) > 255:
            return api_error(code=400, msg=_("Configuration name can only be 255 character max."))
        if bbb_server.strip() == '':
            return api_error(code=400, msg=_("Please provide the url of the BBB server."))
        if bbb_secret == '':
            return api_error(code=400, msg=_("Please provide the shared secret of the BBB server."))

        try:
            setting_entry = BBBPrivateSetting.objects.get(
                id=setting_id,
                user_id=request.user.email
            )
        except BBBPrivateSetting.DoesNotExist:
            return api_error(code=404, msg=_("BBB configuration not found"))

        # Validation done. begin to update
        setting_entry.setting_name = config_name
        setting_entry.bbb_server = bbb_server
        setting_entry.bbb_secret = bbb_secret

        setting_entry.save()

        return api_response(code=200, msg="BBB Configuration updated successfully.")
    
    def delete(self, request, setting_id):
        try:
            setting_entry = BBBPrivateSetting.objects.get(
                id=setting_id,
                user_id=request.user.email
            )
        except BBBPrivateSetting.DoesNotExist:
            return api_error(code=404, msg=_("BBB configuration not found"))

        # Update all the meetings that used the setting to the fallback setting of SYSTEM
        MeetingRoom.objects.filter(private_setting_id=setting_id).update(private_setting_id=-1)
        # delete all the share entries
        BBBPrivateSetting.objects.filter(id=setting_id).delete()

        return api_response(code=200, msg=_("BBB configurations deleted successfully"))

