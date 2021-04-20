import logging
import csv
from itertools import groupby

import operator
from functools import reduce

from rest_framework import serializers, status
from rest_framework.authentication import SessionAuthentication
from django.http import HttpResponse

from django.core.paginator import Paginator
from django.db.models import Q
from django.dispatch import receiver
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.base import APIView
from restapi.api3.models import UserActivity
from restapi.api3.serializers import PaginagtionSerializer
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import (api_error, api_response,
                                get_client_ip_for_event_log, get_perm,
                                get_repo_update_changes, get_user_common_info,
                                get_device_name_from_request, get_device_name_from_token)
from restapi.api3.constants import EventLogActionType, RepoPermission
from restapi.auth.signals import user_logged_in_success_event, user_logged_in_failed_event
from restapi.signals import (file_access_signal, perm_audit_signal,
                             repo_update_commit_signal, repo_update_signal,
                             send_email_signal, share_upload_link_signal)
from restapi.utils import is_org_context
from restapi.views import list_inner_pub_repos
from synserv import syncwerk_api, get_repo, syncwserv_threaded_rpc
from wsgidav.addons.syncwerk.syncwerk_dav_provider import (
    get_group_repos, get_groups_by_user, get_repo_last_modify)
from restapi.settings import DEFAULT_EVENT_LOG_DEVICE_NAME
logger = logging.getLogger(__name__)

class InboundUserActivitiesSerializer(PaginagtionSerializer):
    q = serializers.CharField(required=False, help_text="search", default=None)
    format_str = serializers.BooleanField(required=False,default=True)



class UserActivitiesSerializer(serializers.ModelSerializer):
    sentence = serializers.SerializerMethodField()
    from_f = serializers.SerializerMethodField()
    to_f = serializers.SerializerMethodField()
    user_info = serializers.SerializerMethodField()
    folder_name = serializers.SerializerMethodField()
    user_sub_folder_file = serializers.SerializerMethodField()
    class Meta:
        model = UserActivity
        # fields = '__all__'
        exclude = ['id', 'sub_folder_file']

    def get_sentence(self,obj):
        return obj.get_locale_str(format_str = self.context['validated_data'].get('format_str'))

    def get_from_f(self, obj):
        return obj.from_f

    def get_to_f(self, obj):
        return obj.to_f

    def get_user_info(self, obj):
        if obj.name:
            return get_user_common_info(obj.name)
        return None

    def get_folder_name(self, obj):
        return obj.folder_name

    def get_user_sub_folder_file(self, obj):
        # Change to use user_sub_folder_file because of default sub_folder_file shared sub repo contain original repo name
        return obj.user_sub_folder_file

class UserActivitiesExportCSVSerializer(serializers.ModelSerializer):
    user_sub_folder_file = serializers.SerializerMethodField()
    class Meta:
        model = UserActivity
        # fields = '__all__'
        exclude = ['id', 'sub_folder_file','user_id']
    def get_user_sub_folder_file(self, obj):
        # Change to use user_sub_folder_file because of default sub_folder_file shared sub repo contain original repo name
        return obj.user_sub_folder_file


class UserActivitiesBaseView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    serializer_class = UserActivitiesSerializer

    def get_user_repo_id_list(self, request):
        """Get all repo id of user

        Arguments:
            request {[type]} -- [description]

        Returns:
            [list] -- [list of user's repo]
        """
        repo_ids = []

        email = request.user.username
        org_id = None
        if is_org_context(request):
            org_id = request.user.org.org_id

        # owned_repos
        if org_id:
            repo_ids.extend(r.id for r in syncwerk_api.get_org_owned_repo_list(
                org_id, email, ret_corrupted=True))
        else:
            repo_ids.extend(r.id for r in syncwerk_api.get_owned_repo_list(email,
                                                                           ret_corrupted=True))

        # shared repos
        shared_repos = []
        if org_id:
            shared_repos = syncwerk_api.get_org_share_in_repo_list(org_id,email, -1, -1)
        else:
            shared_repos = syncwerk_api.get_share_in_repo_list(email, -1, -1)

        for repo in shared_repos:
            # This mean not sub repo
            if not repo.origin_repo_id:
                repo_ids.append(repo.repo_id)

        # Group repos
        groups = get_groups_by_user(email, None)
        repo_ids.extend(rid for rid in get_group_repos(email, None, groups))

        # org repos
        if request.user.permissions.can_view_org():
            repo_ids.extend(r.repo_id for r in list_inner_pub_repos(request))
        
        return list(set(repo_ids))

    def get_user_shared_subrepo(self,request):
        shared_sub_repo = []

        email = request.user.username
        org_id = None
        if is_org_context(request):
            org_id = request.user.org.org_id

        shared_repos = []
        if org_id:
            shared_repos = syncwerk_api.get_org_share_in_repo_list(org_id,email, -1, -1)
        else:
            shared_repos = syncwerk_api.get_share_in_repo_list(email, -1, -1)

        for repo in shared_repos:
            # This mean not sub repo
            if repo.origin_repo_id:
                shared_sub_repo.append({
                    "folder_id":repo.origin_repo_id,
                    "sub_folder_file": repo.origin_path,
                    "name": repo.name
                })
        
        return shared_sub_repo

        

    def get_queryset(self, request, q = None, with_sentence=True):
        email = request.user.username
        org_id = None
        if is_org_context(request):
            org_id = request.user.org.org_id

        repo_ids = self.get_user_repo_id_list(request)

        filters = [
            Q(name=email),
            Q(folder_id__in=repo_ids)
        ]

        # Handle sub repo
        subrepo_filter = []
        for subrepo in self.get_user_shared_subrepo(request):
            subrepo_filter.append(
                reduce(operator.and_,
                            (Q(sub_folder_file__startswith=subrepo['sub_folder_file']),
                                Q(folder_id=subrepo['folder_id'])))
            )
        
        if len(subrepo_filter) > 0:
            filters.append(Q(reduce(operator.or_,subrepo_filter)))
        
        # Query acivity relate to user and repo that user involved
        queryset = UserActivity.objects
        
        if with_sentence:
            queryset = UserActivity.objects.with_raw_sentence(queryset=queryset)
        
        # Set default to get user_sub_folder_file
        queryset = UserActivity.objects.with_user_sub_folder_file(email=email, org_id=org_id, queryset=queryset)


        queryset = queryset.filter(reduce(operator.or_,filters))

        # Search 
        if q:
            queryset = queryset.filter(raw_sentence__icontains=q)

        # Ordering
        queryset = queryset.order_by('-updated_at')

        return queryset


class UserActivitiesView(UserActivitiesBaseView):

    def get(self, request):
        # Deserializer
        serializer = InboundUserActivitiesSerializer(
            data=request.GET,
            context={
                'request': request
                })

        # Check is serializing valid or not
        if not serializer.is_valid(raise_exception=False):
            return api_error(status.HTTP_400_BAD_REQUEST, serializer.errors)

        # Get page
        page = serializer.validated_data.get('page')
        per_page = serializer.validated_data.get('per_page')

        # Search
        q = serializer.validated_data.get('q',None)

        # Query set
        queryset = self.get_queryset(request, q,serializer.validated_data)


        # Pagination
        paginator = Paginator(queryset, per_page)

        # Pagination variable
        has_next_page = False
        current_page = page
        total_result = 0
        logs = []

        # Check request page is suitable
        if page <= paginator.num_pages:
            activites_page = paginator.page(page)
            has_next_page = activites_page.has_next()
            logs = activites_page.object_list
            total_result = activites_page.paginator.count

        page_info = {
            'has_next_page': has_next_page,
            'current_page': page,
            'total_result': total_result,
        }

        user_activities = []

        for updated_at, group in groupby(logs, lambda x: x.updated_at.date()):
            # Date
            date = updated_at.strftime('%d.%m.%Y')

            # Get activity sentence
            response_serializer = self.serializer_class(
                sorted(group, key=lambda r:r.updated_at, reverse=True), 
                many=True, 
                context={
                    'request': request,
                    'validated_data': serializer.validated_data
                    })
            activities =  response_serializer.data

            # Insert to response data
            user_activities.append({
                'date': date,
                'activities': activities
            })

        resp = {"page_info": page_info, "user_activities": user_activities}
        return api_response(data=resp)


# Export to CSV
class UserActivitiesExportCSV(UserActivitiesBaseView):
    serializer_class = UserActivitiesExportCSVSerializer


    def get(self, request):
        queryset = self.get_queryset(request)
        

        response = HttpResponse(content_type='text/csv')
        writer = csv.writer(response, lineterminator='\n')
        
        serializer = self.serializer_class(
                queryset, 
                many=True)

        # Get key
        keys = []
        for f in serializer.child.fields.keys():
            keys.append(f)
        
        # Write header
        writer.writerow(keys)


        for activity in serializer.data:

            row_value = []
            for key in keys:
                row_value.append(activity[key])

            writer.writerow(row_value)

        response['Content-Disposition'] = 'attachment; filename=activity_logs.csv'
        return response


# Signal handler
# User login user activities
@receiver(user_logged_in_success_event)
def user_logged_in_success_user_activity(sender, user, request, **kwargs):
    # Try to get device name
    device_name = DEFAULT_EVENT_LOG_DEVICE_NAME
    key = kwargs.get('key',None)
    if key:
        device_name = get_device_name_from_token(key)
    
    # Save user log
    UserActivity.objects.create(
        user_id=user.id,
        name=user.email,
        ip_address=get_client_ip_for_event_log(request),
        device_name = device_name,
        folder=None,
        folder_id=None,
        sub_folder_file=None,
        action_type=EventLogActionType.LOGIN_SUCCESS.value,
        recipient=None,
        permissions=None
    )


@receiver(user_logged_in_failed_event)
def user_logged_in_failed_user_activity(sender, request, **kwargs):
    # Save user log

    # Try to get device name
    device_name = kwargs.get('device_name',DEFAULT_EVENT_LOG_DEVICE_NAME)

    # try get user name
    name = request.POST.get('login', None)

    UserActivity.objects.create(
        user_id=None,
        name=name,
        ip_address=get_client_ip_for_event_log(request),
        device_name = device_name,
        folder=None,
        folder_id=None,
        sub_folder_file=None,
        action_type=EventLogActionType.LOGIN_FAILED.value,
        recipient=None,
        permissions=None
    )

# File Access user_activity
@receiver(file_access_signal)
def file_access_user_activity(sender, request, repo, path, **kwargs):
    # Save file Access log

    # try to get username
    name = None
    try:
        name = request.user.email
    except Exception as e:
        logger.error('Can not get request user email')

    # try to get user_id
    user_id = None
    try:
        user_id = request.user.id
    except Exception as e:
        logger.error('Can not get request user id')

    # try to get repo name
    folder = None
    try:
        folder = repo.name
    except Exception as e:
        logger.error('Can not get repo name: %s' % e)

    folder_id = None
    try:
        folder_id = repo.repo_id
    except Exception as e:
        logger.error('Can not get repo id: %s' % e)

    # Save user_activity
    UserActivity.objects.create(
        user_id=user_id,
        name=name,
        ip_address=get_client_ip_for_event_log(request),
        device_name = get_device_name_from_request(request),
        folder=folder,
        folder_id=folder_id,
        sub_folder_file=path,
        action_type=EventLogActionType.FILE_ACCESS.value,
        recipient=None,
        permissions=None
    )

# Permission user activites signal
@receiver(perm_audit_signal)
def perm_user_activity(sender, request, etype, to, recipient_type,  repo, path, perm, **kwargs):
    # Save file Perm user log

    # try to get username
    name = None
    try:
        name = request.user.email
    except Exception as e:
        logger.error('Can not get request user email')

    # try to get user_id
    user_id = None
    try:
        user_id = request.user.id
    except Exception as e:
        logger.error('Can not get request user id')

    # try to get repo name
    folder = None
    try:
        folder = repo.name
    except Exception as e:
        logger.error('Can not get repo name: %s' % e)

    folder_id = None
    try:
        folder_id = repo.repo_id
    except Exception as e:
        logger.error('Can not get repo id: %s' % e)


    # Save user_activity
    UserActivity.objects.create(
        user_id=user_id,
        name=name,
        ip_address=get_client_ip_for_event_log(request),
        device_name = get_device_name_from_request(request),
        folder=folder,
        folder_id=folder_id,
        sub_folder_file=path,
        action_type=EventLogActionType.get_value_by_etype(etype,recipient_type),
        recipient=to,
        permissions=RepoPermission.get_value_by_name(perm)
    )

# Share link signal
@receiver(share_upload_link_signal)
def share_upload_link_user_activity(sender, request, action_type, repo, path, perm, **kwargs):
    # Save file share link log

    # try to get username
    name = None
    try:
        name = request.user.email
    except Exception as e:
        logger.error('Can not get request user email')

    # try to get user_id
    user_id = None
    try:
        user_id = request.user.id
    except Exception as e:
        logger.error('Can not get request user id')

    # try to get repo name
    folder = None
    try:
        folder = repo.name
    except Exception as e:
        logger.error('Can not get repo name: %s' % e)

    folder_id = None
    try:
        folder_id = repo.repo_id
    except Exception as e:
        logger.error('Can not get repo id: %s' % e)

    # Save user_activity
    UserActivity.objects.create(
        user_id=user_id,
        name=name,
        ip_address=get_client_ip_for_event_log(request),
        device_name = get_device_name_from_request(request),
        folder=folder,
        folder_id=folder_id,
        sub_folder_file=path,
        action_type=action_type,
        recipient=None,
        permissions=perm
    )


@receiver(repo_update_commit_signal)
def repo_update_audit(sender, commit, commit_differ, **kwargs):
    # Save file share link log

    # try to get username
    name = None
    try:
        if sender:
            name = sender.email
        else:
            name = commit.creator_name
    except Exception as e:
        logger.error('Can not get request user email')

    # try to get user_id
    user_id = None
    try:
        if sender:
            user_id = sender.id
    except Exception as e:
        logger.error('Can not get request user id')

    # try to get repo name
    folder = None
    try:
        folder = commit.repo_name
    except Exception as e:
        logger.error('Can not get repo name: %s' % e)

    folder_id = None
    try:
        folder_id = commit.repo_id
    except Exception as e:
        logger.error('Can not get repo id: %s' % e)

    device_name = DEFAULT_EVENT_LOG_DEVICE_NAME
    try: 
        repo = get_repo(commit.repo_id)
        current_commit = syncwserv_threaded_rpc.get_commit(repo.id, repo.version, commit.commit_id)
        if current_commit.device_name:
            device_name = current_commit.device_name
    except Exception as e:
        logger.error('Can not get device name: %s' % e)

    for change in get_repo_update_changes(commit_differ):
        # Save audit log
        UserActivity.objects.create(
            user_id=user_id,
            name=name,
            ip_address=None,
            device_name = device_name,
            folder=folder,
            folder_id=folder_id,
            sub_folder_file=change['path'],
            action_type=change['action_type'],
            recipient=None,
            permissions=None
        )


@receiver(send_email_signal)
def send_email_user_activity(sender, request, recipient, **kwargs):
    # user_activity Email

    # Save file share link log
    # try to get username
    name = None
    user_id = None
    ip_address = None
    device_name = None

    if request:
        try:
            name = request.user.email
        except Exception as e:
            logger.error('Can not get request user email')

        try:
            user_id = request.user.id
        except Exception as e:
            logger.error('Can not get request user id')
        device_name = get_device_name_from_request(request),
        ip_address = get_client_ip_for_event_log(request)

    UserActivity.objects.create(
        user_id=user_id,
        name=name,
        ip_address=ip_address,
        device_name=device_name,
        folder=None,
        folder_id=None,
        sub_folder_file=None,
        action_type=EventLogActionType.SEND_MAIL.value,
        recipient=recipient,
        permissions=None)


@receiver(repo_update_signal)
def repo_create_delete_user_activity(sender, request, action_type, repo_id, repo_name, **kwargs):
    # Note that retrive ip_address in this is possible, but for the uniform with handle repo_update, ip_address is set to none
    # try to get username
    name = None
    try:
        if sender:
            name = sender.email
    except Exception as e:
        logger.error('Can not get request user email')

    # try to get user_id
    user_id = None
    try:
        if sender:
            user_id = sender.id
    except Exception as e:
        logger.error('Can not get request user id')

    # try to get repo name
    folder = None
    try:
        folder = repo_name
    except Exception as e:
        logger.error('Can not get repo name: %s' % e)

    folder_id = None
    try:
        folder_id = repo_id
    except Exception as e:
        logger.error('Can not get repo id: %s' % e)

    # Save user activity
    UserActivity.objects.create(
        user_id=user_id,
        name=name,
        ip_address=None,
        device_name = get_device_name_from_request(request),
        folder=folder,
        folder_id=folder_id,
        sub_folder_file=None,
        action_type=action_type,
        recipient=None,
        permissions=None
    )
