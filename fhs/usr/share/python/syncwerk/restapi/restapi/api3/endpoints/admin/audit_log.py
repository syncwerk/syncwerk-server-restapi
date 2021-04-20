import csv
import datetime
import json
import logging
import os
import random

from rest_framework import parsers, serializers, status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.views import APIView

from django.core.paginator import Paginator
from django.dispatch import receiver
from django.http import HttpResponse
from django.utils.translation import ugettext as _
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.custom.admin.audit_log import AuditLog
from restapi.api3.models import AuditLog as AuditLogDBHandler
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema
from restapi.api3.utils import (api_error, api_response, get_action_type,
                                get_client_ip_for_event_log, get_perm,
                                get_repo_update_changes, get_device_name_from_request,
                                get_device_name_from_token)
from restapi.api3.constants import EventLogActionType, RepoPermission
from restapi.api3.utils.licenseInfo import parse_license_to_json
from restapi.auth.signals import user_logged_in_success_event, user_logged_in_failed_event
from restapi.notifications.models import (Notification, NotificationForm,
                                          UserNotification)
from restapi.notifications.utils import refresh_cache
from restapi.settings import ENABLE_AUDIT_LOG, DEFAULT_EVENT_LOG_DEVICE_NAME

from restapi.signals import (file_access_signal, perm_audit_signal,
                             repo_update_commit_signal, repo_update_signal,
                             send_email_signal, share_upload_link_signal)

from restapi.api3.serializers import PaginagtionSerializer

from synserv import get_repo, syncwserv_threaded_rpc

logger = logging.getLogger(__name__)


def is_audit_log_available():
    license_info = parse_license_to_json()
    available_features_arr = license_info['available_features']
    if license_info['edition'] == 'freeware':
        return True
    else:
        return True if 'auditLog'in available_features_arr and ENABLE_AUDIT_LOG else False


class InboundAuditLogSerializer(PaginagtionSerializer):
    name = serializers.CharField(required=False)
    updated_at__gte = serializers.DateField(required=False, help_text="Start update at")
    updated_at__lte = serializers.DateField(required=False, help_text="End update at")
    ip_address = serializers.CharField(required=False)
    device_name = serializers.CharField(required=False)
    folder = serializers.CharField(required=False)
    folder_id = serializers.CharField(required=False)
    sub_folder_file = serializers.CharField(required=False)
    recipient = serializers.CharField(required=False)
    action_type = serializers.CharField(required=False)
    permissions = serializers.CharField(required=False)

class CsvExportAuditLogSerializer(InboundAuditLogSerializer):
    
    def validate(self, attrs):
        attrs = super(CsvExportAuditLogSerializer, self).validate(attrs)

        # validate max day
        MAX_DAYS = 7

        start_date = attrs.get('updated_at__gte', None)
        end_date = attrs.get('updated_at__lte', datetime.datetime.date(datetime.datetime.now()))
        
        if start_date:
            delta = end_date - start_date
            if delta.days > MAX_DAYS:
                raise serializers.ValidationError('7 days is the maximum export Audit Log range')
        else:
            raise serializers.ValidationError('Start date is required')
        return attrs

class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLogDBHandler
        fields = '__all__'

class AdminAuditLog(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )
    serializer_class = AuditLogSerializer
     
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get Audit Log list',
        operation_description='''Get audit log lust''',
        tags=['admin-audit-log'],
        query_serializer=InboundAuditLogSerializer,
        responses={
            200: openapi.Response(
                description='Audit log list retrived successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "page_info": {
                                "current_page": 1,
                                "has_next_page": False
                            },
                            "audit_log": [
                                {
                                    "id":1,
                                    "user_id":1,
                                    "updated_at": "07-09-2017 10:15",
                                    "ip_address":"192.168.10.2/ Webapp",
                                    "folder": "My folder",
                                    "folder_id": "folder_id",
                                    "sub_folder_file": "read/write",
                                    "action_type":"Login",
                                    "recipient":"test_group",
                                    "permissions":"Read/Write"
                                }
                            ]
                        }
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": 'Token invalid'
                    }
                }
            ),
        }
    )
    def get(self, request, format=None):
        # Get all log api.

        # Deserializer
        serializer = InboundAuditLogSerializer(
            data=request.GET, 
            context={'request': request})

        # Check is serializing valid or not
        if not serializer.is_valid(raise_exception=False):
            return api_error(status.HTTP_400_BAD_REQUEST, serializer.errors)

        # Get page
        page = serializer.validated_data.pop('page')

        # Data 
        audit_log_instance = AuditLog.getInstance()
        audit_log_list_pagination = audit_log_instance.getAuditListPage(
            **serializer.validated_data
        )

        # Pagination variable
        has_next_page = False
        current_page = page
        total_result = 0
        audit_logs = []

        # Check request page is suitable
        if page <= audit_log_list_pagination.num_pages:
            audit_log_page = audit_log_list_pagination.page(page)
            has_next_page = audit_log_page.has_next()
            audit_logs = audit_log_page.object_list
            total_result = audit_log_page.paginator.count

        page_info = {
            'has_next_page': has_next_page,
            'current_page': page,
            'total_result': total_result,
        }

        audit_log_serializer = self.serializer_class(audit_logs, many=True)

        resp = {"page_info": page_info, "audit_log": audit_log_serializer.data}
        return api_response(data=resp)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Delete - Remove Audit Log list',
        operation_description='''Remove Audit Log list''',
        tags=['admin-audit-log'],
        responses={
            200: openapi.Response(
                description='Remove Audit Log list successfully.',
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
            )
        }
    )
    def delete(self, request, format=None):
        # Delete log api
        # Remove AuditLog Data 
        audit_log_instance = AuditLog.getInstance()
        audit_log_list_total = audit_log_instance.deleteAllAuditLog()
        return api_response(data="")

class AdminAuditLogCSV(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )  
    serializer_class = CsvExportAuditLogSerializer
    RECORD_NUM = 1000

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Export Audit log to CSV',
        operation_description='''Export Audit log to CSV''',
        query_serializer=CsvExportAuditLogSerializer,
        tags=['admin-audit-log'],
        responses={
            200: openapi.Response(
                description='Export Audit log to CSV successfully.',
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": 'Token invalid'
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
    def get(self, request):
        
        # Deserializer
        serializer = CsvExportAuditLogSerializer(
            data=request.GET, 
            context={'request': request})

        # Check is serializing valid or not
        if not serializer.is_valid(raise_exception=False):
            return api_error(status.HTTP_400_BAD_REQUEST, serializer.errors)


        audit_log_instance = AuditLog.getInstance()
        audit_log_list = audit_log_instance.getAuditListArray(
            **serializer.validated_data
        )

        response = HttpResponse(content_type='text/csv')
        writer = csv.writer(response, lineterminator='\n')
        
        count = 0
        for row in audit_log_list:
            if count == 0:
                headers = row.keys()
                writer.writerow(headers)
                count += 1
            writer.writerow(row.values())
        response['Content-Disposition'] = 'attachment; filename=audit_log.csv'

        return response

class AdminAuditLogDropdownInfo(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )  
    serializer_class = InboundAuditLogSerializer
    RECORD_NUM = 1000

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Dropdown info for Audit log',
        operation_description='''Dropdown info for to CSV''',
        tags=['admin-audit-log'],
        responses={
            200: openapi.Response(
                description='Dropdown info for Audit log successfully.',
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": 'Token invalid'
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
    def get(self, request):

        data = {
            'action_type': EventLogActionType.getValues(),
            'permission': RepoPermission.getValues()
        }
        return api_response(data=data)



# Signal handler
# User login audit log
@receiver(user_logged_in_success_event)
def user_logged_in_success(sender, user, request, **kwargs):
    
    # Try to get device name
    device_name = DEFAULT_EVENT_LOG_DEVICE_NAME
    key = kwargs.get('key',None)
    if key:
        device_name = get_device_name_from_token(key)

    if is_audit_log_available():
        # Save user log
        audit_log_instance = AuditLog.getInstance()

        audit_log_instance.createAuditLog(
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
def user_logged_in_failed(sender, request, **kwargs):
    # Try to get device name
    device_name = kwargs.get('device_name',DEFAULT_EVENT_LOG_DEVICE_NAME)

    if is_audit_log_available():
        # Save user log
        audit_log_instance = AuditLog.getInstance()
        # try get user name
        name = request.POST.get('login', None)

        audit_log_instance.createAuditLog(
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

# File Access audit log
@receiver(file_access_signal)
def file_access(sender, request, repo, path, **kwargs):
    if is_audit_log_available():
        # Save file Access log
        audit_log_instance = AuditLog.getInstance()
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


        # Save audit log
        audit_log_instance.createAuditLog(
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

# Permission audit signal
@receiver(perm_audit_signal)
def perm_audit(sender, request, etype, to, recipient_type,  repo, path, perm, **kwargs):
    if is_audit_log_available():
        # Save file Perm audit log
        audit_log_instance = AuditLog.getInstance()
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

        # Save audit log
        audit_log_instance.createAuditLog(
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
def share_upload_link_audit(sender, request, action_type, repo, path, perm, **kwargs):
    if is_audit_log_available():
        # Save file share link log
        audit_log_instance = AuditLog.getInstance()
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

        # Save audit log
        audit_log_instance.createAuditLog(
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
    if is_audit_log_available():
        # Save file share link log

        audit_log_instance = AuditLog.getInstance()
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
            audit_log_instance.createAuditLog(
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
def send_email_audit(sender, request, recipient, **kwargs):
    # Auditlog Email
    if is_audit_log_available():
        # Save file share link log

        audit_log_instance = AuditLog.getInstance()
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

            ip_address = get_client_ip_for_event_log(request)
            device_name = get_device_name_from_request(request),

        audit_log = AuditLog.getInstance()
        audit_log.createAuditLog(
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
def repo_create_delete_audit(sender, request, action_type, repo_id, repo_name, **kwargs):
    if is_audit_log_available():
        # Note that retrive ip_address in this is possible, but for the uniform with handle repo_update, ip_address is set to none
        audit_log_instance = AuditLog.getInstance()
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

        # Save audit log
        audit_log_instance.createAuditLog(
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
