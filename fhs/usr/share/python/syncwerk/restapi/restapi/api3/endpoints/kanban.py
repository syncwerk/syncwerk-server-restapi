import synserv
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import User
from django.core.cache import cache
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.timezone import now
from django.utils.translation import ugettext as _
from drf_yasg.utils import swagger_auto_schema
from rest_framework import (authentication, generics, permissions, serializers,
                            status)
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.endpoints.admin.groups import get_group_info
from restapi.api3.models import (KanbanAttach, KanbanBoard, KanbanColor,
                                 KanbanComment, KanbanHistory, KanbanProject,
                                 KanbanShare, KanbanShareLink,
                                 KanbanSubscription, KanbanSubTask, KanbanTag,
                                 KanbanTask)
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response, get_user_common_info
from restapi.settings import ADD_REPLY_TO_HEADER, REPLACE_FROM_EMAIL
from restapi.utils import is_pro_version, normalize_cache_key, send_html_email


def task_create_history(kanban_task, audit, username, request):
    kanban_history = KanbanHistory()
    kanban_history.audit = audit
    kanban_history.owner_id = username
    kanban_history.kanban_task = kanban_task
    kanban_history.save()
    if REPLACE_FROM_EMAIL:
        from_email = username
    else:
        from_email = None  # use default from email
    if ADD_REPLY_TO_HEADER:
        reply_to = username
    else:
        reply_to = None
    for s in kanban_task.kanbansubscription_set.all():
        send_html_email(
            _('Kanban Task Modified'),
            'kanban_task_modified_email.html', {
                'history':
                kanban_history,
                'link':
                request.build_absolute_uri('/kanban/project/%i/%i/%i' % (
                    kanban_task.kanban_board.kanban_project.id,
                    kanban_task.kanban_board.id,
                    kanban_task.id,
                ))
            },
            from_email, [s.user_id],
            reply_to=reply_to,
            request=request)


def has_valid_password(request, project_id):
    return request.session.get('password-valid-%s' % project_id)


def set_valid_password(request, project_id):
    request.session['password-valid-%s' % project_id] = True


# permissions
def filter_by_owner(Model, prefix, request):
    """
    Return list of objects of <Model> belonging to
    either KanbanProject with owner_id == <username>
    or to KanbanProject having KanbanShare with owner_id == <username>
    <prefix> - is a path to resolve relationship to KanbanProject
        in django's objects.filter() notation
        for example for KanbanSubTask it would be kanban_task__kanban_board
    """
    if prefix:
        prefix += '__'
    groups = [
        g.id for g in synserv.get_personal_groups_by_user(request.user.email)
    ]
    qs = Model.objects.filter(
        **{prefix + 'kanban_project__owner_id': request.user.username}
    ) | Model.objects.filter(**{
        prefix + 'kanban_project__kanbanshare__user_id':
        request.user.username
    }) | Model.objects.filter(
        **{prefix + 'kanban_project__kanbanshare__group_id__in': groups})
    token = request.session.get('token')
    if token:
        qs |= Model.objects.filter(
            **{prefix + 'kanban_project__kanbansharelink__token': token})
    return qs.distinct()


class ShareLinkAuthentication(authentication.BaseAuthentication):
    """
    Allow users visited public link and provided password to access API.
    """

    def authenticate(self, request):
        if request.session.get('anonymous_email'):
            return User(username=request.session.get('anonymous_email')), None


# Permission Classes
def has_project_permission(request, kanban_project, rw=None):
    if kanban_project.owner_id == request.user.username:
        return True
    groups = [
        g.id for g in synserv.get_personal_groups_by_user(request.user.email)
    ] if request.user.is_authenticated else []
    qs = (kanban_project.kanbanshare_set.filter(user_id=request.user.username)
          | kanban_project.kanbanshare_set.filter(group_id__in=groups))
    if request.method not in permissions.SAFE_METHODS or rw:
        qs = qs.filter(permission='rw')
    return qs.exists()


class ProjectPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method == "DELETE":
            # deleting permission handled specially in corresponding view
            return True
        return has_project_permission(request, obj)


class BoardPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return has_project_permission(request, obj.kanban_project)


class TaskPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return has_project_permission(request, obj.kanban_board.kanban_project)


class SubTaskPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return has_project_permission(
            request, obj.kanban_task.kanban_board.kanban_project)


class CommentPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return has_project_permission(
            request, obj.kanban_task.kanban_board.kanban_project)


class AttachmentPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return has_project_permission(
            request, obj.kanban_task.kanban_board.kanban_project)


class ShareLinkPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return has_project_permission(request, obj.project)


class SubscriptionPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return has_project_permission(request,
                                      obj.task.kanban_board.kanban_project)


# serializers
class KanbanShareSerializer(serializers.ModelSerializer):
    group_info = serializers.SerializerMethodField()

    # for backwards compatibility
    # owner_id = serializers.SerializerMethodField()

    class Meta:
        model = KanbanShare
        fields = ('id', 'kanban_project', 'share_type', 'user_id', 'group_id',
                  'permission', 'group_info')

    def get_group_info(self, obj):
        if obj.group_id:
            return get_group_info(obj.group_id)

    def get_owner_id(self, obj):
        return obj.user_id

    def validate_kanban_project(self, project):
        if KanbanProject.objects.get(
                pk=project.id
        ).owner_id != self.context['request'].user.username:
            raise serializers.ValidationError("Only project owner add share.")
        return project

    def validate_user_id(self, user_id):
        if user_id:
            for user in synserv.ccnet_threaded_rpc.search_emailusers(
                    'DB', user_id, 0, 10):
                if user.email == user_id:
                    break
            else:
                raise serializers.ValidationError(
                    _("User %s not found.") % user_id)


class KanbanShareLinkSerializer(serializers.ModelSerializer):
    link = serializers.SerializerMethodField()

    class Meta:
        model = KanbanShareLink
        fields = '__all__'
        read_only_fields = 'username', 'token', 'view_cnt'
        extra_kwargs = {'password': {'write_only': True}}

    def validate_project(self, project):
        if KanbanProject.objects.get(
                pk=project.
                id).owner_id != self.context['request'].user.username:
            raise serializers.ValidationError("Only project owner add share.")
        return project

    def create(self, validated_data):
        validated_data['username'] = self.context['request'].user.username
        if 'password' in validated_data:
            validated_data['password'] = make_password(
                validated_data['password'])
        return super(KanbanShareLinkSerializer, self).create(validated_data)

    def get_link(self, obj):
        return '/share-link/k/' + obj.token


class KanbanProjectSerializer(serializers.ModelSerializer):
    owner = serializers.SerializerMethodField()
    writable = serializers.SerializerMethodField()
    members = KanbanShareSerializer(
        source='kanbanshare_set', required=False, many=True)

    class Meta:
        model = KanbanProject
        fields = (
            'id',
            'project_name',
            'created_at',
            'updated_at',
            'writable',
            'members',
            'owner',
            'image',
        )

    def get_owner(self, obj):
        return get_user_common_info(obj.owner_id)

    def get_writable(self, obj):
        return has_project_permission(self.context['request'], obj, True)


class KanbanColorSerializer(serializers.ModelSerializer):
    class Meta:
        model = KanbanColor
        fields = '__all__'


class KanbanTagSerializer(serializers.ModelSerializer):
    class Meta:
        model = KanbanTag
        fields = '__all__'


class KanbanTaskSerializer(serializers.ModelSerializer):
    assignee = serializers.SerializerMethodField()
    color = serializers.SerializerMethodField()
    num_attachments = serializers.SerializerMethodField()
    tags = KanbanTagSerializer(many=True, required=False)

    class Meta:
        model = KanbanTask
        fields = (
            'id',
            'title',
            'due_date',
            'color',
            'order',
            'assignee',
            'tags',
            'completed',
            'description',
            'kanban_board',
            'num_attachments',
        )

    def get_assignee(self, obj):
        return get_user_common_info(obj.assignee_id)

    def get_color(self, obj):
        return [{'color': color.title} for color in obj.task_color.all()]

    def get_num_attachments(self, obj):
        return KanbanAttach.objects.filter(kanban_task=obj.id).count()


class KanbanTaskEditSerializer(KanbanTaskSerializer):
    # Hack to allow date instead of datatime in PUT/POST
    due_date = serializers.DateField()

    class Meta(KanbanTaskSerializer.Meta):
        pass


class KanbanCommentSerializer(serializers.ModelSerializer):
    owner = serializers.SerializerMethodField()

    class Meta:
        model = KanbanComment
        fields = 'id', 'owner', 'comment', 'created_at'

    def get_owner(self, obj):
        return get_user_common_info(obj.owner_id)


class KanbanAttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = KanbanAttach
        fields = 'id', 'title', 'image'


class KanbanSubTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = KanbanSubTask
        fields = 'id', 'title', 'completed', 'kanban_task'


class KanbanBoardSerializer(serializers.ModelSerializer):
    kanban_tasks = KanbanTaskSerializer(
        source='kanbantask_set', required=False, many=True)

    class Meta:
        model = KanbanBoard
        fields = (
            'id',
            'board_name',
            'board_order',
            'kanban_tasks',
            'kanban_project',
        )

    def validate_kanban_project(self, project):
        if not has_project_permission(self.context['request'], project, True):
            raise serializers.ValidationError("Project shared read-only.")
        return project


class KanbanSubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = KanbanSubscription
        fields = '__all__'
        read_only_fields = 'user_id',

    def validate_task(self, task):
        if not has_project_permission(self.context['request'],
                                      task.kanban_board.kanban_project):
            raise serializers.ValidationError("Project shared read-only.")
        if task.kanbansubscription_set.filter(
                user_id=self.context['request'].user.username).exists():
            raise serializers.ValidationError(
                "Already subscribed to this task.")
        return task

    def create(self, validated_data):
        validated_data['user_id'] = self.context['request'].user.username
        return super(KanbanSubscriptionSerializer, self).create(validated_data)


# ViewSets


class KanbanProjectsView(generics.ListCreateAPIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanProjectSerializer

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get Kanban Projects',
        operation_description='Gets a list of Kanban projects',
        tags=['projects'],
    )
    def get(self, request):
        groups = [
            g.id
            for g in synserv.get_personal_groups_by_user(request.user.email)
        ]
        result = {
            'kanban_projects':
            KanbanProjectSerializer(
                KanbanProject.objects.filter(owner_id=request.user.username)
                | KanbanProject.objects.filter(
                    kanbanshare__user_id=request.user.username) |
                KanbanProject.objects.filter(kanbanshare__group_id__in=groups),
                context={
                    'request': request
                },
                many=True,
            ).data
        }
        return api_response(
            code=200,
            data=result,
            msg='Get list of kanban projects successfully')


class KanbanProjectView(generics.RetrieveUpdateDestroyAPIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, ProjectPermission)
    serializer_class = KanbanProjectSerializer
    throttle_classes = (UserRateThrottle, )
    queryset = KanbanProject.objects.all()
    lookup_url_kwarg = 'kanban_project_id'

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get Kanban Project',
        operation_description='Gets a specific Kanban project',
        tags=['projects'],
    )
    def get(self, request, kanban_project_id):
        result = {
            'kanban_project':
            KanbanProjectSerializer(
                self.get_object(), context={
                    'request': request
                }).data
        }
        return api_response(
            code=200, data=result, msg='Get kanban project successfully')

    def post(self, request):
        data = request.data.copy()
        # accept image both
        # in <image> parameter (as supposed to be)
        # and as <file> (for compatibility with frontend code already done)
        if 'file' in data:
            data.setlist('image', data.getlist('file'))
            del data['file']
        serializer = KanbanProjectSerializer(
            data=data, context={'request': request})
        if serializer.is_valid():
            serializer.save(owner_id=request.user.username)
            return api_response(
                code=status.HTTP_201_CREATED,
                data=serializer.data,
                msg='Kanban Project created successfully')
        return api_error(
            code=status.HTTP_400_BAD_REQUEST,
            data=serializer.errors,
            msg='Error creating Kanban project')

    def put(self, request, kanban_project_id):
        data = request.data.copy()
        if 'file' in data:
            data.setlist('image', data.getlist('file'))
            del data['file']
        serializer = KanbanProjectSerializer(
            self.get_object(), data=data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return api_response(
                data=serializer.data,
                msg='Kanban Project updated successfully')
        return api_error(
            code=400,
            data=serializer.errors,
            msg='Error updating Kanban project')

    def delete(self, request, kanban_project_id=None):
        if kanban_project_id is None:
            return api_error(
                code=400,
                msg='Please provide the kanban_project_id to delete.')
        project = self.get_object()
        if project.owner_id != request.user.username:
            project.kanbanshare_set.filter(
                user_id=request.user.username).delete()
        else:
            project.delete()
        return api_response(
            code=status.HTTP_204_NO_CONTENT,
            msg='Kanban Project deleted successfully')


class KanbanSharesView(generics.ListCreateAPIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanShareSerializer
    queryset = KanbanShare.objects.all()

    def get_queryset(self):
        project = self.kwargs.get('kanban_project_id')
        if project:
            return super(KanbanSharesView,
                         self).get_queryset().filter(kanban_project=project)
        return super(KanbanSharesView, self).get_queryset()


class KanbanShareView(generics.RetrieveUpdateDestroyAPIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    queryset = KanbanShare.objects.all()
    serializer_class = KanbanShareSerializer
    lookup_url_kwarg = 'kanban_share_id'

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get Kanban Member',
        operation_description='Gets a specific Kanban Member',
        tags=['member'],
    )
    def get(self, request, kanban_share_id):
        if kanban_share_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_share_id to get.')
        result = {'kanban_member': self.get_serializer(self.get_object()).data}
        return api_response(
            code=200, data=result, msg='Get kanban member successfully')

    def post(self, request):
        data = request.data.copy()
        if 'kanban_project_id' in data:
            data.setlist('kanban_project', data.getlist('kanban_project_id'))
        serializer = KanbanShareSerializer(data=data)
        if serializer.is_valid():
            if (serializer.instance.kanban_project.owner_id !=
                    request.user.username):
                return Response(
                    "Only project owner modify share.",
                    status=status.HTTP_403_FORBIDDEN)
            serializer.save()
            return api_response(
                code=200,
                data=serializer.data,
                msg='Kanban member created successfully')
        return api_error(
            code=400,
            data=serializer.errors,
            msg='Error creating Kanban member')

    def put(self, request, kanban_share_id):
        if kanban_share_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_share_id for edit.')
        data = request.data.copy()
        if 'kanban_project_id' in data:
            data.setlist('kanban_project', data.getlist('kanban_project_id'))
        serializer = KanbanShareSerializer(
            self.get_object(), data=data, partial=True)
        if serializer.is_valid():
            if (serializer.instance.kanban_project.owner_id !=
                    request.user.username):
                return Response(
                    "Only project owner modify share.",
                    status=status.HTTP_403_FORBIDDEN)
            serializer.save()
            return api_response(
                code=200,
                data=serializer.data,
                msg='Kanban member updated successfully')
        return api_error(
            code=400,
            data=serializer.errors,
            msg='Error updating Kanban member')

    def delete(self, request, kanban_share_id):
        if kanban_share_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_share_id to delete.')
        member = self.get_object()
        result = {'id': member.id}
        member.delete()
        return api_response(
            code=200, data=result, msg='Kanban member deleted successfully')


class KanbanBoardsView(generics.ListCreateAPIView):
    authentication_classes = (SessionAuthentication, TokenAuthentication,
                              ShareLinkAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanBoardSerializer

    def get_queryset(self):
        if has_valid_password(self.request, self.kwargs['kanban_project_id']):
            return KanbanBoard.objects.filter(
                kanban_project=self.kwargs['kanban_project_id'])
        return filter_by_owner(KanbanBoard, '', self.request).filter(
            kanban_project=self.kwargs['kanban_project_id'])

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get Kanban Boards for a Project',
        operation_description='Gets a list of Kanban boards for a project',
        tags=['boards'],
    )
    def get(self, request, kanban_project_id):
        result = {
            'kanban_boards':
            KanbanBoardSerializer(self.get_queryset(), many=True).data
        }
        return api_response(
            code=200,
            data=result,
            msg='Get list of kanban boards successfully')


class KanbanBoardView(generics.RetrieveUpdateDestroyAPIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, BoardPermission)
    throttle_classes = (UserRateThrottle, )
    queryset = KanbanBoard.objects.all()
    lookup_url_kwarg = 'kanban_board_id'
    serializer_class = KanbanBoardSerializer

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get Kanban Board',
        operation_description='Gets a specific Kanban Board',
        tags=['projects'],
    )
    def get(self, request, kanban_board_id):
        if kanban_board_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_board_id to get.')
        result = {
            'kanban_board': KanbanBoardSerializer(self.get_object()).data
        }
        return api_response(
            code=200, data=result, msg='Get kanban board successfully')

    def post(self, request):
        kanban_project = request.POST.get('kanban_project', None)
        if kanban_project is None:
            return api_error(
                code=400,
                msg='Please provide the kanban_project for the board.')
        data = request.data.copy()
        data["kanban_project"] = kanban_project
        serializer = KanbanBoardSerializer(
            data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return api_response(
                code=200,
                data=serializer.data,
                msg='Kanban board created successfully')
        return api_error(
            code=400,
            data=serializer.errors,
            msg='Error creating Kanban board')

    def put(self, request, kanban_board_id):
        if kanban_board_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_board_id for edit.')
        serializer = KanbanBoardSerializer(
            self.get_object(), data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save(updated_at=timezone.now())
            return api_response(
                code=200,
                data=serializer.data,
                msg='Kanban board updated successfully')
        return api_error(
            code=400,
            data=serializer.errors,
            msg='Error creating Kanban board')

    def delete(self, request, kanban_board_id):
        if kanban_board_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_board_id to delete.')
        board = self.get_object()
        board.delete()
        result = {'id': board.id}
        return api_response(
            code=200, data=result, msg='Kanban board deleted successfully')


class KanbanTasksView(generics.ListCreateAPIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanTaskSerializer

    def get_queryset(self):
        return filter_by_owner(
            KanbanTask, 'kanban_board',
            self.request).filter(kanban_board=self.kwargs['kanban_board_id'])

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get Kanban Tasks for a Board',
        operation_description='Gets a list of Kanban tasks for a board',
        tags=['tasks'],
    )
    def get(self, request, kanban_board_id):
        result = {
            'kanban_tasks':
            self.get_serializer(self.get_queryset(), many=True).data
        }
        return api_response(
            code=200, data=result, msg='Get list of kanban tasks successfully')


class KanbanTaskView(generics.RetrieveUpdateDestroyAPIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, TaskPermission)
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanTaskSerializer
    lookup_url_kwarg = 'kanban_task_id'
    queryset = KanbanTask.objects.all()

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get Kanban Task',
        operation_description='Gets a specific Kanban Task',
        tags=['task'],
    )
    def get(self, request, kanban_task_id):
        if kanban_task_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_task_id to get.')
        result = {'kanban_task': KanbanTaskSerializer(self.get_object()).data}
        return api_response(
            code=200, data=result, msg='Get kanban task successfully')

    OLD_FIELDS_MAP = (
        ('task_title', 'title'),
        ('task_description', 'description'),
        ('task_due_date', 'due_date'),
        ('task_assignee', 'assignee'),
        ('task_completed', 'completed'),
    )

    def post(self, request):
        kanban_board = request.POST.get('kanban_board', None)
        if kanban_board is None:
            return api_error(
                code=400, msg='Please provide the kanban_board for the task.')
        # for backwards compatibility
        data = request.data.copy()
        for src, dst in self.OLD_FIELDS_MAP:
            if src in data:
                data.setlist(dst, data.getlist(src))
        serializer = KanbanTaskSerializer(data=data)
        if not serializer.is_valid():
            # try parsing due_date as date
            serializer = KanbanTaskEditSerializer(data=data)
        if serializer.is_valid():
            task = serializer.save(completed=False)
            for tag in request.data['tags'].split(','):
                if tag:
                    kanban_tag = KanbanTag.objects.filter(title=tag).first()
                    if kanban_tag is None:
                        kanban_tag = KanbanTag(title=tag)
                        kanban_tag.save()
                    task.tags.add(kanban_tag)
            color = request.data['color']
            kanban_color = KanbanColor.objects.filter(title=color).first()
            if kanban_color is None:
                kanban_color = KanbanColor(title=color)
                kanban_color.save()
            task.task_color.add(kanban_color)
            username = request.user.username
            task_create_history(task, "Task created", username, request)
            return api_response(code=status.HTTP_201_CREATED,
                                data=serializer.data,
                                msg='Kanban task created successfully')
        return api_error(code=status.HTTP_400_BAD_REQUEST,
                         data=serializer.errors,
                         msg='Error creating task')

    def put(self, request, kanban_task_id):
        if kanban_task_id is None:
            return api_error(code=400,
                             msg='Please provide the kanban_task_id for edit.')
        # for backwards compatibility
        data = request.data.copy()
        for src, dst in self.OLD_FIELDS_MAP:
            if src in data:
                data.setlist(dst, data.getlist(src))
        obj = self.get_object()
        old_data = KanbanTaskSerializer(obj).data
        serializer = KanbanTaskSerializer(obj, partial=True, data=data)
        if serializer.is_valid():
            task = serializer.save()
            task.updated_at = timezone.now()
            task.save()
            tags = request.POST.get('tags', None)
            if tags is not None:
                task.tags.clear()
                for tag in tags.split(','):
                    tag = tag.strip()
                    if not tag:
                        continue
                    kanban_tag = KanbanTag.objects.filter(title=tag).first()
                    if kanban_tag is None:
                        kanban_tag = KanbanTag(title=tag)
                        kanban_tag.save()
                    task.tags.add(kanban_tag)
            color = request.POST.get('color', None)
            if color is not None:
                task.task_color.clear()
                kanban_color = KanbanColor.objects.filter(title=color).first()
                if kanban_color is None:
                    kanban_color = KanbanColor(title=color)
                kanban_color.save()
                task.task_color.add(kanban_color)
            # Create history
            username = request.user.username
            serializer = KanbanTaskSerializer(self.get_object())
            for k in old_data:
                if old_data[k] != serializer.data[k]:
                    print(k)
                    task_create_history(task, "Task updated: %s changed" % k,
                                        username, request)
            return api_response(data=serializer.data,
                                msg='Kanban task updated successfully')
        return api_error(code=status.HTTP_400_BAD_REQUEST,
                         data=serializer.errors,
                         msg='Error creating Kanban task')

    def delete(self, request, kanban_task_id):
        if kanban_task_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_task_id to delete.')
        task = self.get_object()
        task.delete()
        result = {'id': task.id}
        return api_response(
            code=200, data=result, msg='Kanban task deleted successfully')


class KanbanSubTasksView(generics.ListCreateAPIView):

    authentication_classes = (SessionAuthentication, TokenAuthentication,
                              ShareLinkAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanSubTaskSerializer

    def get_queryset(self):
        return filter_by_owner(
            KanbanSubTask, 'kanban_task__kanban_board',
            self.request).filter(kanban_task_id=self.kwargs['kanban_task_id'])

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get Kanban Sub Tasks',
        operation_description='Gets all Kanban SubTasks',
        tags=['sub_tasks'],
    )
    def get(self, request, kanban_task_id):
        result = {
            'kanban_sub_tasks':
            KanbanSubTaskSerializer(self.get_queryset(), many=True).data
        }
        return api_response(
            code=200,
            data=result,
            msg='Get list of kanban sub tasks successfully')


class KanbanSubTaskView(generics.RetrieveUpdateDestroyAPIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, SubTaskPermission)
    throttle_classes = (UserRateThrottle, )
    queryset = KanbanSubTask.objects.all()
    lookup_url_kwarg = 'kanban_subtask_id'
    serializer_class = KanbanSubTaskSerializer

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get Kanban SubTask',
        operation_description='Gets a specific Kanban SubTask',
        tags=['sub_task'],
    )
    def get(self, request, kanban_subtask_id=None):
        if kanban_subtask_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_subtask_id to get.')
        result = {
            'kanban_sub_task': KanbanSubTaskSerializer(self.get_object()).data
        }
        return api_response(
            code=200, data=result, msg='Get kanban subtask successfully')

    def post(self, request):
        serializer = KanbanSubTaskSerializer(data=request.data)
        if serializer.is_valid():
            kanban_task_id = request.POST.get('kanban_task_id', None)
            kanban_subtask = serializer.save(
                kanban_task=get_object_or_404(KanbanTask, pk=kanban_task_id))
            # Create history
            username = request.user.username
            task_create_history(kanban_subtask.kanban_task,
                                "SubTask " + str(kanban_subtask.id) + "added",
                                username, request)
            return api_response(
                code=status.HTTP_201_CREATED,
                data=serializer.data,
                msg='Kanban subtask created successfully')
        return api_error(
            code=status.HTTP_400_BAD_REQUEST,
            data=serializer.errors,
            msg='Error creating Kanban subtask')

    def put(self, request, kanban_subtask_id=None):
        if kanban_subtask_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_subtask_id for edit.')
        serializer = KanbanSubTaskSerializer(
            self.get_object(), data=request.data)
        if serializer.is_valid():
            kanban_subtask = serializer.save()
            # Create history
            username = request.user.username
            task_create_history(
                kanban_subtask.kanban_task,
                "SubTask " + str(kanban_subtask.id) + "updated", username,
                request)
            return api_response(
                code=200,
                data=serializer.data,
                msg='Kanban subtask updated successfully')
        return api_error(
            code=400, data=serializer.errors, msg='Error modifing subtask')

    def delete(self, request, kanban_subtask_id):
        if kanban_subtask_id is None:
            return api_error(
                code=400,
                msg='Please provide the kanban_subtask_id to delete.')
        subtask = self.get_object()
        kanban_task = subtask.kanban_task
        subtask.delete()
        # Create history
        username = request.user.username
        task_create_history(kanban_task,
                            "SubTask " + str(kanban_subtask_id) + "deleted",
                            username, request)
        result = {'id': subtask.id}
        return api_response(code=200,
                            data=result,
                            msg='Kanban subtask deleted successfully')


class KanbanCommentsView(generics.ListCreateAPIView):

    authentication_classes = (SessionAuthentication, TokenAuthentication,
                              ShareLinkAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanCommentSerializer

    def get_queryset(self):
        return filter_by_owner(
            KanbanComment, 'kanban_task__kanban_board',
            self.request).filter(kanban_task_id=self.kwargs['kanban_task_id'])

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get Kanban Comments',
        operation_description='Gets all Kanban Comments',
        tags=['sub_tasks'],
    )
    def get(self, request, kanban_task_id):
        result = {
            'kanban_comments':
            self.get_serializer(self.get_queryset(), many=True).data
        }
        return api_response(
            code=200,
            data=result,
            msg='Get list of kanban comments successfully')


class KanbanCommentView(generics.RetrieveUpdateDestroyAPIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, CommentPermission)
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanCommentSerializer
    queryset = KanbanComment.objects.all()
    lookup_url_kwarg = 'kanban_comment_id'

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get Kanban Comment',
        operation_description='Gets a specific Kanban Comment',
        tags=['comment'],
    )
    def get(self, request, kanban_comment_id):
        if kanban_comment_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_subtask_id to get.')
        result = {
            'kanban_comment': KanbanCommentSerializer(self.get_object()).data
        }
        return api_response(
            code=200, data=result, msg='Get kanban comment successfully')

    def post(self, request):
        serializer = KanbanCommentSerializer(data=request.data)
        if serializer.is_valid():
            username = request.user.username
            kanban_task_id = request.POST.get('kanban_task_id', None)
            kanban_comment = serializer.save(
                owner_id=username,
                kanban_task=KanbanTask.objects.get(id=kanban_task_id))
            # Create history
            task_create_history(kanban_comment.kanban_task,
                                "Comment " + str(kanban_comment.id) + " added",
                                username, request)
            result = {'id': kanban_comment.id}
            return api_response(
                code=200,
                data=result,
                msg='Kanban kanban_comment created successfully')
        return api_error(
            code=400,
            data=serializer.errors,
            msg='Error creating Kanban kanban_comment')

    def delete(self, request, kanban_comment_id):
        if kanban_comment_id is None:
            return api_error(
                code=400,
                msg='Please provide the kanban_comment_id to delete.')

        comment = self.get_object()
        kanban_task = comment.kanban_task
        comment.delete()
        # Create history
        username = request.user.username
        task_create_history(kanban_task,
                            "Comment " + str(kanban_comment_id) + " deleted",
                            username, request)
        result = {'id': comment.id}
        return api_response(
            code=200, data=result, msg='Kanban comment deleted successfully')


class KanbanHistoryView(APIView):

    authentication_classes = (SessionAuthentication, TokenAuthentication,
                              ShareLinkAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def get_queryset(self):
        return filter_by_owner(
            KanbanHistory, 'kanban_task__kanban_board',
            self.request).filter(kanban_task=self.kwargs['kanban_task_id'])

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get History',
        operation_description='Gets History for Task',
        tags=['sub_tasks'],
    )
    def get(self, request, kanban_task_id):
        history_list = []
        for history in self.get_queryset():
            history_list.append({
                'id': history.id,
                'audit': history.audit,
                'created_at': history.created_at,
                'owner': get_user_common_info(history.owner_id)
            })
        result = {'kanban_history': history_list}
        return api_response(
            code=200, data=result, msg='Got history successfully')


class KanbanAttachmentsView(generics.ListCreateAPIView):

    authentication_classes = (SessionAuthentication, TokenAuthentication,
                              ShareLinkAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanAttachmentSerializer

    def get_queryset(self):
        return filter_by_owner(
            KanbanAttach, 'kanban_task__kanban_board',
            self.request).filter(kanban_task=self.kwargs['kanban_task_id'])

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get Kanban Attachments',
        operation_description='Gets a specific Kanban Attachments',
        tags=['comment'],
    )
    def get(self, request, kanban_task_id):
        if kanban_task_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_task_id to get.')
        kanban_attach = self.get_queryset()
        result = {
            'kanban_attachs': self.get_serializer(kanban_attach,
                                                  many=True).data
        }
        return api_response(
            code=200, data=result, msg='Get kanban attach successfully')


class KanbanAttachmentView(generics.RetrieveUpdateDestroyAPIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, AttachmentPermission)
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanAttachmentSerializer
    lookup_url_kwarg = 'kanban_attach_id'
    queryset = KanbanAttach.objects.all()

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get Kanban Attachment',
        operation_description='Gets a specific Kanban Attachment',
        tags=['comment'],
    )
    def get(self, request, kanban_attach_id):
        if kanban_attach_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_attach_id to get.')
        result = {'kanban_attach': self.get_serializer(self.get_object()).data}
        return api_response(
            code=200, data=result, msg='Get kanban attach successfully')

    def post(self, request):
        data = request.data.copy()
        if 'file' in data:
            data.setlist('image', data.getlist('file'))
            del data['file']
        serializer = KanbanAttachmentSerializer(data=data)
        if serializer.is_valid():
            kanban_task_id = request.POST.get('kanban_task_id', None)
            kanban_attach = serializer.save(
                kanban_task=KanbanTask.objects.get(id=kanban_task_id))
            # Create history
            username = request.user.username
            task_create_history(
                kanban_attach.kanban_task,
                "Attachment " + str(kanban_attach.id) + " added", username,
                request)
            return api_response(
                code=200,
                data=serializer.data,
                msg='Kanban attach created successfully')
        return api_error(
            code=400,
            data=serializer.errors,
            msg='Error creating Kanban attach')

    def delete(self, request, kanban_attach_id):
        if kanban_attach_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_attach_id to delete.')
        attach = self.get_object()
        kanban_task = attach.kanban_task
        attach.delete()
        # Create history
        username = request.user.username
        task_create_history(kanban_task,
                            "Attachment " + str(kanban_attach_id) + " added",
                            username, request)
        result = {'id': attach.id}
        return api_response(
            code=200, data=result, msg='Kanban attach deleted successfully')


class KanbanColorsView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get Kanban Colors',
        operation_description='Gets all Kanban Colors',
        tags=['colors'],
    )
    def get(self, request):
        kanban_color = KanbanColor.objects.all()
        result = {
            'kanban_colors': KanbanColorSerializer(kanban_color,
                                                   many=True).data
        }
        return api_response(
            code=200,
            data=result,
            msg='Get list of kanban colors successfully')


class KanbanColorView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def get_object(self, pk):
        try:
            return KanbanColor.objects.get(pk=pk)
        except KanbanProject.DoesNotExist:
            raise Http404

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get Kanban Color',
        operation_description='Gets a specific Kanban Color',
        tags=['color'],
    )
    def get(self, request, kanban_color_id):
        if kanban_color_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_color_id to get.')
        result = {
            'kanban_color':
            KanbanColorSerializer(self.get_object(kanban_color_id)).data
        }
        return api_response(
            code=200, data=result, msg='Get kanban task successfully')

    def post(self, request):
        serializer = KanbanColorSerializer(request.data)
        if serializer.is_valid():
            serializer.save()
            return api_response(
                code=200,
                data=serializer.data,
                msg='Kanban color created successfully')
        return api_error(
            code=400,
            data=serializer.errors,
            msg='Error creating Kanban color')

    def put(self, request, kanban_color_id):
        if kanban_color_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_color_id for edit.')
        serializer = KanbanColorSerializer(
            self.get_object(kanban_color_id), request.data)
        if serializer.is_valid():
            serializer.save()
            return api_response(
                code=200,
                data=serializer.data,
                msg='Kanban color updated successfully')
        return api_error(
            code=400,
            data=serializer.errors,
            msg='Error creating Kanban color')

    def delete(self, request, kanban_color_id):
        if kanban_color_id is None:
            return api_error(
                code=400, msg='Please provide the kanban_color_id to delete.')
        color = self.get_object(kanban_color_id)
        result = {'id': color.id}
        color.delete()
        return api_response(
            code=200, data=result, msg='Kanban color deleted successfully')


class KanbanTagsView(generics.ListCreateAPIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanTagSerializer
    queryset = KanbanTag.objects.all()


class KanbanTagDetail(generics.RetrieveUpdateDestroyAPIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanTagSerializer
    queryset = KanbanTag.objects.all()


class KanbanShareLinkList(generics.ListCreateAPIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanShareLinkSerializer
    queryset = KanbanShareLink.objects.all()

    def get_queryset(self):
        qs = super(KanbanShareLinkList, self).get_queryset().filter(
            project__owner_id=self.request.user.username)
        project = self.kwargs.get('kanban_project_id')
        if project:
            return qs.filter(project=project)
        return qs


class KanbanShareLinkDetail(generics.RetrieveUpdateDestroyAPIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, ShareLinkPermission)
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanShareLinkSerializer
    queryset = KanbanShareLink.objects.all()


class KanbanShareLinkView(generics.RetrieveUpdateDestroyAPIView):
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanProjectSerializer
    queryset = KanbanProject.objects.all()

    def get(self, request, token):
        link = get_object_or_404(KanbanShareLink, token=token)
        if link.expire_date and link.expire_date < now():
            return api_error(status.HTTP_403_FORBIDDEN, _('Link expired'))
        # no audit for authenticated user
        if not request.user.is_authenticated():
            if request.session.get('anonymous_email'):
                request.user.username = request.session.get('anonymous_email')
            elif is_pro_version() and settings.ENABLE_SHARE_LINK_AUDIT:
                # check for e-mail verification code
                code = request.POST.get('code', '')
                if code:
                    email = request.POST.get('email', '')
                    cache_key = normalize_cache_key(email, 'share_link_audit_')
                    if code == cache.get(cache_key):
                        # code is correct, add this email to session so that he
                        # will not be asked again during this session, and
                        # clear this code.
                        request.session['anonymous_email'] = email
                        # request.session['token'] = token
                        request.user.username = request.session.get(
                            'anonymous_email')
                        cache.delete(cache_key)
                    else:
                        return api_error(status.HTTP_400_BAD_REQUEST,
                                         _('Invalid token, please try again.'))
                else:
                    resp = {'token': token}
                    resp['share_link_audit'] = (
                        True if settings.ENABLE_SHARE_LINK_AUDIT else False)
                    return api_response(data=resp)
            # check password
            if link.password and not has_valid_password(
                    request, link.project.pk):
                password = request.POST.get('password', None)
                if not password:
                    return api_response(
                        data={
                            'password_protected': True,
                            'share_link_audit': False,
                        },
                        msg=_('Password is required.'))
                if not check_password(password, link.password):
                    return api_response(
                        data={
                            'password_protected': True,
                            'share_link_audit': False,
                        },
                        msg=_('Incorrect password'))
                set_valid_password(request, link.project.pk)
        result = KanbanProjectSerializer(
            link.project, context={
                "request": request
            }).data
        result["expire_date"] = link.expire_date
        request.session['token'] = token
        return api_response(
            code=200, data=result, msg='Get kanban project successfully')

    def post(self, request, token):
        return self.get(request, token)


class SubscriptionList(generics.ListCreateAPIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanSubscriptionSerializer

    def get_queryset(self):
        return KanbanSubscription.objects.filter(
            user_id=self.request.user.username)


class SubscriptionDetail(generics.RetrieveUpdateDestroyAPIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, SubscriptionPermission)
    throttle_classes = (UserRateThrottle, )
    serializer_class = KanbanSubscriptionSerializer
    queryset = KanbanSubscription.objects.all()
