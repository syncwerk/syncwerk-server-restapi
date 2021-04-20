import json
from datetime import datetime

import synserv
from constance import config
from django.http.cookie import SimpleCookie
from django.test import TestCase

from restapi.api3.models import KanbanProject, TokenV2
from restapi.base.accounts import User
from restapi.constants import DEFAULT_ADMIN
from restapi.profile.models import Profile
from restapi.role_permissions.models import AdminRole

TEST_DATE = datetime(2020, 2, 20)


def User_objects_get_mock(email=None, id=None):
    """
    Mock for calls to User.objects.get()
    since CCNET server won't be available during testing.
    """
    if not email and not id:
        raise User.DoesNotExist("User matching query does not exits.")
    user = User(email)
    user.id = 1
    user.is_staff = True
    user.is_active = True
    if user.is_staff:
        try:
            role_obj = AdminRole.objects.get_admin_role(email)
            admin_role = role_obj.role
        except AdminRole.DoesNotExist:
            admin_role = DEFAULT_ADMIN
        user.admin_role = admin_role
    else:
        user.admin_role = ""
    return user


def get_personal_groups_by_user(email):
    return []


class KanbanTestCase(TestCase):
    """
    Tests for restapi.api3.endpoints.kanban
    """
    def setUp(self):
        # display long differences on failures
        self.maxDiff = 4096
        # simulate authentication
        TokenV2.objects.create(key="test", user="admin")
        Profile.objects.create(login_id="admin", user="admin")
        self.client.cookies = SimpleCookie({"token": "test"})
        # TODO: replace with proper mocking library after upgrade to Py3
        User.objects.get = User_objects_get_mock
        synserv.get_personal_groups_by_user = get_personal_groups_by_user

    def test_get_kanban_projects(self):
        """
        Test GET /api3/kanban/projects/
        """
        # create test objects
        project = KanbanProject.objects.create(project_name="test",
                                               owner_id="admin")
        KanbanProject.objects.update(created_at=TEST_DATE,
                                     updated_at=TEST_DATE)
        response = self.client.get("/api3/kanban/projects/")
        self.assertJSONEqual(
            response.content,
            {
                u"message": u"Get list of kanban projects successfully",
                u"data": {
                    u"kanban_projects": [{
                        u"id": project.id,
                        u"project_name": u"test",
                        u"created_at": u"2020-02-20T00:00:00",
                        u"updated_at": u"2020-02-20T00:00:00",
                        u"writable": True,
                        u"members": [],
                        u"owner": {
                            u"login_id": u"admin",
                            u"avatar_size": 80,
                            u"name": u"admin",
                            u"nick_name": None,
                            u"is_default_avatar": True,
                            u"avatar_url":
                            config.SERVICE_URL + "/media/avatars/default.png",
                            u"email": u"admin",
                        },
                        "image": None,
                    }]
                },
            },
        )

    def test_create_task(self):
        """
        Test POST /api3/kanban/tasks/<id>/
        """
        board = KanbanProject.objects.create().kanbanboard_set.create()
        response = self.client.post(
            "/api3/kanban/task/",
            {
                "tags": "",
                "title": "task-1",
                "color": "#00ff00",
                "kanban_board": board.id,
                "due_date": TEST_DATE.isoformat(),
            },
        )
        self.assertJSONEqual(
            response.content,
            {
                u"data": {
                    u"assignee": {
                        u"avatar_size": 80,
                        u"avatar_url":
                        config.SERVICE_URL + "/media/avatars/default.png",
                        u"email": u"",
                        u"is_default_avatar": True,
                        u"login_id": u"",
                        u"name": u"",
                        u"nick_name": None,
                    },
                    u"color": [{
                        u"color": u"#00ff00"
                    }],
                    u"completed": False,
                    u"description": u"",
                    u"due_date": u"2020-02-20T00:00:00",
                    u"id": board.kanbantask_set.get().id,
                    u"kanban_board": board.id,
                    u"num_attachments": 0,
                    u"order": 0,
                    u"tags": [],
                    u"title": u"task-1",
                },
                u"message": u"Kanban task created successfully",
            },
        )

    def test_update_task(self):
        """
        Test PUT /api3/kanban/tasks/<id>/
        """
        task = (KanbanProject.objects.create(
            owner_id="admin").kanbanboard_set.create().kanbantask_set.create(
                due_date=TEST_DATE, completed=False))
        response = self.client.put(
            "/api3/kanban/task/%i/" % task.id,
            data=json.dumps({"title": "task-1"}),
            content_type="application/json",
        )
        self.assertJSONEqual(
            response.content,
            {
                u"data": {
                    u"assignee": {
                        u"avatar_size": 80,
                        u"avatar_url":
                        config.SERVICE_URL + u"/media/avatars/default.png",
                        u"email": u"",
                        u"is_default_avatar": True,
                        u"login_id": u"",
                        u"name": u"",
                        u"nick_name": None,
                    },
                    u"color": [],
                    u"completed": False,
                    u"description": u"",
                    u"due_date": u"2020-02-20T00:00:00",
                    u"id": task.id,
                    u"kanban_board": task.kanban_board.id,
                    u"num_attachments": 0,
                    u"order": 0,
                    u"tags": [],
                    u"title": u"task-1",
                },
                u"message": u"Kanban task updated successfully",
            },
        )

    def test_create_subtask(self):
        """
        Test POST /api3/kanban/subtasks/<id>/
        """
        task = (KanbanProject.objects.create().kanbanboard_set.create().
                kanbantask_set.create(due_date=TEST_DATE, completed=False))
        response = self.client.post("/api3/kanban/subtasks/%i/" % task.id,
                                    {"title": "subtask-1"})
        self.assertJSONEqual(
            response.content,
            {
                u"completed": False,
                u"id": 1,
                u"kanban_task": None,
                u"title": u"subtask-1",
            },
        )

    def test_create_comment(self):
        """
        Test POST /api3/kanban/comment/
        """
        task = (KanbanProject.objects.create(
            owner_id="admin").kanbanboard_set.create().kanbantask_set.create(
                due_date=TEST_DATE, completed=False))
        response = self.client.post(
            "/api3/kanban/comment/",
            {
                "kanban_task_id": task.id,
                "comment": "comment text"
            },
        )
        self.assertJSONEqual(
            response.content,
            {
                u"data": {
                    u"id": 1
                },
                u"message": u"Kanban kanban_comment created successfully",
            },
        )

    def test_create_subscription(self):
        """
        Test POST /api3/kanban/subscriptions/
        """
        task = (KanbanProject.objects.create(
            owner_id="admin").kanbanboard_set.create().kanbantask_set.create(
                due_date=TEST_DATE, completed=False))
        response = self.client.post("/api3/kanban/subscriptions/",
                                    {"task": task.id})
        self.assertJSONEqual(response.content, {
            u"id": 1,
            u"task": task.id,
            u"user_id": u"admin"
        })
