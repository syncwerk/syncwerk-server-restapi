import logging
import json
import os
import datetime

from synserv import syncwerk_api, get_repo
from pyrpcsyncwerk import RpcsyncwerkError

from django.utils.translation import ugettext as _

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.views import APIView

from restapi.base.sudo_mode import sudo_mode_check, update_sudo_mode_ts
from restapi.auth.forms import AuthenticationForm
from restapi.share.models import FileShare

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

from restapi.api3.models import VirusScanningInfectedFile

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class VirusFiles(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get list virus file',
        operation_description='''Get list files infected by virus''',
        tags=['admin-virus'],
        responses={
            200: openapi.Response(
                description='Virus infected list file recieved',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "total_number_of_files": 2,
                            "infected_files": [
                                {
                                    "id": 1,
                                    "repo_id": "d1b73ee3-a236-4868-b7d2-0279e401195a",
                                    "repo_name": "Re-contextualized",
                                    "infected_file_path": "/virus3",
                                    "is_handled": True,
                                    "is_false_positive": False,
                                    "repo_owner": "nfriedlos0@opensource.org",
                                    "commit_id": "7d4f2392816352e51e13ccfb49b49d97692f88ac",
                                    "detected_at": "2019-05-06T03:10:59.477193"
                                },
                                {
                                    "id": 2,
                                    "repo_id": "f342a42f-892c-49a1-891f-028061dffe04",
                                    "repo_name": "Cross-group",
                                    "infected_file_path": "/path/virus2",
                                    "is_handled": False,
                                    "is_false_positive": True,
                                    "repo_owner": "astollmeyer1@tinypic.com",
                                    "commit_id": "9cf7917ec196f47bba3e0ea098dcf20d999bcec7",
                                    "detected_at": "2019-05-06T03:10:50.477193"
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
        # TODO: Real process.
        response_data = {
            "total_number_of_files": 0,
            "infected_files": []
        }
        infected_files = VirusScanningInfectedFile.objects.all().order_by('-detected_at')
        response_data['total_number_of_files'] = len(infected_files)
        for infected_file in infected_files:
            repo_details = get_repo(infected_file.repo_id)
            if not repo_details:
                response_data['total_number_of_files'] = response_data['total_number_of_files'] - 1
                continue
            repo_owner = syncwerk_api.get_repo_owner(infected_file.repo_id)
            file_obj = {
                "id": infected_file.id,
                "repo_id": infected_file.repo_id,
                "infected_file_path": infected_file.infected_file_path,
                "is_handled": infected_file.is_handled,
                "is_false_positive": infected_file.is_false_positive,
                "repo_name": repo_details.name,
                "repo_owner": repo_owner,
                "commit_id": infected_file.commit_id,
                "detected_at": infected_file.detected_at,
            }
            response_data['infected_files'].append(file_obj)

        return api_response(code=200, data=response_data)
        
class VirusFile(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Mark file as false positive',
        operation_description='''Mark file as false positive''',
        tags=['admin-virus'],
        manual_parameters=[
            openapi.Parameter(
                name='record_id',
                in_="path",
                type='string',
                description='id of the virus scanning records',
            ),
        ],
        responses={
            200: openapi.Response(
                description='File marked as false positive successfully',
                examples={
                    'application/json': {
                        "message": "File marked as false positive.",
                        "data": None
                    }
                },
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
                description='File / Folder / Scanning record not found / moved / renamed / already handled.',
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
    def put(self, request, record_id):
        try:
            infected_file_obj = VirusScanningInfectedFile.objects.get(id=record_id, is_handled=False)
        except VirusScanningInfectedFile.DoesNotExist as e:
            return api_response(code=404, msg=_("Virus scanning record not found or already handled."))
        # resource check
        repo = get_repo(infected_file_obj.repo_id)
        if not repo:
            infected_file_obj.is_handled = True
            infected_file_obj.save()
            return api_response(code=404, msg=_("Folder was deleted."))

        file_id = syncwerk_api.get_file_id_by_path(infected_file_obj.repo_id, infected_file_obj.infected_file_path)
        if not file_id:
            infected_file_obj.is_handled = True
            infected_file_obj.save()
            return api_response(code=404, msg=_("File was moved, renamed or deleted."))

        infected_file_obj.is_handled = True
        infected_file_obj.is_false_positive = True
        infected_file_obj.save()
        return api_response(code=200, msg=_("File marked as false positive."))
    
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Remove infected files',
        operation_description='''Remove virus infected files in the system''',
        tags=['admin-virus'],
        manual_parameters=[
            openapi.Parameter(
                name='record_id',
                in_="path",
                type='string',
                description='id of the virus scanning records',
            ),
        ],
        responses={
            200: openapi.Response(
                description='File handled successfully',
                examples={
                    'application/json': {
                        "message": "Remove infected file successfully.",
                        "data": None
                    }
                },
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
                description='Tenant not found',
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
    def delete(self, request, record_id):
        try:
            infected_file_obj = VirusScanningInfectedFile.objects.get(id=record_id)
        except VirusScanningInfectedFile.DoesNotExist as e:
            return api_response(code=404, msg=_("Virus scanning record not found."))
        # resource check
        repo = get_repo(infected_file_obj.repo_id)
        if not repo:
            infected_file_obj.is_handled = True
            infected_file_obj.save()
            return api_response(code=200, msg=_("Remove infected file successfully."))

        file_id = syncwerk_api.get_file_id_by_path(infected_file_obj.repo_id, infected_file_obj.infected_file_path)
        if not file_id:
            infected_file_obj.is_handled = True
            infected_file_obj.save()
            return api_response(code=200, msg=_("Remove infected file successfully."))

        # delete file
        parent_dir = os.path.dirname(infected_file_obj.infected_file_path)
        file_name = os.path.basename(infected_file_obj.infected_file_path)
        try:
            syncwerk_api.del_file(infected_file_obj.repo_id, parent_dir,
                                 file_name, request.user.username)
            try:
                # remove file share link
                fileshare = FileShare.objects.get(repo_id=infected_file_obj.repo_id,path=infected_file_obj.infected_file_path)
                if fileshare:
                    fileshare.delete()
            except FileShare.DoesNotExist as e:
                pass
        except RpcsyncwerkError as e:
            return api_response(code=500, msg=_("Failed to remove infected file."))
        infected_file_obj.is_handled = True
        infected_file_obj.save()
        return api_response(code=200, msg=_("Remove infected file successfully."))