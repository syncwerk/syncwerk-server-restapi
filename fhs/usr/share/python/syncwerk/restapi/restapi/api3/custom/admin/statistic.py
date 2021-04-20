import logging
import json
import os
import datetime

from django.utils.translation import ugettext as _

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.views import APIView

from restapi.base.sudo_mode import sudo_mode_check, update_sudo_mode_ts
from restapi.auth.forms import AuthenticationForm

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response
from restapi.api3.models import MonthlyUserTraffic

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class TrafficStatistic(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get traffic statistic',
        operation_description='''Get traffic statistic by month''',
        tags=['admin-statistic'],
        responses={
            200: openapi.Response(
                description='Admin statistic recieve',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "month": "201903",
                            "traffic_data": [
                                {
                                    "user_email": "email1@grr.la",
                                    "sync_upload": 209715200,
                                    "sync_donwload": 1073741824,
                                    "web_upload": 100000,
                                    "web_download": 10737418242,
                                    "share_link_upload": 10737467,
                                    "share_link_download": 10000,
                                },
                                {
                                    "user_email": "email2@grr.la",
                                    "sync_upload": 209715200,
                                    "sync_donwload": 1073741824,
                                    "web_upload": 100000,
                                    "web_download": 10737418242,
                                    "share_link_upload": 10737467,
                                    "share_link_download": 10000,
                                },
                                {
                                    "user_email": "email3@grr.la",
                                    "sync_upload": 209715200,
                                    "sync_donwload": 1073741824,
                                    "web_upload": 100000,
                                    "web_download": 10737418242,
                                    "share_link_upload": 10737467,
                                    "share_link_download": 10000,
                                },
                                {
                                    "user_email": "email4@grr.la",
                                    "sync_upload": 209715200,
                                    "sync_donwload": 1073741824,
                                    "web_upload": 100000,
                                    "web_download": 10737418242,
                                    "share_link_upload": 10737467,
                                    "share_link_download": 10000,
                                },
                                {
                                    "user_email": "email5@grr.la",
                                    "sync_upload": 209715200,
                                    "sync_donwload": 1073741824,
                                    "web_upload": 100000,
                                    "web_download": 10737418242,
                                    "share_link_upload": 10737467,
                                    "share_link_download": 10000,
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
        month_from_request = request.GET.get('month', None)
        if month_from_request is None:
            report_month = datetime.date.today().strftime('%Y-%m-01')
        else:
            try:
                python_date_obj = datetime.datetime.strptime(month_from_request, '%Y%m')
                report_month = python_date_obj.strftime('%Y-%m-01')
            except Exception as e:
                return api_error(400, msg=_('Invalid date format'))
        current_month_traffic_data = MonthlyUserTraffic.objects.filter(month=report_month)
        response_data = {
            "month": report_month,
            "traffic_data": []
        }
        for data in current_month_traffic_data:
            response_data["traffic_data"].append({
                "user_email": data.user,
                "sync_upload": data.sync_file_upload,
                "sync_donwload": data.sync_file_download,
                "web_upload": data.web_file_upload,
                "web_download": data.web_file_download,
                "share_link_upload": data.link_file_upload,
                "share_link_download": data.link_file_download
            })
            pass  
        return api_response(code=200, data=response_data)
        
