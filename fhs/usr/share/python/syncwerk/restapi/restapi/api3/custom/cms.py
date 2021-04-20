import os
import json

from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication

from synserv import get_file_id_by_path, syncwerk_api

from constance import config
# SUPPORT_PAGE_ENABLE, SUPPORT_PAGE_EN_HTML_FILE_PATH, SUPPORT_PAGE_DE_HTML_FILE_PATH,\
#     PRIVACY_POLICY_ENABLE, PRIVACY_POLICY_EN_HTML_FILE_PATH,\
#     PRIVACY_POLICY_DE_HTML_FILE_PATH, TERMS_ENABLE,\
#     TERMS_EN_HTML_FILE_PATH, TERMS_DE_HTML_FILE_PATH,\
#     WELCOME_MESSAGE_ENABLE, WELCOME_MESSAGE_EN_HTML_FILE_PATH,\
#     WELCOME_MESSAGE_DE_HTML_FILE_PATH, LEGAL_NOTICES_ENABLE,\
#     LEGAL_NOTICES_EN_HTML_FILE_PATH, LEGAL_NOTICES_DE_HTML_FILE_PATH
from restapi.utils import gen_file_get_url

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response
from restapi.api3.models import CcnetUser
from restapi.api3.utils.file import repo_file_get

from restapi.utils import gen_inner_file_get_url

from django.utils.translation import ugettext as _
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

def get_raw_file_content_from_setting(setting_path):
    if setting_path == '':
        return None
    path_arr = setting_path.split('/')
    repo_id = path_arr.pop(0)
    file_path = '/'.join(path_arr)
    u_filename = os.path.basename(file_path)

    obj_id = get_file_id_by_path(repo_id, '/' + file_path)
    if not obj_id:
        return None
    token = syncwerk_api.get_fileserver_access_token(repo_id,
                                                     obj_id, 'view', '', use_onetime=False)
    if not token:
        # return render_permission_error(request, _(u'Unable to view file'))
        return None
    raw_url = gen_inner_file_get_url(token, u_filename)
    file_content = repo_file_get(raw_url, 'auto')
    return file_content


class CmsContent(APIView):
    """ APIs for getting CMS content
    """
    throttle_classes = (UserRateThrottle,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_description='Get content from a specific CMS page',
        operation_summary='Get specific CMS content.',
        tags=['cms'],
        manual_parameters=[
            openapi.Parameter(
                name='cms_type',
                in_="path",
                type='string',
                description='Type of content to retrive.',
                enum=['support', 'privacy', 'welcome', 'terms', 'legal'],
            ),
        ],
        responses={
            200: openapi.Response(
                description='Retrieve CMS content success',
                examples={
                    'application/json': {  
                        "message":"",
                        "data":{  
                            "file_content":"CMS file content",
                            "lang":"en"
                        }
                    }
                },
                # schema=openapi.Schema(
                #     type='object',
                #     properties={
                #         "hello": openapi.Schema(type='string', description='ghehe'),
                #         "hello2": "things",
                #         "hello3": openapi.Schema(
                #                 type='object',
                #                 properties={
                #                     "ditc1": "another ditch"
                #                 }
                #             )
                #     }
                # ),
            ),
            404: openapi.Response(
                description='CMS content not found',
                examples={
                    'application/json': {
                        'msg': ''
                    }
                },
            )
        }
    )
    def get(self, request, cms_type):
        if cms_type not in ['support', 'privacy', 'welcome', 'terms', 'legal']:
            return api_error(code=404, msg='')

        lang_list = request.META.get('HTTP_ACCEPT_LANGUAGE'),
        lang = lang_list[0]
        response = {
            'file_content': '',
            'lang': lang,
        }

        if cms_type == 'support':
            if not config.SUPPORT_PAGE_ENABLE:
                return api_error(code=404, msg='')
            elif lang == 'en':
                content = get_raw_file_content_from_setting(
                    config.SUPPORT_PAGE_EN_HTML_FILE_PATH)
                if content != None:
                    response['file_content'] = content[1]
            else:
                content = get_raw_file_content_from_setting(
                    config.SUPPORT_PAGE_DE_HTML_FILE_PATH)
                if content != None:
                    response['file_content'] = content[1]

        elif cms_type == 'privacy':
            if not config.PRIVACY_POLICY_ENABLE:
                return api_error(code=404, msg='')
            elif lang == 'en':
                content = get_raw_file_content_from_setting(
                    config.PRIVACY_POLICY_EN_HTML_FILE_PATH)
                if content != None:
                    response['file_content'] = content[1]
            else:
                content = get_raw_file_content_from_setting(
                    config.PRIVACY_POLICY_DE_HTML_FILE_PATH)
                if content != None:
                    response['file_content'] = content[1]

        elif cms_type == 'welcome':
            if not config.WELCOME_MESSAGE_ENABLE:
                return api_error(code=404, msg='')
            elif lang == 'en':
                content = get_raw_file_content_from_setting(
                    config.WELCOME_MESSAGE_EN_HTML_FILE_PATH)
                if content != None:
                    response['file_content'] = content[1]
            else:
                content = get_raw_file_content_from_setting(
                    config.WELCOME_MESSAGE_DE_HTML_FILE_PATH)
                if content != None:
                    response['file_content'] = content[1]

        elif cms_type == 'terms':
            if not config.TERMS_ENABLE:
                return api_error(code=404, msg='')
            elif lang == 'en':
                content = get_raw_file_content_from_setting(
                    config.TERMS_EN_HTML_FILE_PATH)
                if content != None:
                    response['file_content'] = content[1]
            else:
                content = get_raw_file_content_from_setting(
                    config.TERMS_DE_HTML_FILE_PATH)
                if content != None:
                    response['file_content'] = content[1]

        elif cms_type == 'legal':
            if not config.LEGAL_NOTICES_ENABLE:
                return api_error(code=404, msg='')
            elif lang == 'en':
                content = get_raw_file_content_from_setting(
                    config.LEGAL_NOTICES_EN_HTML_FILE_PATH)
                if content != None:
                    response['file_content'] = content[1]
            else:
                content = get_raw_file_content_from_setting(
                    config.LEGAL_NOTICES_DE_HTML_FILE_PATH)
                if content != None:
                    response['file_content'] = content[1]

        return api_response(code=200, data=response)
