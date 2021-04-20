import logging
import os
from constance import config

from django.conf import settings as dj_settings
from django.utils.translation import ugettext as _
import restapi.settings as RestapiSetting

from restapi.settings import MEDIA_ROOT

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.views import APIView
from rest_framework import status

from restapi.utils.two_factor_auth import has_two_factor_auth

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response

from restapi.api3.endpoints.admin.logo import CUSTOM_LOGO_PATH
from restapi.api3.endpoints.admin.favicon import CUSTOM_FAVICON_PATH

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class SystemSettings(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )
    
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get system settings',
        operation_description='''Get system settings''',
        tags=['admin-system'],
        responses={
            200: openapi.Response(
                description='System setting retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "config_dict": {
                                "DISABLE_SYNC_WITH_ANY_FOLDER": False,
                                "ENABLE_USER_CREATE_ORG_REPO": True,
                                "PRIVACY_POLICY_ENABLE": 0,
                                "SUPPORT_PAGE_DE_HTML_FILE_PATH": "5162d1dd-428d-4a6f-9d44-c60ad57abebb/support-de.html",
                                "TERMS_ENABLE": 0,
                                "COOKIE_MODAL_TEXT_DE": "",
                                "TERMS_EN_HTML_FILE_PATH": "",
                                "REGISTER_PAGE_TERM_AND_CONDITION_CHECKBOX_TEXT_EN": "",
                                "SHARE_LINK_TOKEN_LENGTH": 20,
                                "ENABLE_GLOBAL_ADDRESSBOOK": 1,
                                "WELCOME_MESSAGE_DE_HTML_FILE_PATH": "",
                                "COOKIE_MODAL_TEXT_EN": "",
                                "CUSTOM_LOGO_PATH": "custom/mylogo.png",
                                "REPO_PASSWORD_MIN_LENGTH": 8,
                                "WELCOME_MESSAGE_EN_HTML_FILE_PATH": "",
                                "REGISTRATION_SEND_MAIL": False,
                                "SHARE_LINK_PASSWORD_MIN_LENGTH": 8,
                                "LEGAL_NOTICES_EN_HTML_FILE_PATH": "",
                                "ENABLE_BRANDING_CSS": False,
                                "ENABLE_REPO_HISTORY_SETTING": True,
                                "SERVICE_URL": "https://alpha.syncwerk.com",
                                "REGISTER_PAGE_TERM_AND_CONDITION_CHECKBOX_TEXT_DE": "",
                                "PRIVACY_POLICY_DE_HTML_FILE_PATH": "",
                                "SHOW_COOKIE_DISCLAIMER": False,
                                "ACTIVATE_AFTER_REGISTRATION": True,
                                "COOKIE_BANNER_TEXT_DE": "",
                                "TERMS_DE_HTML_FILE_PATH": "",
                                "ENABLE_ENCRYPTED_FOLDER": True,
                                "CUSTOM_CSS": "",
                                "SITE_NAME": "Syncwerk Server",
                                "WELCOME_MESSAGE_ENABLE": False,
                                "LOGIN_REMEMBER_DAYS": 7,
                                "ENABLE_TERMS_AND_CONDITIONS": True,
                                "SITE_TITLE": "Syncwerk Server",
                                "USER_STRONG_PASSWORD_REQUIRED": False,
                                "SUPPORT_PAGE_EN_HTML_FILE_PATH": "5162d1dd-428d-4a6f-9d44-c60ad57abebb/support-en.html",
                                "FORCE_PASSWORD_CHANGE": True,
                                "LEGAL_NOTICES_ENABLE": False,
                                "PRIVACY_POLICY_EN_HTML_FILE_PATH": "",
                                "USER_PASSWORD_MIN_LENGTH": 6,
                                "ENABLE_SHARE_TO_ALL_GROUPS": True,
                                "SUPPORT_PAGE_ENABLE": 1,
                                "ENABLE_USER_CLEAN_TRASH": True,
                                "FREEZE_USER_ON_LOGIN_FAILED": False,
                                "CUSTOM_FAVICON_PATH": "custom/favicon.ico",
                                "COOKIE_BANNER_TEXT_EN": "",
                                "ENABLE_TWO_FACTOR_AUTH": True,
                                "HAS_CUSTOM_FAVICON": False,
                                "COOKIE_DISCLAIMER_TYPE": "banner",
                                "TEXT_PREVIEW_EXT": "ac, am, bat, c, cc, cmake, cpp, cs, css, diff, el, h, html, htm, java, js, json, less, make, org, php, pl, properties, py, rb, scala, script, sh, sql, txt, text, tex, vi, vim, xhtml, xml, log, csv, groovy, rst, patch, go",
                                "ENABLE_SIGNUP": 1,
                                "HAS_CUSTOM_LOGO": False,
                                "LEGAL_NOTICES_DE_HTML_FILE_PATH": "",
                                "USER_PASSWORD_STRENGTH_LEVEL": 3,
                                "FILE_SERVER_ROOT": "https://alpha.syncwerk.com/seafhttp",
                                "LOGIN_ATTEMPT_LIMIT": 3,
                                "ENABLE_WIKI": True,
                                "ALLOW_FOLDERS_IN_BATCH": '0',
                                "BATCH_MAX_FILES_COUNT": 50
                            },
                            "has_two_factor_auth": True
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
    def get(self, request, format=None):
        if not dj_settings.ENABLE_SETTINGS_VIA_WEB:
            return api_error(status.HTTP_404_NOT_FOUND, '')

        config_dict = {}
        for key in dir(config):
            value = getattr(config, key)
            config_dict[key] = value

        config_dict['HAS_CUSTOM_LOGO'] = os.path.isfile(os.path.join(MEDIA_ROOT, CUSTOM_LOGO_PATH))
        config_dict['CUSTOM_LOGO_PATH'] = CUSTOM_LOGO_PATH
        config_dict['HAS_CUSTOM_FAVICON'] = os.path.isfile(os.path.join(MEDIA_ROOT, CUSTOM_FAVICON_PATH))
        config_dict['CUSTOM_FAVICON_PATH'] = CUSTOM_FAVICON_PATH

        if config_dict['BBB_SECRET_KEY'] is not None and config_dict['BBB_SECRET_KEY'] != '':
            config_dict['BBB_SECRET_KEY'] = True
        else:
            config_dict['BBB_SECRET_KEY'] = False
            
        resp = {
            'config_dict': config_dict,
            'has_two_factor_auth': has_two_factor_auth(),
        }
        return api_response(data=resp)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Update system settings',
        operation_description='''Update system settings''',
        tags=['admin-system'],
        manual_parameters=[
            openapi.Parameter(
                name='key',
                in_='formData',
                type='string',
                description='setting key for update',
            ),
            openapi.Parameter(
                name='value',
                in_='formData',
                type='string',
                description='new value to set to the setting',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Update setting successfully.',
                examples={
                    'application/json': {
                        "message": "Update setting successfully",
                        "data": None
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
    def post(self, request, format=None):
        key = request.POST.get('key', None)
        value = request.POST.get('value', None)

        if key not in dir(config) or value is None:
            return api_error(status.HTTP_400_BAD_REQUEST, _(u'Invalid setting'))

        STRING_WEB_SETTINGS = (
            'SERVICE_URL',
            'FILE_SERVER_ROOT',
            'TEXT_PREVIEW_EXT',
            'COOKIE_DISCLAIMER_TYPE',
            'COOKIE_BANNER_TEXT_EN',
            'COOKIE_BANNER_TEXT_DE',
            'COOKIE_MODAL_TEXT_EN',
            'COOKIE_MODAL_TEXT_DE',
            'REGISTER_PAGE_TERM_AND_CONDITION_CHECKBOX_TEXT_EN',
            'REGISTER_PAGE_TERM_AND_CONDITION_CHECKBOX_TEXT_DE',
            'SUPPORT_PAGE_EN_HTML_FILE_PATH',
            'SUPPORT_PAGE_DE_HTML_FILE_PATH',
            'PRIVACY_POLICY_EN_HTML_FILE_PATH',
            'PRIVACY_POLICY_DE_HTML_FILE_PATH',
            'TERMS_EN_HTML_FILE_PATH',
            'TERMS_DE_HTML_FILE_PATH',
            'WELCOME_MESSAGE_EN_HTML_FILE_PATH',
            'WELCOME_MESSAGE_DE_HTML_FILE_PATH',
            'LEGAL_NOTICES_EN_HTML_FILE_PATH',
            'LEGAL_NOTICES_DE_HTML_FILE_PATH',
            'BBB_SERVER_URL',
            'BBB_SECRET_KEY',
        )

        if value.isdigit():
            if key in dir(config):
                value = int(value)
            else:
                return api_error(status.HTTP_400_BAD_REQUEST, _(u'Invalid value'))

            if key == 'USER_PASSWORD_STRENGTH_LEVEL' and value not in (1, 2, 3, 4):
                return api_error(status.HTTP_400_BAD_REQUEST, _(u'Invalid value'))

        else:
            if key not in STRING_WEB_SETTINGS:
                return api_error(status.HTTP_400_BAD_REQUEST, _(u'Invalid value'))

        try:
            setattr(config, key, value)
            return api_response(msg='Update setting successfully.')
        except AttributeError as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, _(u'Internal server error'))


class SystemSettingsByKeys(APIView):
    throttle_classes = (UserRateThrottle,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Get constance settings by keys',
        operation_description='''Get constance settings by keys''',
        tags=['other'],
        manual_parameters=[
            openapi.Parameter(
                name='keys',
                in_='query',
                type='string',
                description='a string contains the setting keys for retrieve seperate by comma',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Constance setting retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "config_dict": {
                                "ENABLE_WIKI": True
                            },
                            "has_two_factor_auth": True
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
        keys = request.GET.get('keys').split(',')
        config_dict = {}
        for key in keys:
            value = getattr(config, key)
            config_dict[key] = value
        resp = {
            'config_dict': config_dict,
            'has_two_factor_auth': has_two_factor_auth(),
        }
        return api_response(data=resp)


class RestapiSettingByKeys(APIView):
    throttle_classes = (UserRateThrottle,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Get restapi settings by keys',
        operation_description='''Get restapi settings by keys''',
        tags=['other'],
        manual_parameters=[
            openapi.Parameter(
                name='keys',
                in_='query',
                type='string',
                description='a string contains the setting keys for retrieve seperate by comma',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Constance setting retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "config_dict": {
                                "ENABLE_WIKI": True
                            },
                            "has_two_factor_auth": True
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
        keys = request.GET.get('keys').split(',')
        config_dict = {}
        for key in keys:
            value = False
            if hasattr(config, key):
                value = getattr(config, key)
                if value == 0 or value == "false" or value == "False":
                    value = False
                elif value == 1 or value == "true" or value == "True":
                    value = True
            elif hasattr(RestapiSetting, key):
                value = getattr(RestapiSetting, key)
            config_dict[key] = value
        resp = {
            'config_dict': config_dict,
            'has_two_factor_auth': has_two_factor_auth(),
        }
        return api_response(data=resp)
