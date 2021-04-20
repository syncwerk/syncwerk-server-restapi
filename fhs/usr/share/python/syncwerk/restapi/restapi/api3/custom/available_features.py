from rest_framework.authentication import SessionAuthentication

from rest_framework.views import APIView

from restapi.api3.utils import api_error, api_response
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils.licenseInfo import parse_license_to_json


from restapi.settings import ENABLE_FOLDER_MANAGEMENT, ENABLE_FILE_COMMENTS, ENABLE_GROUPS, \
    ENABLE_WIKI, ENABLE_FILE_PREVIEW, ENABLE_INTERNAL_SHARE, \
    ENABLE_PUBLIC_SHARE, ENABLE_ADMIN_AREA, ENABLE_MULTI_TENANCY, ENABLE_WEBDAV, ENABLE_VIRUS_SCANNING, \
    ENABLE_AUDIT_LOG, BBB_ENABLED, ENABLE_KANBAN

from constance import config

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

def getAvailableFeatures():
    license_info = parse_license_to_json()
    available_features_arr = license_info['available_features']

    isBBBMeetingsEnabled = False

    if hasattr(config, 'BBB_ENABLED'):
        isBBBMeetingsEnabled = True if config.BBB_ENABLED == 1 else False
    else:
        isBBBMeetingsEnabled = True if BBB_ENABLED else False

    isKanbanEnabled = False

    if hasattr(config, 'ENABLE_KANBAN'):
        isKanbanEnabled = True if config.ENABLE_KANBAN == 1 else False
    else:
        isKanbanEnabled = True if ENABLE_KANBAN else False

    if license_info['edition'] == 'freeware':
        return {
            'folder_management': True,
            'file_comments': True,
            'groups': True,
            'wiki': True,
            'file_preview': True,
            'internal_share': True,
            'public_share': True,
            'admin_area': True,
            'multi_tenancy': True,
            'webdav': True,
            'trafficTracking': True,
            'virusScanning': True if ENABLE_VIRUS_SCANNING else False,
            'auditLog': True if ENABLE_AUDIT_LOG else False,
            'bbbMeetings': isBBBMeetingsEnabled,
            'kanban': isKanbanEnabled,
        }
    else:
        return {
            'folder_management': True if 'folders' in available_features_arr and ENABLE_FOLDER_MANAGEMENT else False ,
            'file_comments': True if 'fileComments' in available_features_arr and ENABLE_FILE_COMMENTS else False,
            'groups': True if 'groups' in available_features_arr and ENABLE_GROUPS else False,
            'wiki': True if 'wiki' in available_features_arr and ENABLE_WIKI else False,
            'file_preview': True if 'filePreview' in available_features_arr and ENABLE_FILE_PREVIEW else False,
            'internal_share': True if 'internalShare' in available_features_arr and ENABLE_INTERNAL_SHARE else False,
            'public_share': True if 'publicShare' in available_features_arr and ENABLE_PUBLIC_SHARE else False,
            'admin_area': True if 'adminArea' in available_features_arr and ENABLE_ADMIN_AREA else False,
            'multi_tenancy': True if 'multiTenancy' in available_features_arr and ENABLE_MULTI_TENANCY else False,
            'webdav': True if 'webdav' in available_features_arr and ENABLE_WEBDAV else False,
            'trafficTracking': True if 'trafficTracking' in available_features_arr else False,
            'virusScanning': True if 'virusScanning'in available_features_arr and ENABLE_VIRUS_SCANNING else False,
            'auditLog': True if 'auditLog'in available_features_arr and  ENABLE_AUDIT_LOG else False,
            'bbbMeetings': isBBBMeetingsEnabled,
            'kanban': isKanbanEnabled,
        }

class AvailableFeatures(APIView):
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Get available features',
        operation_description='Get info about which features is available or not',
        tags=['other'],
        responses={
            200: openapi.Response(
                description='Retrieve available features success',
                examples={
                    'application/json': {  
                        "message":"",
                        "data": {
                            'folder_management': True,
                            'file_comments': True,
                            'groups': True,
                            'wiki': True,
                            'file_preview': True,
                            'internal_share': True,
                            'public_share': True,
                            'admin_area': True,
                            'multi_tenancy': True,
                            'webdav': True,
                        }
                    }
                },
            ),
        }
    )
    def get(self, request):

        license_info = parse_license_to_json()
        available_features_arr = license_info['available_features']

        isBBBMeetingsEnabled = False

        if hasattr(config, 'BBB_ENABLED'):
            isBBBMeetingsEnabled = True if config.BBB_ENABLED == 1 else False
        else:
            isBBBMeetingsEnabled = True if BBB_ENABLED else False

        isKanbanEnabled = False

        if hasattr(config, 'ENABLE_KANBAN'):
            isKanbanEnabled = True if config.ENABLE_KANBAN == 1 else False
        else:
            isKanbanEnabled = True if ENABLE_KANBAN else False

        if license_info['edition'] == 'freeware':
            return api_response(code=200, data={
            'folder_management': True,
            'file_comments': True,
            'groups': True,
            'wiki': True,
            'file_preview': True,
            'internal_share': True,
            'public_share': True,
            'admin_area': True,
            'multi_tenancy': True,
            'webdav': True,
            'trafficTracking': True,
            'virusScanning': True if ENABLE_VIRUS_SCANNING else False,
            'auditLog': True if ENABLE_AUDIT_LOG else False,
            'bbbMeetings': isBBBMeetingsEnabled,
            'kanban': isKanbanEnabled,
        })
        else:
            return api_response(code=200, data={
                'folder_management': True if 'folders' in available_features_arr and ENABLE_FOLDER_MANAGEMENT else False ,
                'file_comments': True if 'fileComments' in available_features_arr and ENABLE_FILE_COMMENTS else False,
                'groups': True if 'groups' in available_features_arr and ENABLE_GROUPS else False,
                'wiki': True if 'wiki' in available_features_arr and ENABLE_WIKI else False,
                'file_preview': True if 'filePreview' in available_features_arr and ENABLE_FILE_PREVIEW else False,
                'internal_share': True if 'internalShare' in available_features_arr and ENABLE_INTERNAL_SHARE else False,
                'public_share': True if 'publicShare' in available_features_arr and ENABLE_PUBLIC_SHARE else False,
                'admin_area': True if 'adminArea' in available_features_arr and ENABLE_ADMIN_AREA else False,
                'multi_tenancy': True if 'multiTenancy' in available_features_arr and ENABLE_MULTI_TENANCY else False,
                'webdav': True if 'webdav' in available_features_arr and ENABLE_WEBDAV else False,
                'trafficTracking': True if 'trafficTracking' in available_features_arr else False,
                'virusScanning': True if 'virusScanning'in available_features_arr and ENABLE_VIRUS_SCANNING else False,
                'auditLog': True if 'auditLog'in available_features_arr and  ENABLE_AUDIT_LOG else False,
                'bbbMeetings': isBBBMeetingsEnabled,
                'kanban': isKanbanEnabled,
            })

