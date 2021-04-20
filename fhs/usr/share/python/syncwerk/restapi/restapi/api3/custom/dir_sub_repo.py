import logging
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from django.utils.translation import ugettext as _

from restapi.api3.base import APIView
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

from restapi.utils import is_org_context
from restapi.views import check_folder_permission

from pyrpcsyncwerk import RpcsyncwerkError
import synserv
from synserv import get_repo, syncwerk_api

logger = logging.getLogger(__name__)

class DirSubRepoView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)
    swagger_schema = None
    
    def get(self, request, repo_id, format=None):
        """ Create sub-repo for folder

        Permission checking:
        1. user with `r` or `rw` permission.
        2. password correct for encrypted repo.
        """

        # argument check
        path = request.GET.get('p', None)
        if not path:
            error_msg = 'p invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        name = request.GET.get('name', None)
        if not name:
            error_msg = 'name invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # recourse check
        repo = get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if not check_folder_permission(request, repo_id, path) or \
                not request.user.permissions.can_add_repo():
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        username = request.user.username
        password = request.GET.get('password', '')
        if repo.encrypted:
            # check password for encrypted repo
            if not password:
                error_msg = 'password invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
            else:
                try:
                    syncwerk_api.set_passwd(repo_id, username, password)
                except RpcsyncwerkError as e:
                    if e.msg == 'Bad arguments':
                        error_msg = 'Bad arguments'
                        return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
                    elif e.msg == 'Incorrect password':
                        error_msg = _(u'Wrong password')
                        return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
                    elif e.msg == 'Internal server error':
                        error_msg = _(u'Internal server error')
                        return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)
                    else:
                        error_msg = _(u'Decrypt library error')
                        return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            # create sub-lib for encrypted repo
            try:
                if is_org_context(request):
                    org_id = request.user.org.org_id
                    sub_repo_id = syncwerk_api.create_org_virtual_repo(
                            org_id, repo_id, path, name, name, username, password)
                else:
                    sub_repo_id = syncwerk_api.create_virtual_repo(
                            repo_id, path, name, name, username, password)
            except RpcsyncwerkError as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)
        else:
            # create sub-lib for common repo
            try:
                if is_org_context(request):
                    org_id = request.user.org.org_id
                    sub_repo_id = syncwerk_api.create_org_virtual_repo(
                            org_id, repo_id, path, name, name, username)
                else:
                    sub_repo_id = syncwerk_api.create_virtual_repo(
                            repo_id, path, name, name, username)
            except RpcsyncwerkError as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # return Response({'sub_repo_id': sub_repo_id})
        resp = {'sub_repo_id': sub_repo_id}
        return api_response(status.HTTP_200_OK, '', resp)