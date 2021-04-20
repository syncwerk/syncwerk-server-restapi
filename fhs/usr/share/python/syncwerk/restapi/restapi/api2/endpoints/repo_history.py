# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from restapi.api2.throttling import UserRateThrottle
from restapi.api2.authentication import TokenAuthentication
from restapi.api2.utils import api_error
from restapi.profile.models import Profile
from restapi.base.templatetags.restapi_tags import email2nickname
from restapi.options.models import UserOptions, CryptoOptionNotSetError
from restapi.utils.timeutils import timestamp_to_isoformat_timestr
from restapi.utils import new_merge_with_no_conflict
from restapi.views import check_folder_permission

from synserv import syncwerk_api

logger = logging.getLogger(__name__)

class RepoHistory(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def get_item_info(self, commit):
        email = commit.creator_name
        item_info = {
            "name": email2nickname(email),
            "contact_email": Profile.objects.get_contact_email_by_user(email),
            'email': email,
            'time': timestamp_to_isoformat_timestr(commit.ctime),
            'description': commit.desc,
            'commit_id': commit.id,
        }

        return item_info

    def get(self, request, repo_id, format=None):
        """ Return history of library

        Permission checking:
        1. all authenticated user can perform this action.
        """

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if check_folder_permission(request, repo_id, '/') is None:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        username = request.user.username
        try:
            server_crypto = UserOptions.objects.is_server_crypto(username)
        except CryptoOptionNotSetError:
            # Assume server_crypto is ``False`` if this option is not set.
            server_crypto = False

        password_set = False
        if repo.encrypted and \
                (repo.enc_version == 1 or (repo.enc_version == 2 and server_crypto)):
            try:
                ret = syncwerk_api.is_password_set(repo_id, username)
                if ret == 1:
                    password_set = True
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            if not password_set:
                error_msg = 'Library is encrypted, but password is not set in server.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        try:
            page = int(request.GET.get('page', '1'))
            per_page = int(request.GET.get('per_page', '100'))
        except ValueError:
            page = 1
            per_page = 100

        if page <= 0:
            error_msg = 'page invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if per_page <= 0:
            error_msg = 'per_page invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        start = (page - 1) * per_page
        limit = per_page + 1

        try:
            all_commits = syncwerk_api.get_commit_list(repo_id, start, limit)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        items = []
        commits = all_commits[:per_page]
        for commit in commits:
            if new_merge_with_no_conflict(commit):
                continue

            item_info = self.get_item_info(commit)
            items.append(item_info)

        result = {
            'data': items,
            'more': True if len(all_commits) == per_page + 1 else False
        }

        return Response(result)
