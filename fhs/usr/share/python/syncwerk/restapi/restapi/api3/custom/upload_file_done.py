import logging

from rest_framework.views import APIView

from django.utils.translation import ugettext as _

from synserv import syncwerk_api

from restapi.share.models import UploadLinkShare
from restapi.signals import upload_file_successful
from restapi.api3.utils import api_error, api_response

logger = logging.getLogger(__name__)

class UploadFileDoneView(APIView):
    def get(self, request):
        """
        This is for sending a message when file upload is done
        """
        filename = request.GET.get('fn', '')
        if not filename:
            return api_error(code=400, msg=_('File name is missing'))
        repo_id = request.GET.get('repo_id', '')
        if not repo_id:
            return api_error(code=400, msg=_('Repo id is missing'))
        path = request.GET.get('p', '')
        if not path:
            return api_error(code=400, msg=_('Path is missing'))
        # a few checkings
        if not syncwerk_api.get_repo(repo_id):
            return api_error(code=400, msg=_('Incorrect repo id'))

        # get upload link share creator
        token = request.GET.get('token', '')
        if not token:
            return api_error(code=400, msg=_('Share token is missing'))

        uls = UploadLinkShare.objects.get_valid_upload_link_by_token(token)
        if uls is None:
            return api_error(code=400, msg=_('Bad upload link'))
        creator = uls.username

        file_path = path.rstrip('/') + '/' + filename
        if syncwerk_api.get_file_id_by_path(repo_id, file_path) is None:
            return api_error(code=400, msg=_('File does not exists'))

        # send singal
        upload_file_successful.send(sender=None,
                                    repo_id=repo_id,
                                    file_path=file_path,
                                    owner=creator)
        return api_response(code=200, msg=_('Notification sent.'))

        # return HttpResponse(json.dumps({'success': True}), content_type=ct)