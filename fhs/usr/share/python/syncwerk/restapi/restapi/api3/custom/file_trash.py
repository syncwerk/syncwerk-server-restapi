from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response
from restapi.api3.utils.file import view_trash_file

class FileTrash(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    swagger_schema = None
    
    def get(self, request, repo_id, format=None):
        """ 
        ---
        # YAML

        type:
          Authorization:
            required: true
            type: string
          obj_id:
            required: true
            type: string
          commit_id:
            required: true
            type: string
          p:
            required: true
            type: string
          base:
            required: true
            type: string

        parameters:
            - name: Authorization
              required: true
              type: string
              paramType: header
            - name: obj_id
              required: true
              type: string
              paramType: query
            - name: commit_id
              required: true
              type: string
              paramType: query
            - name: p
              required: true
              type: string
              paramType: query
            - name: base
              required: true
              type: string
              paramType: query

        responseMessages:
            - code: 400
              message: BAD_REQUEST
            - code: 401
              message: UNAUTHORIZED
            - code: 403
              message: FORBIDDEN
            - code: 404
              message: NOT_FOUND
            - code: 500
              message: INTERNAL_SERVER_ERROR

        consumes:
            - application/json
        produces:
            - application/json
        """
        return view_trash_file(request, repo_id)
