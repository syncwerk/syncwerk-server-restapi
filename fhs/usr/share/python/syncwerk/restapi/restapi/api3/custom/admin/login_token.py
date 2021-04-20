from rest_framework.authentication import SessionAuthentication

from rest_framework.views import APIView

from restapi.api3.utils import api_error, api_response, get_token_v1
from restapi.api3.authentication import TokenAuthentication
from rest_framework.permissions import IsAdminUser
from restapi.api3.models import Token, TokenV2

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class LoginToken(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get user login tokens',
        operation_description='Get list of current login token of any user as super admin',
        tags=['admin'],
        manual_parameters=[
            openapi.Parameter(
                name='user_email',
                in_="path",
                type='string',
                description='User email for retrieve token',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Retrieve user login tokens successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "type": "webapp",
                                "ctime": "2019-02-15T04:00:33.508308",
                                "key": "b0334fcdc41a512fc5cf094c28d07690e5cb0810"
                            },
                            {
                                "last_accessed": "2019-02-11T02:54:53",
                                "device_name": "Nexus 5",
                                "platform_version": "6.0.1",
                                "platform": "android",
                                "user": "admin@alpha.syncwerk.com",
                                "key": "f6afe84b11820433c506fbaedb1b1bc35a60f313",
                                "wiped_at": None,
                                "client_version": "2.2.11",
                                "last_login_ip": "::ffff:192.168.1.250",
                                "device_id": "8974b51d0c0875e2"
                            }
                        ]
                    }
                },
            ),
        }
    )
    def get(self, request, user_email):
        # Get webapp token
        print 'here is the tiokedqwdqwdwqwdqs' 
        token_list = [];
        try:
            token = Token.objects.get(user=user_email)
            print 'here is the tioke'
            print token
            token_list.append({
                'key': token.key,
                'ctime': token.created,
                'type': 'webapp'
            })
        except Exception as e:
            print e
            pass
        

        ## Get logged in device token
        # token_v2 = TokenV2.filter(user=user_email,wiped_at=None)
        token_v2 = TokenV2.objects.get_all_current_login_tokens_by_user(user_email)
        for token in token_v2:
            token_list.append(token.as_dict())
        return api_response(code=200, data=token_list)
        
