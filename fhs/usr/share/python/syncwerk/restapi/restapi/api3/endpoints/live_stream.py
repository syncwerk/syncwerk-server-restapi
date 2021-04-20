import re
from rest_framework.views import APIView
from restapi.api3.models import MeetingRoom, BBBPrivateSetting
from restapi.api3.utils import api_error, api_response, get_user_common_info, send_html_email
from django.utils.translation import ugettext as _


class LiveStream(APIView):

    def get(self, request, meeting_id=None):
        result = {}

        api_token = request.META.get('HTTP_AUTHORIZATION')

        if meeting_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_id.'))

        try:
            meeting_room = MeetingRoom.objects.get(
                b3_meeting_id=meeting_id,
            )

            meeting_server = BBBPrivateSetting.objects.get(
                id=meeting_room.private_setting_id,
            )

            if meeting_room is None:
                return api_error(code=404, msg=_('BBB Meeting not found.'))
            if meeting_server is None:
                return api_error(code=404, msg=_('BBB Setting not found.'))
            if api_token != meeting_server.live_stream_token:
                return api_error(code=401, msg=_('Not authorized'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('BBB Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))

        meeting_info = {
            "bbb_meeting_id": meeting_room.b3_meeting_id,
            "live_stream_active": meeting_room.live_stream_active
        }

        result = {
            "meeting_room": meeting_info
        }

        # return Response(result)
        return api_response(data=result)

    def post(self, request, meeting_id=None):
        result = {}

        api_token = request.META.get('HTTP_AUTHORIZATION')

        if meeting_id is None :
            return api_error(code=400, msg=_('Please provide the meeting_id.'))

        try:
            meeting_room = MeetingRoom.objects.get(
                b3_meeting_id=meeting_id,
            )

            meeting_server = BBBPrivateSetting.objects.get(
                id=meeting_room.private_setting_id,
            )

            if meeting_room is None:
                return api_error(code=404, msg=_('BBB Meeting not found.'))
            if meeting_server is None:
                return api_error(code=404, msg=_('BBB Setting not found.'))

            if api_token != meeting_server.live_stream_token:
                return api_error(code=401, msg=_('Not authorized'))

            # Get parameters
            live_stream_url = request.POST.get('live_stream_url', None)
            live_stream_meeting_key = request.POST.get('live_stream_meeting_key', None)

            # Save
            meeting_room.live_stream_url = live_stream_url
            meeting_room.live_stream_meeting_key = live_stream_meeting_key
            meeting_room.save()

        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('BBB Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))

        # return Response(result)
        return api_response(data=result)


class LiveStreamMeetingInfo(APIView):

    def get(self, request, meeting_key=None):
        result = {}

        if meeting_key is None:
            return api_error(code=400, msg=_('Please provide the meeting_key.'))

        try:

            meeting_room = MeetingRoom.objects.get(
                live_stream_meeting_key=meeting_key,
            )

            if meeting_room is None:
                return api_error(code=404, msg=_('BBB Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('BBB Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))

        result = {
            "stream_link": meeting_room.live_stream_url,
            "feedback_enabled": meeting_room.live_stream_feedback_active,
        }

        # return Response(result)
        return api_response(data=result)


class LiveStreamMeetingFeedback(APIView):

    def post(self, request, meeting_key=None):
        result = {}

        if meeting_key is None:
            return api_error(code=400, msg=_('Please provide the meeting_key.'))

        form_email = request.POST.get('email', None)
        if not re.match("\\S+@[a-zA-Z0-9\u00E4\u00F6\u00FC\u00C4\u00D6\u00DC\u00df._-]+\\.[a-zA-Z0-9\u00E4\u00F6\u00FC\u00C4\u00D6\u00DC\u00df._-]+", form_email.strip()):
            return api_error(code=400, msg=_('Invalid email. Please check again'))

        try:
            meeting_room = MeetingRoom.objects.get(
                live_stream_meeting_key=meeting_key,
            )

            email = get_user_common_info(meeting_room.owner_id)['email']
            form_username = request.POST.get('username', None)
            form_message = request.POST.get('message', None)

            c = {
                'meeting_name': email,
                'username': form_username,
                'email': form_email,
                'message': form_message,
            }
            send_html_email(u'Feedback from Meeting',
                            'api3/stream_meeting_feedback.html', c, None, [email])

            if meeting_room is None:
                return api_error(code=404, msg=_('BBB Meeting not found.'))
        except MeetingRoom.DoesNotExist:
            return api_error(code=404, msg=_('BBB Meeting not found.'))
        except Exception as e:
            return api_error(code=500, msg=_('Internal server error.'))

        # return Response(result)
        return api_response(
            code=200,
            data=result,
            msg='Feedback submitted successfully')

