from rest_framework.views import exception_handler
from rest_framework.exceptions import Throttled
from django.utils.translation import ugettext as _
from django.utils.translation import LANGUAGE_SESSION_KEY


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)
    if isinstance(exc, Throttled): # check that a Throttled exception is raised
        try:
            language = context['request'].COOKIES['lang']
        except Exception as e:
            language = 'de'
        if language == 'en':
            message = 'Request was throttled. Expected available in %d seconds.'%exc.wait
        else:
            message = 'Anfrage wurde gedrosselt. Voraussichtlich in %d Sekunden lieferbar.'%exc.wait
        custom_response_data = { # prepare custom response data
            'detail': message
            
        }
        response.data = custom_response_data # set the custom response data on response object

    return response
    