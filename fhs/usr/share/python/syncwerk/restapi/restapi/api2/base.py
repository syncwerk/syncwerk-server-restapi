# Copyright (c) 2012-2016 Seafile Ltd.
#coding: UTF-8

from rest_framework.views import APIView as RestFrameworkAPIView

from restapi.api2.authentication import DeviceRemoteWipedException

class APIView(RestFrameworkAPIView):
    """
    Subclass restframework's APIView to implement some custom feature like
    adding a `X-Syncwerk-Wiped` header if the current client device has been
    marked to be remote wiped by the user.
    """
    def __init__(self, *a, **kw):
        super(APIView, self).__init__(*a, **kw)
        self._syncwerk_exc = None

    def handle_exception(self, exc):
        self._syncwerk_exc = exc
        return super(APIView, self).handle_exception(exc)

    def dispatch(self, *a, **kw):
        response = super(APIView, self).dispatch(*a, **kw)
        if self._syncwerk_exc and isinstance(self._syncwerk_exc, DeviceRemoteWipedException):
            response['X-Syncwerk-Wiped'] = 'true'
        return response
