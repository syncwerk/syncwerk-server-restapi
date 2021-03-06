# Copyright (c) 2012-2016 Seafile Ltd.
from __future__ import absolute_import, division, print_function, unicode_literals


from restapi.auth.decorators import user_passes_test
from restapi.two_factor.models import user_has_device
from restapi.two_factor.conf import settings

def otp_required(view=None, redirect_field_name='next', login_url=None, if_configured=False):
    """
    Similar to :func:`~django.contrib.auth.decorators.login_required`, but
    requires the user to be :term:`verified`. By default, this redirects users
    to :setting:`OTP_LOGIN_URL`.

    :param if_configured: If ``True``, an authenticated user with no confirmed
        OTP devices will be allowed. Default is ``False``.
    :type if_configured: bool
    """
    if login_url is None:
        login_url = settings.OTP_LOGIN_URL

    def test(user):
        return user.is_verified() or (if_configured and user.is_authenticated() and not user_has_device(user))

    decorator = user_passes_test(test, login_url=login_url, redirect_field_name=redirect_field_name)

    return decorator if (view is None) else decorator(view)
