# Copyright (c) 2012-2016 Seafile Ltd.
import os
import logging

from django.template import Context, loader
from post_office import mail, connections
from post_office.models import PRIORITY
from constance import config

from restapi.utils import get_site_scheme_and_netloc, get_site_name
from restapi.settings import MEDIA_URL, LOGO_PATH, \
        MEDIA_ROOT, CUSTOM_LOGO_PATH
from restapi.signals import send_email_signal

MAIL_PRIORITY = PRIORITY        # 'low medium high now'

logger = logging.getLogger(__name__)

def send_html_email_with_dj_template(recipients, subject, dj_template,
                                     context={}, sender=None, template=None,
                                     message='', headers=None,
                                     priority=None, backend='', request = None):
    """

    Arguments:
    - `recipients`:
    - `subject`:
    - `sender`:
    - `template`:
    - `context`:

    """

    # get logo path
    logo_path = LOGO_PATH
    custom_logo_file = os.path.join(MEDIA_ROOT, CUSTOM_LOGO_PATH)
    if os.path.exists(custom_logo_file):
        logo_path = CUSTOM_LOGO_PATH

    base_context = {
        'url_base': get_site_scheme_and_netloc(),
        'site_name': get_site_name(),
        'media_url': MEDIA_URL,
        'logo_path': logo_path,
    }
    context.update(base_context)
    t = loader.get_template(dj_template)
    html_message = t.render(context)

    logger.info('send mail can run here')

    # Auditlog Email
    # sender = NULL 
    send_email_signal.send(sender=None, request=request, recipient=recipients)

    mail.send(recipients, sender=sender, template=template, context=context,
              subject=subject, message=message,
              html_message=html_message, headers=headers, priority=priority,
              backend=backend)

    # try:
    #     connections._connections.connections['default'].close()
    #     connections._connections.connections['default'].open()
    # except AttributeError:
    #     pass

    # mail.send(recipients, sender=sender, template=template, context=context,
    #           subject=subject, message=message,
    #           html_message=html_message, headers=headers, priority=priority,
    #           backend=backend)
    # try:
    #     connections._connections.connections['default'].close()
    # except AttributeError:
    #     pass
