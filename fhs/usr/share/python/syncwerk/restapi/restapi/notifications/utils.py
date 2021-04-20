# Copyright (c) 2012-2016 Seafile Ltd.
from django.core.cache import cache

from restapi.notifications.models import Notification
from restapi.notifications.settings import NOTIFICATION_CACHE_TIMEOUT
def refresh_cache():
    """
    Function to be called when change primary notification.
    """
    cache.set('CUR_TOPINFO', Notification.objects.all().filter(primary=1),
              NOTIFICATION_CACHE_TIMEOUT)
    
