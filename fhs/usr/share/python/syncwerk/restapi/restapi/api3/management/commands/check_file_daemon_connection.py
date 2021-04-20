import logging
import threading

from django.core.management.base import BaseCommand

from restapi.api3.syncwevent.syncwevent_async_client import startEventListening

class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        startEventListening(check_connection_only=True)