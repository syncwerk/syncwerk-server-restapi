from django.core.management.base import BaseCommand
from restapi import settings
from restapi.api3.elasticsearch.indexing import start_indexing

class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        start_indexing()

