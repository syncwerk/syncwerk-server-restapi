# Copyright (c) 2012-2016 Seafile Ltd.
from django.apps import AppConfig
from django.core.cache import cache

class BaseConfig(AppConfig):
    name = "restapi.base"
    verbose_name = "restapi base app"

    def ready(self):
        super(BaseConfig, self).ready()

        # check table `base_filecomment` is ok
        from restapi.base.models import FileComment
        try:
            _ = list(FileComment.objects.all()[:1].values('uuid_id'))
        except:
            print '''
Warning: File comment has changed since version 6.3, while table `base_filecomment` is not migrated yet, please consider migrate it according to v6.3.0 release note, otherwise the file comment feature will not work correctly.
            '''
