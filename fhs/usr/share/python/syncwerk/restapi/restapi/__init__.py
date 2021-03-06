# Copyright (c) 2012-2016 Seafile Ltd.
from signals import repo_created, repo_deleted, clean_up_repo_trash
# from handlers import repo_created_cb, repo_deleted_cb, clean_up_repo_trash_cb

# repo_created.connect(repo_created_cb)
# repo_deleted.connect(repo_deleted_cb)
# clean_up_repo_trash.connect(clean_up_repo_trash_cb)

try:
    # ../conf/restapi_settings.py
    from restapi_settings import repo_created_callback
    repo_created.connect(repo_created_callback)
except ImportError:
    pass
