# Copyright (c) 2012-2016 Seafile Ltd.
import django.dispatch

# Use org_id = -1 if it's not an org repo
repo_created = django.dispatch.Signal(providing_args=["org_id", "creator", "repo_id", "repo_name", "library_template"])
repo_deleted = django.dispatch.Signal(providing_args=["org_id", "usernames", "repo_owner", "repo_id", "repo_name"])
clean_up_repo_trash = django.dispatch.Signal(providing_args=["org_id", "operator", "repo_id", "repo_name", "days"])
upload_file_successful = django.dispatch.Signal(providing_args=["repo_id", "file_path", "owner"])
comment_file_successful = django.dispatch.Signal(providing_args=["repo", "file_path", "comment", "author", "notify_users"])
tenant_deleted = django.dispatch.Signal(providing_args=["inst_name"])
# For handle audit log
file_access_signal = django.dispatch.Signal(providing_args=['request', 'repo','path'])
perm_audit_signal = django.dispatch.Signal(providing_args=["request","etype", "to", "recipient_type", "repo", "path", "perm"]) 
share_upload_link_signal = django.dispatch.Signal(providing_args=["request","action_type", "repo", "path", "perm"])
send_email_signal =  django.dispatch.Signal(providing_args=["request","recipient"])
repo_update_commit_signal = django.dispatch.Signal(providing_args=["commit", "commit_differ"])
repo_update_signal = django.dispatch.Signal(providing_args=["request", "action_type", "repo_id", "repo_name"])
