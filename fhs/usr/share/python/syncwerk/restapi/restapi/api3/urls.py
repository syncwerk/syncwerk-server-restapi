from django.conf.urls import include, url
from django.http import FileResponse
from django.template.loader import render_to_string
from drf_yasg import openapi
from drf_yasg.inspectors import SwaggerAutoSchema
from drf_yasg.views import get_schema_view
from rest_framework import permissions

from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

from . import views
from .custom.accounts import Accounts
from .custom.accounts_registration import (AccountActivationViaEmail,
                                           AccountRegistration)
from .custom.activity_logs import ActivitiesLog, ActivitiesLogCSV
from .custom.admin.email_change_request import (AdminUserEmailChangeRequest,
                                                AdminUserEmailChangeRequests)
from .custom.admin.login_token import LoginToken
from .custom.admin.meeting_rooms import (AdminBBBPrivateSettingEntries,
                                         AdminBBBPrivateSettingEntry,
                                         AdminInitAddMeetingModal,
                                         AdminMeetingRecording,
                                         AdminMeetingRecordings,
                                         AdminMeetingRoomsView,
                                         AdminMeetingRoomView,
                                         AdminMeetingSearchGroupToShare,
                                         AdminShareMeetingRoomPublic,
                                         AdminShareMeetingRoomToGroupEntries,
                                         AdminShareMeetingRoomToGroupEntry,
                                         AdminShareMeetingRoomToUsersEntries,
                                         AdminShareMeetingRoomToUsersEntry,
                                         AdminStartMeetingView,
                                         AdminStopMeetingView)
from .custom.admin.public_share import (AdminDownloadLink, AdminPublicShare,
                                        AdminUploadLink, PublicShares)
from .custom.admin.statistic import TrafficStatistic
from .custom.admin.sudo_mode import SudoMode
from .custom.admin.system_notification import (CurrentNotification,
                                               SystemNotification,
                                               SystemNotifications)
from .custom.admin.tenants import (AdminTenant, AdminTenantAdmins,
                                   AdminTenantBBB, AdminTenants,
                                   AdminTenantUser, AdminTenantUsers)
from .custom.admin.users import (AdminAdmin, AdminAdmins, AdminUser,
                                 AdminUserImport, AdminUsers,
                                 AdminUsersExcelExport, AdminUserSource,
                                 AdminUsersSearch, AdminUsersToggleRoles,
                                 AdminUserToggleStatus)
from .custom.admin.users_info import (AdminUserGroups, AdminUserOwnedLibs,
                                      AdminUserSharedLinkRemovePublicLink,
                                      AdminUserSharedLinkRemoveUploadLink)
from .custom.admin.virus_files import VirusFile, VirusFiles
from .custom.admin_library import AdminLibraries
from .custom.available_features import AvailableFeatures
from .custom.beshared_repos import BeSharedRepos
from .custom.cms import CmsContent
from .custom.default_repo import DefaultRepoView
from .custom.devices import DevicesView
from .custom.dir_restore import DirRestore
from .custom.dir_sub_repo import DirSubRepoView
from .custom.dir_trash import DirTrash
from .custom.dirents import (Dirents, DirentsCopy, DirentsDelete, DirentsMove,
                             UnEncRWRepos)
from .custom.download_file import DownloadFile
from .custom.events import EventsView
from .custom.favicon import Favicon
from .custom.file_edit import FileEditView
from .custom.file_preview import FilePreviewView
from .custom.file_restore import FileRestore
from .custom.file_revision_preview import FileRevisionPreview
from .custom.file_revisions import FileRevisions
from .custom.file_trash import FileTrash
from .custom.group_repo import GroupRepo
from .custom.group_repos import GroupRepos
from .custom.group_search_user import GroupSearchUser
from .custom.lib_dir import LibDirView
from .custom.logo import Logo
from .custom.meeting_rooms import (BBBPrivateSettingEntries,
                                   BBBPrivateSettingEntry,
                                   BBBPrivateSettingList,
                                   EndMeetingCallbackForBBB, MeetingRecording,
                                   MeetingRecordings,
                                   MeetingRoomByShareTokenView,
                                   MeetingRoomsView, MeetingRoomView,
                                   MeetingSearchGroupToShare,
                                   ShareMeetingRoomPublic,
                                   ShareMeetingRoomToGroupEntries,
                                   ShareMeetingRoomToGroupEntry,
                                   ShareMeetingRoomToUsersEntries,
                                   ShareMeetingRoomToUsersEntry,
                                   StartMeetingView, StopMeetingView,
                                   TestBBBConnection,
                                   TestPrivateBBBSettingConnection)
from .custom.multiple_files import OpCopyView, OpDeleteView, OpMoveView
from .custom.profile import ProfileBBBSettingView, ProfileView
from .custom.profile_password import (ConfirmPasswordReset, PasswordChangeView,
                                      PasswordReset)
from .custom.repo_group_folder_perm import RepoGroupFolderPerm
from .custom.repo_history_changes import RepoHistoryChanges
from .custom.repo_history_limit import RepoHistoryLimit
from .custom.repo_history_snapshot import RepoHistorySnapshot
from .custom.repo_password import RepoPassword
from .custom.repo_shared_link import (RepoDownloadSharedLink,
                                      RepoDownloadSharedLinks,
                                      RepoUploadSharedLink,
                                      RepoUploadSharedLinks)
from .custom.repo_thumbnail import ThumbnailView
from .custom.repo_trash import RepoTrash
from .custom.repo_user_folder_perm import RepoUserFolderPerm
from .custom.roles import Roles
from .custom.search import SearchFiles
from .custom.share_link import (BatchSharedDirView, SharedDirFileLinkView,
                                SharedDirLinkView, SharedFileLinkView,
                                SharedUploadLinkView, ShareLinkAuditView)
from .custom.share_search_group import ShareSearchGroup
from .custom.share_search_user import ShareSearchUser
from .custom.shared_dir import SharedDirView
from .custom.starred_files import StarredFileView
from .custom.sys_settings import (RestapiSettingByKeys, SystemSettings,
                                  SystemSettingsByKeys)
from .custom.text_diff import TextDiffView
from .custom.trash_more import TrashMore
from .custom.update_user_avatar import UpdateUserAvatarView
from .custom.upload_file_done import UploadFileDoneView
from .custom.upload_link import UploadLinkSharedView, UploadLinkView
from .custom.user_profile import (UserProfileChangeEmailConfirmView,
                                  UserProfileChangeEmailRequestEntryView,
                                  UserProfileChangeEmailView, UserProfileView)
from .custom.views_auth import LogoutDeviceView
from .custom.wikis import WikiPagesView, WikisView, WikiView
from .endpoints import kanban
from .endpoints import live_stream
from .endpoints.account import Account
from .endpoints.admin.audit_log import (AdminAuditLog, AdminAuditLogCSV,
                                        AdminAuditLogDropdownInfo,
                                        is_audit_log_available)
from .endpoints.admin.default_library import AdminDefaultLibrary
from .endpoints.admin.device_errors import AdminDeviceErrors
from .endpoints.admin.devices import AdminDevices
from .endpoints.admin.favicon import AdminFavicon, AdminFavIconReset
from .endpoints.admin.group_libraries import (AdminGroupLibraries,
                                              AdminGroupLibrary)
from .endpoints.admin.group_members import AdminGroupMember, AdminGroupMembers
from .endpoints.admin.groups import (AdminGroup, AdminGroupBBB, AdminGroups,
                                     AdminGroupsExport)
from .endpoints.admin.libraries import (AdminLibraries, AdminLibrary,
                                        AdminLibraryPassword,
                                        AdminLibraryShares)
from .endpoints.admin.library_dirents import (AdminLibraryDirent,
                                              AdminLibraryDirents)
from .endpoints.admin.license import AdminLicense
from .endpoints.admin.logo import AdminLogo, SetDefaultAdminLogo
from .endpoints.admin.shares import AdminShares
from .endpoints.admin.sysinfo import SysInfo, SysVersion
from .endpoints.admin.system_library import (AdminSystemLibrary,
                                             AdminSystemLibraryUploadLink)
from .endpoints.admin.trash_libraries import (AdminTrashLibraries,
                                              AdminTrashLibrary)
from .endpoints.admin.users_batch import AdminUsersBatch
from .endpoints.batch_download import BatchDownloadView
from .endpoints.be_shared_repo import BeSharedRepo
from .endpoints.copy_move_task import CopyMoveTaskView
from .endpoints.deleted_repos import DeletedRepos
from .endpoints.dir import DirDetailView, DirView
from .endpoints.dir_shared_items import DirSharedItemsEndpoint
from .endpoints.file import FileDetailView, FileView
from .endpoints.file_comment import FileCommentView
from .endpoints.file_comments import FileCommentsView
from .endpoints.file_comments_counts import FileCommentsCounts
from .endpoints.group_discussion import GroupDiscussion
from .endpoints.group_discussions import GroupDiscussions
from .endpoints.group_members import (GroupMember, GroupMembers,
                                      GroupMembersBulk)
from .endpoints.groups import Group, GroupBBB, Groups
from .endpoints.notifications import (NotificationCountView, NotificationsView,
                                      NotificationTopView, NotificationView)
from .endpoints.query_copy_move_progress import QueryCopyMoveProgressView
from .endpoints.query_zip_progress import QueryZipProgressView
from .endpoints.repo_history import RepoHistory
from .endpoints.repo_trash import RepoTrashClean
from .endpoints.search_group import SearchGroup
from .endpoints.search_user import SearchUser
from .endpoints.send_share_link_email import SendShareLinkView
from .endpoints.send_upload_link_email import SendUploadLinkView
from .endpoints.share_link_zip_task import ShareLinkZipTaskView
from .endpoints.share_links import ShareLink, ShareLinks
from .endpoints.shared_folders import SharedFolders
from .endpoints.shared_repos import SharedRepo, SharedRepos
from .endpoints.shares import Shares
from .endpoints.upload_links import UploadLink, UploadLinks
from .endpoints.user_activities import (UserActivitiesExportCSV,
                                        UserActivitiesView)
from .endpoints.zip_task import ZipTaskView
from .elasticsearch.views import SearchView
# from rest_framework_swagger.views import get_swagger_view

# from .custom.swagger import SwaggerSchemaView


def document_url(request):
    file_url = 'syncwerk/docs/apis.json'
    return FileResponse(open(file_url, 'rb'), content_type='application/json')


schema_view = get_schema_view(openapi.Info(
    title="Syncwerk API",
    default_version='v3',
    x_logo={
        "url": "/media/img/syncwerk-logo-160.png",
        "backgroundColor": "#607D8B"
    },
    description="""
# Introduction
v3 api for Syncwerk
      """,
),
                              public=True,
                              permission_classes=(permissions.AllowAny, ),
                              patterns=[
                                  url(r'^api3/', include('restapi.api3.urls')),
                              ])

urlpatterns = [
    ##################################################
    # Documentation
    url(r'^swagger(?P<format>\.json|\.yaml)$',
        schema_view.without_ui(cache_timeout=0),
        name='schema-json'),
    url(r'^swagger/$',
        schema_view.with_ui('swagger', cache_timeout=0),
        name='schema-swagger-ui'),
    url(r'^redoc/$',
        schema_view.with_ui('redoc', cache_timeout=0),
        name='schema-redoc'),
    # url(r'^docs/apis.json$', document_url),
    # url(r'^docs/', SwaggerSchemaView.as_view()),
    url(r'^captcha/', include('captcha.urls')),
    # CMS Content
    url(r'^cms/(?P<cms_type>[0-9A-Za-z]+)/$', CmsContent.as_view()),
    # Account section
    url(r'^ping$', views.Ping.as_view()),
    url(r'^features/$', AvailableFeatures.as_view()),
    # Register
    url(r'^register$', AccountRegistration.as_view()),
    url(r'^active/(?P<activation_key>\w+)$',
        AccountActivationViaEmail.as_view()),
    # Login
    url(r'^login-config$', views.LoginConfiguration.as_view()),
    url(r'^get-captcha$', views.GetCaptcha.as_view()),
    # url(r'^auth-token$', ObtainAuthToken.as_view())
    url(r'^auth-token$', views.OtherObtainAuthToken.as_view()),
    url(r'^third-party-auth-token$',
        views.ObtainThirdPartyAuthToken.as_view()),
    # Get Authentication Status
    url(r'^auth-status$', views.AuthStatus.as_view()),
    # Get login token as super admin
    url(
        ur'^login-token/(?P<user_email>\S+@[a-zA-Z0-9\u00E4\u00F6\u00FC\u00C4\u00D6\u00DC\u00df._-]+\.[a-zA-Z0-9\u00E4\u00F6\u00FC\u00C4\u00D6\u00DC\u00df._-]+)/$',
        LoginToken.as_view()),
    # Logout
    url(r'^logout$', LogoutDeviceView.as_view()),
    # User Information
    # Get user account information
    url(r'^account/info/$', views.AccountInfo.as_view()),
    # Delete account
    url(r'^delete-account/$', views.DeleteAccountView.as_view()),
    # Get/Update current user profile
    url(r'^profile/$', ProfileView.as_view()),
    url(r'^profile/bbb/$', ProfileBBBSettingView.as_view()),
    # Change password
    url(r'^profile/password/$', PasswordChangeView.as_view()),
    # Update profile avatar
    url(r'^profile/avatar/$', UpdateUserAvatarView.as_view()),
    # Get/Set user's default folder
    url(r'^profile/default-repo/$', DefaultRepoView.as_view()),
    # User's email change operations
    url(r'^profile/change-email-request/$', UserProfileChangeEmailView.as_view()),
    url(r'^profile/change-email-request/(?P<request_id>\d+)/$', UserProfileChangeEmailRequestEntryView.as_view()),
    url(r'^profile/confirm-new-email/$', UserProfileChangeEmailConfirmView.as_view()),
    # Get user profile
    url(r'^user/profile/(?P<email>\S+@[a-zA-Z0-9\u00E4\u00F6\u00FC\u00C4\u00D6\u00DC\u00df._-]+\.[a-zA-Z0-9\u00E4\u00F6\u00FC\u00C4\u00D6\u00DC\u00df._-]+)/$', UserProfileView.as_view()),
    # Password reset
    url(r'^password/reset/$', PasswordReset.as_view()),
    # Confirm password reset
    url(r'^password/reset/confirm/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$',
        ConfirmPasswordReset.as_view()),

    # Get space and traffic info
    url(r'^space-traffic/$', views.SpaceTrafficView.as_view()),
    # Search user
    url(r'^search-user/$', SearchUser.as_view()),
    url(r'^search-group/$', SearchGroup.as_view()),
    # Notification
    url(r'^notifications/count/$', NotificationCountView.as_view()),
    url(r'^notifications/top/$', NotificationTopView.as_view()),
    url(r'^notifications/$', NotificationsView.as_view()),
    url(r'^notification/$', NotificationView.as_view()),
    ##################################################
    # Library Section
    url(r'^repos/$', views.Repos.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/$', views.Repo.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9-a-f]{36})/dir/$', DirView.as_view()),
    url(r'^search/(?P<repo_id>[-0-9-a-f]{36})/dir/$', SearchView.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9-a-f]{36})/file/$', FileView.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/dir/detail/$',
        DirDetailView.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9-a-f]{36})/file/detail/$',
        FileDetailView.as_view()),
    # Get all children file in one folder (full)
    url(r'^lib/(?P<repo_id>[-0-9-a-f]{36})/dir/$', LibDirView.as_view()),
    # Check/Create Sub Library
    url(r'^repos/(?P<repo_id>[-0-9-a-f]{36})/dir/sub_repo/$',
        DirSubRepoView.as_view()),
    # Get list public folder
    url(r'^repos/public/$', views.PubRepos.as_view()),
    # Get folder's owner info
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/owner$',
        views.RepoOwner.as_view()),

    # Get history action of one folder
    url(r'^events/$', EventsView.as_view()),
    # Get list connected devices
    url(r'^devices/$', DevicesView.as_view()),

    # Share
    # Create Share Link (Download Link)
    url(r'^share-links/$', ShareLinks.as_view()),
    # Delete share link
    url(r'^share-links/(?P<token>[a-f0-9]+)/$', ShareLink.as_view()),
    # Create Upload Link (Upload Link)
    url(r'^upload-links/$', UploadLinks.as_view()),
    # Delete upload link
    url(r'^upload-links/(?P<token>[a-f0-9]+)/$', UploadLink.as_view()),
    url(r'^upload-file-done/', UploadFileDoneView.as_view()),
    # Send Share Link Email
    url(r'^send-share-link/$', SendShareLinkView.as_view()),
    # Send Upload Link Email
    url(r'^send-upload-link/$', SendUploadLinkView.as_view()),
    # Share a Library to User (Share to user) & Share a Library to Group (Share to group)
    url(r'^repos/(?P<repo_id>[-0-9-a-f]{36})/dir/shared_items/$',
        DirSharedItemsEndpoint.as_view()),
    # Seach user/group to share
    url(r'^repos/(?P<repo_id>[-0-9-a-f]{36})/dir/share_search_user/$',
        ShareSearchUser.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9-a-f]{36})/dir/share_search_group/$',
        ShareSearchGroup.as_view()),
    #
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/download-shared-links/$',
        RepoDownloadSharedLinks.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/download-shared-links/(?P<token>[a-f0-9]+)/$',
        RepoDownloadSharedLink.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/upload-shared-links/$',
        RepoUploadSharedLinks.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/upload-shared-links/(?P<token>[a-f0-9]+)/$',
        RepoUploadSharedLink.as_view()),
    # List Directory in Dir Download Link
    url(r'^d/(?P<token>[a-f0-9]+)/dir/$', SharedDirView.as_view()),
    # Shared Folders
    url(r'^shared-folders/$', SharedFolders.as_view()),
    url(r'^shares/$', Shares.as_view()),
    # Shared Libraries
    url(r'^shared-repos/$', SharedRepos.as_view()),
    url(r'^shared-repos/(?P<repo_id>[-0-9a-f]{36})/$', SharedRepo.as_view()),
    # List Be Shared Libraries
    url(r'^beshared-repos/$', BeSharedRepos.as_view()),
    # Delete Be Shared Library
    url(r'^beshared-repos/(?P<repo_id>[-0-9-a-f]{36})/$',
        BeSharedRepo.as_view()),

    # Get/Set folder history limit days
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/history-limit/$',
        RepoHistoryLimit.as_view()),
    # Fetch folder download info
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/download-info/$',
        views.DownloadRepo.as_view()),
    # Decrypt folder/change folder password
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/password/$',
        RepoPassword.as_view()),

    # Folder Permission
    # User Folder Permission
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/user-folder-perm/$',
        RepoUserFolderPerm.as_view()),
    # Group Folder Permission
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/group-folder-perm/$',
        RepoGroupFolderPerm.as_view()),

    ## History, Trash, Snapshot
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/history/$', RepoHistory.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/history/changes/$',
        RepoHistoryChanges.as_view()),
    # View history snapshot / Restore snapshot
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/history/snapshot/$',
        RepoHistorySnapshot.as_view()),
    # Download file snapshot
    url(r'^repo/(?P<repo_id>[-0-9a-f]{36})/(?P<obj_id>[0-9a-f]{40})/download/$',
        DownloadFile.as_view()),

    # Upload file
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/upload-link/$',
        UploadLinkView.as_view()),

    # Trash
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/trash/$', RepoTrash.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/trash/dir/$', DirTrash.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/trash/file/$',
        FileTrash.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/trash/more/$',
        TrashMore.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/trash/clean/$',
        RepoTrashClean.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9-a-f]{36})/trash/dir/restore/$',
        DirRestore.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9-a-f]{36})/trash/file/restore/$',
        FileRestore.as_view()),

    # Group
    url(r'^groups/$', Groups.as_view()),
    url(r'^groups/(?P<group_id>\d+)/$', Group.as_view()),
    url(r'^groups/(?P<group_id>\d+)/bbb/$', GroupBBB.as_view()),
    url(r'^groups/(?P<group_id>\d+)/members/$', GroupMembers.as_view()),
    url(r'^groups/(?P<group_id>\d+)/members/bulk/$', GroupMembersBulk.as_view()),
    url(
        r'^groups/(?P<group_id>\d+)/members/(?P<email>[^/]+)/$', GroupMember.as_view()),
    url(r'^groups/(?P<group_id>\d+)/discussions/$', GroupDiscussions.as_view()),
    url(r'^groups/(?P<group_id>\d+)/discussions/(?P<discuss_id>\d+)/$',
        GroupDiscussion.as_view()),
    url(r'^groups/(?P<group_id>\d+)/repos/$', GroupRepos.as_view()),
    url(
        r'^groups/(?P<group_id>\d+)/repos/(?P<repo_id>[-0-9a-f]{36})/$', GroupRepo.as_view()),
    url(r'^groups/(?P<group_id>\d+)/search_user/$', GroupSearchUser.as_view()),

    # Multiple Files / Directories
    url(r'^repos/(?P<repo_id>[-0-9-a-f]{36})/fileops/delete/$',
        OpDeleteView.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9-a-f]{36})/fileops/copy/$',
        OpCopyView.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9-a-f]{36})/fileops/move/$',
        OpMoveView.as_view()),

    # Download
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/zip-task/$',
        ZipTaskView.as_view()),
    # Batch Download
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/batch-download/$',
        BatchDownloadView.as_view()),
    url(r'^share-link-zip-task/$', ShareLinkZipTaskView.as_view()),
    url(r'^query-zip-progress/$', QueryZipProgressView.as_view()),

    # Starred Files
    url(r'^starredfiles/', StarredFileView.as_view()),

    # Get Thumbnail Image
    url(r'^repos/(?P<repo_id>[-0-9-a-f]{36})/thumbnail/$',
        ThumbnailView.as_view()),

    # Get User/Group Avatar
    url(
        r'^avatars/user/(?P<user>\S+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/resized/(?P<size>[0-9]+)/$',
        views.UserAvatarView.as_view()),
    url(r'^avatars/group/(?P<group_id>\d+)/resized/(?P<size>[0-9]+)/$',
        views.GroupAvatarView.as_view()),

    # Deleted Repos
    url(r'^deleted-repos/$', DeletedRepos.as_view()),

    # File Preview
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/file/preview/$',
        FilePreviewView.as_view()),
    # File Revisions
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/file/revisions/$',
        FileRevisions.as_view()),
    # File Revision Preview
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/file/revision/preview/$',
        FileRevisionPreview.as_view()),
    # File Comments
    url(r'^repos/(?P<repo_id>[-0-9-a-f]{36})/file/comments/$',
        FileCommentsView.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9-a-f]{36})/file/comments/counts/$',
        FileCommentsCounts.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9-a-f]{36})/file/comments/(?P<pk>\d+)/$',
        FileCommentView.as_view()),
    # File Edit
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/file/edit/$',
        FileEditView.as_view()),
    # File Text Diff
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/file/text_diff/$',
        TextDiffView.as_view()),
    # Get shared file link info
    url(r'^f/(?P<token>[a-f0-9]+)/$', SharedFileLinkView.as_view()),
    # Get shared directory link info
    url(r'^d/(?P<token>[a-f0-9]+)/$', SharedDirLinkView.as_view()),
    # Get file via shared dir
    url(r'^d/(?P<token>[a-f0-9]+)/files/$', SharedDirFileLinkView.as_view()),
    url(r'^d/(?P<token>[a-f0-9]+)/batch/$', BatchSharedDirView.as_view()),
    # Get shared upload link info
    url(r'^u/d/(?P<token>[-0-9a-f]+)/$', SharedUploadLinkView.as_view()),
    # Get upload link for shared directory
    url(r'^u/d/(?P<token>[-0-9a-f]+)/upload/$',
        UploadLinkSharedView.as_view()),
    #
    url(r'^share-link-audit/$', ShareLinkAuditView.as_view()),

    # Tree Operations
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/dirents/$', Dirents.as_view()),
    url(r'^unenc-rw-repos/$', UnEncRWRepos.as_view()),
    url(r'^copy-move-task/$', CopyMoveTaskView.as_view()),
    url(r'^query-copy-move-progress/$', QueryCopyMoveProgressView.as_view()),
    url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/dirents/delete/$',
        DirentsDelete.as_view()),
    # url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/dirents/move/$', DirentsMove.as_view()),
    # url(r'^repos/(?P<repo_id>[-0-9a-f]{36})/dirents/copy/$', DirentsCopy.as_view()),

    # Wikis
    url(r'^wikis/$', WikisView.as_view()),
    url(r'^wikis/(?P<slug>[^/]+)/$', WikiView.as_view()),
    url(r'^wikis/(?P<slug>[^/]+)/pages/$', WikiPagesView.as_view()),

    # Search APIs
    url(r'^search/files/$', SearchFiles.as_view()),

    # Personal activity logs
    url(r'^activity-logs/$', ActivitiesLog.as_view()),
    url(r'^activity-logs/export/$', ActivitiesLogCSV.as_view()),

    # User Activity (replace activity-log)
    url(r'^user-activities/$', UserActivitiesView.as_view()),
    url(r'^user-activities/export/$', UserActivitiesExportCSV.as_view()),

    # Admin Section
    url(r'^admin/sysinfo/$', SysInfo.as_view()),
    url(r'^sys/settings/$', SystemSettings.as_view()),
    # Account
    url(r'^accounts/$', Accounts.as_view()),
    url(r'^accounts/(?P<email>[^/]+)/$', Account.as_view()),
    # Devices
    url(r'^admin/devices/$', AdminDevices.as_view()),
    url(r'^admin/device-errors/$', AdminDeviceErrors.as_view()),
    # Default Library
    url(r'^admin/default-folder/$', AdminDefaultLibrary.as_view()),
    # Libraries
    url(r'^admin/folders/(?P<repo_id>[-0-9a-f]{36})/shares/$',
        AdminLibraryShares.as_view()),
    url(r'^admin/folders/(?P<repo_id>[-0-9a-f]{36})/dirents/$',
        AdminLibraryDirents.as_view()),
    url(r'^admin/folders/(?P<repo_id>[-0-9a-f]{36})/dirent/$',
        AdminLibraryDirent.as_view()),
    url(r'^admin/folders/(?P<repo_id>[-0-9a-f]{36})/password/$',
        AdminLibraryPassword.as_view()),
    url(r'^admin/folders/(?P<repo_id>[-0-9a-f]{36})/$',
        AdminLibrary.as_view()),
    url(r'^admin/folders/$', AdminLibraries.as_view()),
    # System folders
    url(r'^admin/system-folders/$', AdminSystemLibrary.as_view()),
    url(r'^admin/system-folders/upload-links$',
        AdminSystemLibraryUploadLink.as_view()),
    # Trash folders
    url(r'^admin/trash_folders/$', AdminTrashLibraries.as_view()),
    url(r'^admin/trash_folders/(?P<repo_id>[-0-9a-f]{36})/$',
        AdminTrashLibrary.as_view()),

    # Groups
    url(r'^admin/groups/$', AdminGroups.as_view()),
    url(r'^admin/groups/export/$', AdminGroupsExport.as_view()),
    url(r'^admin/groups/(?P<group_id>\d+)/$', AdminGroup.as_view()),
    url(r'^admin/groups/(?P<group_id>\d+)/bbb/$', AdminGroupBBB.as_view()),
    url(r'^admin/groups/(?P<group_id>\d+)/folders/$',
        AdminGroupLibraries.as_view()),
    url(
        r'^admin/groups/(?P<group_id>\d+)/folders/(?P<repo_id>[-0-9a-f]{36})/$', AdminGroupLibrary.as_view()),
    url(r'^admin/groups/(?P<group_id>\d+)/members/$', AdminGroupMembers.as_view()),
    url(
        r'^admin/groups/(?P<group_id>\d+)/members/(?P<email>[^/]+)/$', AdminGroupMember.as_view()),

    url(r'^admin/shares/$', AdminShares.as_view()),

    url(r'^page-logo/$', Logo.as_view()),
    url(r'^page-favicon/$', Favicon.as_view()),

    # admin::users
    url(r'^admin/users/$', AdminUsers.as_view()),
    url(r'^admin/users/source$', AdminUserSource.as_view()),
    url(r'^admin/users/export/$', AdminUsersExcelExport.as_view()),
    url(r'^admin/users/search/$', AdminUsersSearch.as_view()),
    url(r'^admin/users/admins/$', AdminAdmins.as_view()),
    url(ur'^admin/users/admins/(?P<user_email>[^/]+)/$', AdminAdmin.as_view()),
    url(r'^admin/users/batch/$', AdminUsersBatch.as_view()),
    url(r'^admin/users/import/$', AdminUserImport.as_view()),
    url(ur'^admin/users/(?P<user_email>[^/]+)/$', AdminUser.as_view()),
    url(ur'^admin/users/(?P<user_email>[^/]+)/toggle-roles/$', AdminUsersToggleRoles.as_view()),
    url(ur'^admin/users/(?P<user_email>[^/]+)/toggle-status/$', AdminUserToggleStatus.as_view()),
    # admin :: user info
    url(r'^admin/user-info/lib/transfer/$', AdminUserOwnedLibs.as_view()),
    url(r'^admin/user-info/download-link/(?P<token>\S+[a-zA-Z0-9._-]+)/$',
        AdminUserSharedLinkRemovePublicLink.as_view()),
    url(r'^admin/user-info/upload-link/(?P<token>\S+[a-zA-Z0-9._-]+)/$',
        AdminUserSharedLinkRemoveUploadLink.as_view()),
    url(r'^admin/user-info/groups/(?P<group_id>\d+)/$', AdminUserGroups.as_view()),
    # admin logo & fav icon
    url(r'^admin/logo/$', AdminLogo.as_view()),
    url(r'^admin/logo/reset/$', SetDefaultAdminLogo.as_view()),
    url(r'^admin/favicon/$', AdminFavicon.as_view()),
    url(r'^admin/favicon/reset/$', AdminFavIconReset.as_view()),
    url(r'^admin/license/$', AdminLicense.as_view()),
    # admin tenant
    url(r'^admin/tenants/$', AdminTenants.as_view()),
    url(r'^admin/tenants/(?P<inst_id>\d+)/$', AdminTenant.as_view()),
    url(r'^admin/tenants/(?P<inst_id>\d+)/bbb/$', AdminTenantBBB.as_view()),
    url(r'^admin/tenants/(?P<inst_id>\d+)/users/$', AdminTenantUsers.as_view()),
    url(ur'^admin/tenants/(?P<inst_id>\d+)/admins/(?P<user_email>\S+@[a-zA-Z0-9\u00E4\u00F6\u00FC\u00C4\u00D6\u00DC\u00df._-]+\.[a-zA-Z0-9\u00E4\u00F6\u00FC\u00C4\u00D6\u00DC\u00df._-]+)/$', AdminTenantAdmins.as_view()),
    url(ur'^admin/tenants/(?P<inst_id>\d+)/users/(?P<user_email>\S+@[a-zA-Z0-9\u00E4\u00F6\u00FC\u00C4\u00D6\u00DC\u00df._-]+\.[a-zA-Z0-9\u00E4\u00F6\u00FC\u00C4\u00D6\u00DC\u00df._-]+)/$', AdminTenantUser.as_view()),
    # admin public share
    url(r'^admin/upload-links/(?P<token>\S+[a-zA-Z0-9._-]+)/$',
        AdminUploadLink.as_view()),
    url(r'^admin/download-links/(?P<token>\S+[a-zA-Z0-9._-]+)/$',
        AdminDownloadLink.as_view()),
    url(r'^admin/public-shares/$', PublicShares.as_view()),
    url(r'^admin/all-shares/$', AdminPublicShare.as_view()),
    # admin statistic
    url(r'^admin/statistics/traffic/$', TrafficStatistic.as_view()),
    # admin viruses
    url(r'^admin/virus_scan_records/$', VirusFiles.as_view()),
    url(r'^admin/virus_scan_records/(?P<record_id>\d+)/$', VirusFile.as_view()),
    # get setting keys (no auth)
    url(r'^settings/by-keys', SystemSettingsByKeys.as_view()),
    url(r'^settings/restapi/by-keys', RestapiSettingByKeys.as_view()),
    # Current system notification
    url(r'^current-system-notification/', CurrentNotification.as_view()),
    # get server info
    url(r'^server-info', SysVersion.as_view()),
    # System notification
    url(r'^admin/sysnotifications/$', SystemNotifications.as_view()),
    url(r'^admin/sysnotifications/(?P<notification_id>\d+)/$',
        SystemNotification.as_view()),
    # Sudo mode
    url(r'^admin/sudo/$', SudoMode.as_view()),
    # Email changes requests management
    url(r'^admin/email-change-requests/$', AdminUserEmailChangeRequests.as_view()),
    url(r'^admin/email-change-requests/(?P<request_id>\d+)/$', AdminUserEmailChangeRequest.as_view()),

    # roles
    url(r'^roles/$', Roles.as_view()),

    # bbb settings
    url(r'^bbb-settings/(?P<setting_id>\d+)/$', AdminBBBPrivateSettingEntry.as_view()),
    url(r'^bbb-settings/$', BBBPrivateSettingEntries.as_view()),

    # admin bbb settings
    
    url(r'^admin/bbb-settings/(?P<setting_id>\d+)/$', AdminBBBPrivateSettingEntry.as_view()),
    url(r'^admin/bbb-settings/$', AdminBBBPrivateSettingEntries.as_view()),
    

    # meeting rooms
    url(r'^meeting-rooms/bbb-callback/end-meeting$', EndMeetingCallbackForBBB.as_view()),
    url(r'^meeting-rooms/share/groups/search/$', MeetingSearchGroupToShare.as_view()),
    url(r'^meeting-rooms/(?P<meeting_room_id>\d+)/share/public/$', ShareMeetingRoomPublic.as_view()),
    url(r'^meeting-rooms/(?P<meeting_room_id>\d+)/share/users/$', ShareMeetingRoomToUsersEntries.as_view()),
    url(r'^meeting-rooms/(?P<meeting_room_id>\d+)/share/users/(?P<share_entry_id>\d+)/$', ShareMeetingRoomToUsersEntry.as_view()),
    url(r'^meeting-rooms/(?P<meeting_room_id>\d+)/share/groups/$', ShareMeetingRoomToGroupEntries.as_view()),
    url(r'^meeting-rooms/(?P<meeting_room_id>\d+)/share/groups/(?P<share_entry_id>\d+)/$', ShareMeetingRoomToGroupEntry.as_view()),
    url(r'^meeting-rooms/(?P<meeting_room_id>\d+)/start/$', StartMeetingView.as_view()),
    url(r'^meeting-rooms/(?P<meeting_room_id>\d+)/stop/$', StopMeetingView.as_view()),
    url(r'^meeting-rooms/(?P<meeting_room_id>\d+)/recordings/$', MeetingRecordings.as_view()),
    url(r'^meeting-rooms/(?P<meeting_room_id>\d+)/recordings/(?P<recording_id>\S+[a-zA-Z0-9-]+)/$', MeetingRecording.as_view()),
    url(r'^meeting-rooms/(?P<meeting_room_id>\d+)/$', MeetingRoomView.as_view()),
    url(r'^meeting-rooms/by-token/(?P<share_meeting_room_token>\S+[a-zA-Z0-9]+)/$', MeetingRoomByShareTokenView.as_view()),
    url(r'^meeting-rooms/test-bbb/$', TestBBBConnection.as_view()),
    url(r'^meeting-rooms/test-private-bbb/$', TestPrivateBBBSettingConnection.as_view()),
    url(r'^meeting-rooms/private-bbb-settings/$', BBBPrivateSettingList.as_view()),
    url(r'^meeting-rooms/$', MeetingRoomsView.as_view()),
    

    # meeting rooms for admin api
    url(r'^admin/meeting-rooms/share/groups/search/$', AdminMeetingSearchGroupToShare.as_view()),
    url(r'^admin/meeting-rooms/add-modal-init/$', AdminInitAddMeetingModal.as_view()),
    url(r'^admin/meeting-rooms/(?P<meeting_room_id>\d+)/share/public/$', AdminShareMeetingRoomPublic.as_view()),
    url(r'^admin/meeting-rooms/(?P<meeting_room_id>\d+)/share/users/$', AdminShareMeetingRoomToUsersEntries.as_view()),
    url(r'^admin/meeting-rooms/(?P<meeting_room_id>\d+)/share/users/(?P<share_entry_id>\d+)/$', AdminShareMeetingRoomToUsersEntry.as_view()),
    url(r'^admin/meeting-rooms/(?P<meeting_room_id>\d+)/share/groups/$', AdminShareMeetingRoomToGroupEntries.as_view()),
    url(r'^admin/meeting-rooms/(?P<meeting_room_id>\d+)/share/groups/(?P<share_entry_id>\d+)/$', AdminShareMeetingRoomToGroupEntry.as_view()),
    url(r'^admin/meeting-rooms/(?P<meeting_room_id>\d+)/start/$', AdminStartMeetingView.as_view()),
    url(r'^admin/meeting-rooms/(?P<meeting_room_id>\d+)/stop/$', AdminStopMeetingView.as_view()),
    url(r'^admin/meeting-rooms/(?P<meeting_room_id>\d+)/recordings/$', AdminMeetingRecordings.as_view()),
    url(r'^admin/meeting-rooms/(?P<meeting_room_id>\d+)/recordings/(?P<recording_id>\S+[a-zA-Z0-9-]+)/$', AdminMeetingRecording.as_view()),
    url(r'^admin/meeting-rooms/(?P<meeting_room_id>\d+)/$', AdminMeetingRoomView.as_view()),
    url(r'^admin/meeting-rooms/$', AdminMeetingRoomsView.as_view()),

    # Kanban
    url(r'^kanban/projects/$', kanban.KanbanProjectsView.as_view()),
    url(r'^kanban/project/$', kanban.KanbanProjectView.as_view()),
    url(r'^kanban/project/(?P<kanban_project_id>\d+)/$',
        kanban.KanbanProjectView.as_view()),
    url(r'^kanban/boards/(?P<kanban_project_id>\d+)/$',
        kanban.KanbanBoardsView.as_view()),
    url(r'^kanban/board/$', kanban.KanbanBoardView.as_view()),
    url(r'^kanban/board/(?P<kanban_board_id>\d+)/$',
        kanban.KanbanBoardView.as_view()),
    url(r'^kanban/tasks/(?P<kanban_board_id>\d+)/$',
        kanban.KanbanTasksView.as_view()),
    url(r'^kanban/task/$', kanban.KanbanTaskView.as_view()),
    url(r'^kanban/task/(?P<kanban_task_id>\d+)/$',
        kanban.KanbanTaskView.as_view()),
    url(r'^kanban/colors/$', kanban.KanbanColorsView.as_view()),
    url(r'^kanban/color/$', kanban.KanbanColorView.as_view()),
    url(r'^kanban/color/(?P<kanban_color_id>\d+)/$',
        kanban.KanbanColorView.as_view()),
    url(r'^kanban/subtasks/(?P<kanban_task_id>\d+)/$',
        kanban.KanbanSubTasksView.as_view()),
    url(r'^kanban/subtask/$', kanban.KanbanSubTaskView.as_view()),
    url(r'^kanban/subtask/(?P<kanban_subtask_id>\d+)/$',
        kanban.KanbanSubTaskView.as_view()),
    url(r'^kanban/comments/(?P<kanban_task_id>\d+)/$',
        kanban.KanbanCommentsView.as_view()),
    url(r'^kanban/comment/$', kanban.KanbanCommentView.as_view()),
    url(r'^kanban/comment/(?P<kanban_comment_id>\d+)/$',
        kanban.KanbanCommentView.as_view()),
    url(r'^kanban/history/(?P<kanban_task_id>\d+)/$',
        kanban.KanbanHistoryView.as_view()),
    url(r'^kanban/attachments/(?P<kanban_task_id>\d+)/$',
        kanban.KanbanAttachmentsView.as_view()),
    url(r'^kanban/attachment/$', kanban.KanbanAttachmentView.as_view()),
    url(r'^kanban/attachment/(?P<kanban_attach_id>\d+)/$',
        kanban.KanbanAttachmentView.as_view()),
    url(r'^kanban/shares/$', kanban.KanbanSharesView.as_view()),
    url(r'^kanban/shares/(?P<kanban_project_id>\d+)/$',
        kanban.KanbanSharesView.as_view()),
    url(r'^kanban/share/(?P<kanban_share_id>\d+)/$',
        kanban.KanbanShareView.as_view()),
    url(r'^kanban/share-links/$', kanban.KanbanShareLinkList.as_view()),
    url(r'^kanban/share-links/(?P<kanban_project_id>\d+)/$',
        kanban.KanbanShareLinkList.as_view()),
    url(r'^kanban/share-link/(?P<pk>\d+)/$',
        kanban.KanbanShareLinkDetail.as_view()),
    url(r'^kanban/tags/$', kanban.KanbanTagsView.as_view()),
    url(r'^kanban/tags/(?P<pk>\d+)/$', kanban.KanbanTagDetail.as_view()),
    url(r'^kanban/subscriptions/$', kanban.SubscriptionList.as_view()),
    url(r'^kanban/subscriptions/(?P<pk>\d+)/$',
        kanban.SubscriptionDetail.as_view()),
    # Get shared link info (public view)
    url(r'^k/(?P<token>[a-z0-9]+)/$', kanban.KanbanShareLinkView.as_view()),

    # BBB Live Stream
    url(r'^livestream/meeting/(?P<meeting_id>\S+[a-zA-Z0-9._-]+)/$', live_stream.LiveStream.as_view()),
    url(r'^livestream/info/(?P<meeting_key>\S+[a-zA-Z0-9._-]+)/$', live_stream.LiveStreamMeetingInfo.as_view()),
    url(r'^livestream/feedback/(?P<meeting_key>\S+[a-zA-Z0-9._-]+)/$', live_stream.LiveStreamMeetingFeedback.as_view()),
]

if is_audit_log_available():
    urlpatterns += [
            # Audit log for super admin
        url(r'^admin/audit-log/$', AdminAuditLog.as_view()),
        url(r'^admin/audit-log/export/$', AdminAuditLogCSV.as_view()),
        url(r'^admin/audit-log/dropdown-info/$', AdminAuditLogDropdownInfo.as_view()),
    ]

if getattr(views.settings, 'ENABLE_ONLYOFFICE', False):
    from restapi.onlyoffice.views import onlyoffice_editor_callback
    urlpatterns += [
        url(r'^onlyoffice/editor-callback/$', onlyoffice_editor_callback,
            name='api3_onlyoffice_editor_callback'),
    ]
