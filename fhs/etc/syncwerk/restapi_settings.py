SECRET_KEY = "SECRETKEY"
#ADMINS = (
#    ('admin1', 'admin1@example.com'),
#    ('admin2', 'admin2@example.com'),
#    ('admin3', 'admin3@example.com'),
#)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'APIDBNAME',
        'USER': 'DBUSER',
        'PASSWORD': 'DBPASS',
        'HOST': '127.0.0.1',
        'PORT': '3306',
        'OPTIONS': {
            'init_command': 'SET storage_engine=INNODB, sql_mode=STRICT_TRANS_TABLES',
        }
    },
    'ccnet': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'CCNETDBNAME',
        'USER': 'DBUSER',
        'PASSWORD': 'DBPASS',
        'HOST': '127.0.0.1',
        'PORT': '3306',
        'OPTIONS': {
            'init_command': 'SET storage_engine=INNODB, sql_mode=STRICT_TRANS_TABLES',
        }
    },
    'syncwerk-server': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'SERVERDBNAME',
        'USER': 'DBUSER',
        'PASSWORD': 'DBPASS',
        'HOST': '127.0.0.1',
        'PORT': '3306',
        'OPTIONS': {
            'init_command': 'SET storage_engine=INNODB, sql_mode=STRICT_TRANS_TABLES',
        }
    }
}
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
    'LOCATION': '127.0.0.1:11211',
#    'LOCATION': '127.0.0.2:11211',
#    'LOCATION': '127.0.0.3:11211',
    }
}
# Use for cluster environment. Create database table manually with avatar_uploadedfilenamefilename_md5datasizemtime
#AVATAR_FILE_STORAGE = 'restapi.base.database_storage.DatabaseStorage'
COMPRESS_CACHE_BACKEND = 'django.core.cache.backends.locmem.LocMemCache'
#ACTIVATE_AFTER_REGISTRATION         = True
#ADD_REPLY_TO_HEADER                 = True
BRANDING_CSS                        = 'css/syncwerk.css'
#CLOUD_MODE                          = True
DEFAULT_FROM_EMAIL                  = 'noreply@HOSTNAME'
EMAIL_HOST                          = 'localhost'
EMAIL_HOST_PASSWORD                 = ''
EMAIL_HOST_USER                     = ''
EMAIL_PORT                          = '25'
EMAIL_USE_TLS                       = False
#ENABLE_GLOBAL_ADDRESSBOOK           = True
#ENABLE_MAKE_GROUP_PUBLIC            = True
#ENABLE_REPO_HISTORY_SETTING         = True
#ENABLE_SETTINGS_VIA_WEB             = True
#ENABLE_SIGNUP                       = True
#ENABLE_SYS_ADMIN_VIEW_REPO          = True
#ENABLE_THUMBNAIL                    = True
#ENABLE_UPLOAD_FOLDER                = True
#FILE_ENCODING_LIST                  = ['auto', 'utf-8', 'gbk', 'ISO-8859-1', 'ISO-8859-5', 'Shift_JIS']
#FILE_PREVIEW_MAX_SIZE               = 30 * 1024 * 1024
FILE_SERVER_ROOT                    = 'https://HOSTNAME/seafhttp'
#LOGO_HEIGHT                         = 32
#LOGO_WIDTH                          = 149
#OFFICE_CONVERTER_ROOT               = 'http://127.0.0.1'
#REPLACE_FROM_EMAIL                  = True
#REPO_PASSWORD_MIN_LENGTH            = 8
SEND_EMAIL_ON_ADDING_SYSTEM_MEMBER  = True
#SEND_EMAIL_ON_RESETTING_USER_PASSWD = True
SERVER_EMAIL                        = 'EMAIL_HOST_USER'
#SESSION_COOKIE_AGE                  = 60 * 60 * 24 * 7 * 2
#SESSION_EXPIRE_AT_BROWSER_CLOSE     = True
#SESSION_SAVE_EVERY_REQUEST          = True
SITE_BASE                           = 'https://HOSTNAME'
SITE_NAME                           = 'Syncwerk Server'
SITE_TITLE                          = 'Syncwerk Server'
THUMBNAIL_ROOT                      = '/var/lib/syncwerk/thumbnails/'
#TIME_ZONE                           = ''
#USER_PASSWORD_MIN_LENGTH            = 8
#USER_PASSWORD_STRENGTH_LEVEL        = 3
#USER_STRONG_PASSWORD_REQUIRED       = True
#USE_PDFJS                           = True
#LOGIN_REMEMBER_DAYS                 = True
#LOGIN_ATTEMPT_LIMIT                 = True
#FREEZE_USER_ON_LOGIN_FAILED         = True
#FORCE_PASSWORD_CHANGE               = True
ENABLE_WIKI                         = True
ENABLE_REPO_SNAPSHOT_LABEL          = True
DISABLE_SYNC_WITH_ANY_FOLDER        = False
ENABLE_SHARE_TO_ALL_GROUPS          = True
ENABLE_AUDIT_LOG                    = True
#TEXT_PREVIEW_EXT                    = "ac, am, bat, c, cc, cmake, cpp, cs, css, diff, el, h, html, htm, java, js, json, less, make, org, php, pl, properties, py, rb, scala, script, sh, sql, txt, text, tex, vi, vim, xhtml, xml, log, csv, groovy, rst, patch, go"
THUMBNAIL_IMAGE_SIZE_LIMIT          = 30
#ENABLE_VIDEO_THUMBNAIL              = True
#THUMBNAIL_VIDEO_FRAME_TIME          = 5
#THUMBNAIL_SIZE_FOR_ORIGINAL         = 1024
#ENABLE_ADFS_LOGIN                   = True
ENABLE_KRB5_LOGIN                   = True
#ENABLE_SHIBBOLETH_LOGIN             = True
LANGUAGE_CODE                       = 'de'
MAX_NUMBER_OF_FILES_FOR_FILEUPLOAD  = 500
SHARE_LINK_EMAIL_LANGUAGE           = 'de'
#UNREAD_NOTIFICATIONS_REQUEST_INTERVAL = 3 * 60
SHOW_TRAFFIC                        = True
SERVE_STATIC                        = False
LOGIN_URL                           = '/login'
ENABLE_SHARE_LINK_AUDIT             = True
ENABLE_UPLOAD_LINK_VIRUS_CHECK      = True
ENABLE_TERMS_AND_CONDITIONS         = True
ENABLE_TWO_FACTOR_AUTH              = True
LIBRARY_TEMPLATES = {
    'Technology': ['/Develop/Python', '/Test'],
    'Finance': ['/Current assets', '/Fixed assets/Computer']
}
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_RATES': {
        'ping': '600/minute',
        'anon': '5/minute',
        'user': '300/minute',
    },
    'UNICODE_JSON': False,
}
#REST_FRAMEWORK_THROTTING_WHITELIST  = ['127.0.0.1', '192.168.1.1']
MULTI_INSTITUTION                   = True
EXTRA_MIDDLEWARE_CLASSES = (
    'restapi.tenants.middleware.TenantMiddleware',
)
ENABLED_ROLE_PERMISSIONS = {
    'default': {
        'can_add_repo': True,
        'can_add_group': True,
        'can_view_org': True,
        'can_use_global_address_book': True,
        'can_generate_share_link': True,
        'can_generate_upload_link': True,
        'can_invite_guest': False,
        'can_connect_with_android_clients': True,
        'can_connect_with_ios_clients': True,
        'can_connect_with_desktop_clients': True,
        'role_quota': '',
    },
    'guest': {
        'can_add_repo': False,
        'can_add_group': False,
        'can_view_org': False,
        'can_use_global_address_book': False,
        'can_generate_share_link': False,
        'can_generate_upload_link': False,
        'can_invite_guest': False,
        'can_connect_with_android_clients': False,
        'can_connect_with_ios_clients': False,
        'can_connect_with_desktop_clients': False,
        'role_quota': '',
    },
    'employee': {
        'can_add_repo': True,
        'can_add_group': True,
        'can_view_org': True,
        'can_use_global_address_book': True,
        'can_generate_share_link': True,
        'can_generate_upload_link': True,
        'can_invite_guest': True,
        'can_connect_with_android_clients': True,
        'can_connect_with_ios_clients': True,
        'can_connect_with_desktop_clients': True,
        'role_quota': '',
    },
}
ENABLED_ADMIN_ROLE_PERMISSIONS = {
    'superadmin': {
        'can_view_system_info': True,
        'can_config_system': True,
        'can_view_statistic': True,
        'can_manage_library': True,
        'can_manage_user': True,
        'can_manage_group': True,
        'can_view_user_log': True,
        'can_view_admin_log': True,
        'notify_admin_on_throttle_events': False,
    },
    'auditadmin': {
        'can_view_system_info': True,
        'can_view_admin_log': True,
    },
}
# Enable Only Office
#ENABLE_ONLYOFFICE = True
#VERIFY_ONLYOFFICE_CERTIFICATE = True
#ONLYOFFICE_APIJS_URL = 'https://HOSTNAME/onlyofficeds/web-apps/apps/api/documents/api.js'
#ONLYOFFICE_FILE_EXTENSION = ('doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'odt', 'fodt', 'odp', 'fodp', 'ods', 'fods')
#ONLYOFFICE_EDIT_FILE_EXTENSION = ('doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'odt', 'fodt', 'odp', 'fodp', 'ods', 'fods')
