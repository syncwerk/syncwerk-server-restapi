from restapi.settings import *

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'APIDBNAME',
        'USER': 'root',
        'PASSWORD': 'DBPASS',
        'HOST': 'mariadb',
        'PORT': '3306',
        'OPTIONS': {
            'init_command': 'SET storage_engine=INNODB, sql_mode=STRICT_TRANS_TABLES',
        }
    },
    'ccnet': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'CCNETDBNAME',
        'USER': 'root',
        'PASSWORD': 'DBPASS',
        'HOST': 'mariadb',
        'PORT': '3306',
        'OPTIONS': {
            'init_command': 'SET storage_engine=INNODB, sql_mode=STRICT_TRANS_TABLES',
        }
    },
    'syncwerk-server': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'SERVERDBNAME',
        'USER': 'root',
        'PASSWORD': 'DBPASS',
        'HOST': 'mariadb',
        'PORT': '3306',
        'OPTIONS': {
            'init_command': 'SET storage_engine=INNODB, sql_mode=STRICT_TRANS_TABLES',
        }
    }
}
