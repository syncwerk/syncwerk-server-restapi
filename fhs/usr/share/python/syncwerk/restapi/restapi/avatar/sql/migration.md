## step 0: create avatar table in restapi db,

```
CREATE TABLE IF NOT EXISTS `avatar_uploaded` (`filename` TEXT NOT NULL, `filename_md5` CHAR(32) NOT NULL PRIMARY KEY, `data` MEDIUMTEXT NOT NULL, `size` INTEGER NOT NULL, `mtime` datetime NOT NULL);
```

## step 1: download migration script

```
cd <syncwerk-path>/syncwerk-server-latest/restapi/restapi/avatar/management/commands/

wget https://raw.githubusercontent.com/syncwerk/restapi/6.2/restapi/avatar/management/commands/migrate_avatars_fs2db.py
```

## step 2: run migration

```
cd <syncwerk-path>/syncwerk-server-latest

./restapi.sh python-env restapi/manage.py migrate_avatars_fs2db
```

## step 3: change avatar storage backend

```
vi <syncwerk-path>/conf/restapi_settings.py

AVATAR_FILE_STORAGE = 'restapi.base.database_storage.DatabaseStorage'
```

## step 4: restart restapi cache and syncwerk service

for memcached: `service memcached restart`

otherwise: `rm -rf /tmp/restapi_cache/*`
