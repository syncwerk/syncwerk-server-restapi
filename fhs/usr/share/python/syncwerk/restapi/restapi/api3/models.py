import datetime
import hmac
import re
import uuid
from hashlib import sha1
from itertools import chain
from random import randrange

from constance import config
from django.contrib.auth.models import User
from django.db import models
from django.db.models import Case, F, Q, Value, When
from django.db.models.expressions import Func
from django.db.models.functions import Concat, Substr
from django.db.models.lookups import Transform
from django.utils import timezone
from django.utils.translation import activate, deactivate
from django.utils.translation import ugettext as _
from restapi.api3.constants import AgentType, EventLogActionType
from restapi.base.fields import LowerCaseCharField
from synserv import ccnet_threaded_rpc, syncwerk_api

DESKTOP_PLATFORMS = ('windows', 'linux', 'mac')
MOBILE_PLATFORMS = ('ios', 'android')


def random_color():
    return '%06x' % randrange(0x1000000)


def make_random_token():
    return User.objects.make_random_password(
        config.SHARE_LINK_TOKEN_LENGTH).lower()


# Define this some where
def one_hour_hence():
    return timezone.now() + timezone.timedelta(hours=1)


class Token(models.Model):
    """
    The default authorization token model.
    """
    key = models.CharField(max_length=40, primary_key=True)
    user = LowerCaseCharField(max_length=255, unique=True)
    created = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super(Token, self).save(*args, **kwargs)

    def generate_key(self):
        unique = str(uuid.uuid4())
        return hmac.new(unique, digestmod=sha1).hexdigest()

    def __unicode__(self):
        return self.key
    
    class Meta:
        managed = True

class TokenV2Manager(models.Manager):

    def get_all_current_login_tokens_by_user(self, username):
        token_list = super(TokenV2Manager, self).filter(
            user=username, wiped_at=None)
        return token_list

    def get_devices(self, platform, start, end):
        devices = super(TokenV2Manager, self).filter(wiped_at=None)
        if platform == 'desktop':
            devices = devices.filter(platform__in=DESKTOP_PLATFORMS).order_by('-last_accessed')[start : end]
        elif platform == 'mobile':
            devices = devices.filter(platform__in=MOBILE_PLATFORMS).order_by('-last_accessed')[start : end]
        else:
            devices = devices.order_by('-last_accessed')[start : end]
        print len(devices)
        return devices

    def get_total_devices_count(self):
        return super(TokenV2Manager, self).filter(wiped_at=None).count()

    def get_current_connected_devices_count(self):
        # get number of devices last one hour accessed
        devices = super(TokenV2Manager, self).filter(wiped_at=None)
        date_from = datetime.datetime.now() - datetime.timedelta(hours=1)

        # greater than or equal to.
        return devices.filter(last_accessed__gte=date_from).count()

    def get_user_devices(self, username):
        '''List user devices, most recently used first'''
        devices = super(TokenV2Manager, self).filter(user=username).filter(wiped_at=None)
        platform_priorities = {
            'windows': 0,
            'linux': 0,
            'mac': 0,
            'android': 1,
            'ios': 1,
        }

        def sort_devices(d1, d2):
            '''Desktop clients are listed before mobile clients. Devices of
            the same category are listed by most recently used first

            '''
            ret = cmp(platform_priorities[d1.platform], platform_priorities[d2.platform])
            if ret != 0:
                return ret

            return cmp(d2.last_accessed, d1.last_accessed)

        return [ d.as_dict() for d in sorted(devices, sort_devices) ]

    def _get_token_by_user_device(self, username, platform, device_id):
        try:
            return super(TokenV2Manager, self).get(user=username,
                                                   platform=platform,
                                                   device_id=device_id)
        except TokenV2.DoesNotExist:
            return None

    def get_or_create_token(self, username, platform, device_id, device_name,
                            client_version, platform_version, last_login_ip):

        token = self._get_token_by_user_device(username, platform, device_id)
        if token and token.wiped_at:
            token.delete()
            token = None

        if token:
            if token.client_version != client_version or token.platform_version != platform_version \
                or token.device_name != device_name:

                token.client_version = client_version
                token.platform_version = platform_version
                token.device_name = device_name
                token.save()

            return token

        token = TokenV2(user=username,
                        platform=platform,
                        device_id=device_id,
                        device_name=device_name,
                        client_version=client_version,
                        platform_version=platform_version,
                        last_login_ip=last_login_ip)
        token.save()
        return token


    def delete_device_token(self, username, platform, device_id):
        super(TokenV2Manager, self).filter(user=username, platform=platform, device_id=device_id).delete()

    def mark_device_to_be_remote_wiped(self, username, platform, device_id):
        token = self._get_token_by_user_device(username, platform, device_id)
        if not token:
            return
        token.wiped_at = datetime.datetime.now()
        token.save()

class TokenV2(models.Model):
    """
    Device specific token
    """

    key = models.CharField(max_length=40, primary_key=True)

    user = LowerCaseCharField(max_length=255)

    # windows/linux/mac/ios/android
    platform = LowerCaseCharField(max_length=32)

    # ccnet id, android secure id, etc.
    device_id = models.CharField(max_length=40)

    # lin-laptop
    device_name = models.CharField(max_length=40)

    # platform version
    platform_version = LowerCaseCharField(max_length=16)

    # syncwerk client/app version
    client_version = LowerCaseCharField(max_length=16)

    # most recent activity
    last_accessed = models.DateTimeField(auto_now=True)

    last_login_ip = models.GenericIPAddressField(null=True, default=None)

    created_at = models.DateTimeField(default=timezone.now)
    wiped_at = models.DateTimeField(null=True)

    objects = TokenV2Manager()

    class Meta:
        unique_together = (('user', 'platform', 'device_id'),)
        managed = True

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super(TokenV2, self).save(*args, **kwargs)

    def generate_key(self):
        unique = str(uuid.uuid4())
        return hmac.new(unique, digestmod=sha1).hexdigest()

    def __unicode__(self):
        return "TokenV2{user=%(user)s,device=%(device_name)s}" % \
            dict(user=self.user,device_name=self.device_name)

    def is_desktop_client(self):
        return str(self.platform) in ('windows', 'linux', 'mac')

    def as_dict(self):
        return dict(key=self.key,
                    user=self.user,
                    platform=self.platform,
                    device_id=self.device_id,
                    device_name=self.device_name,
                    client_version=self.client_version,
                    platform_version=self.platform_version,
                    last_accessed=self.last_accessed,
                    last_login_ip=self.last_login_ip,
                    wiped_at=self.wiped_at)


# Class for ccnet (use with 'ccnet' database config)
class CcnetUserManager(object):

    def get(self,email=None):
        if not email:
            # This for override the models.Manager of django
            raise CcnetUser.DoesNotExist, 'CcnetUser matching query does not exits.'
        else:
            # Query from ccnet api
            emailuser = ccnet_threaded_rpc.get_emailuser(email)

            # Raise exception if not exist user
            if not emailuser:
                raise CcnetUser.DoesNotExist, 'CcnetUser matching query does not exits.'
            else:
                # Check source 
                if emailuser.source == EmailUser.source:
                    # Query from EmailUser
                    return EmailUser.objects.using('ccnet').get(email=email)
                elif emailuser.source == LDAPUsers.source:
                    # Query from LDAPUsers
                    return LDAPUsers.objects.using('ccnet').get(email=email)
                else:
                    raise CcnetUser.DoesNotExist, 'CcnetUser matching query does not exits.'

    def all(self):
        # Get both Email User and LDAPUsers then sort by id

        return sorted(
            chain(
                EmailUser.objects.using('ccnet').all(), 
                LDAPUsers.objects.using('ccnet').all()
                ),
            key=lambda instance: instance.id)

class CcnetUser(object):
    # User for ccnet database
    objects = CcnetUserManager()

    class DoesNotExist(Exception):
        pass

class EmailUser(models.Model):
    # EmailUser for ccnet database
    id = models.AutoField(primary_key=True)
    email = LowerCaseCharField(max_length=255)
    passwd = models.CharField(max_length=256)
    is_staff = models.BooleanField()
    is_active = models.BooleanField()
    language = LowerCaseCharField(max_length=255)
    ctime = models.BigIntegerField()
    reference_id = models.CharField(max_length=255)

    # Define source
    source = 'DB'

    class Meta:
        db_table = "EmailUser"

class LDAPUsers(models.Model):
    # LDAPUsers for ccnet database
    id = models.AutoField(primary_key=True)
    email = LowerCaseCharField(max_length=255)
    password = models.CharField(max_length=255)
    is_staff = models.BooleanField()
    is_active = models.BooleanField()
    language = LowerCaseCharField(max_length=255)
    extra_attrs = models.TextField()
    reference_id = models.CharField(max_length=255)

    # Define source
    source = 'LDAPImport'

    class Meta:
        db_table = "LDAPUsers"

class FileLocks(models.Model):
    id = models.AutoField(primary_key=True)
    repo_id = LowerCaseCharField(max_length=36)
    path = models.CharField(max_length=512)
    email = models.CharField(max_length=255, db_column='user_name')
    lock_time = models.BigIntegerField()
    expire = models.BigIntegerField(default=0)

    class Meta:
        db_table = "FileLocks"
        unique_together = (("repo_id","path"),)

class FileLockTimestamp(models.Model):
    repo_id = LowerCaseCharField(max_length=36, primary_key=True)
    update_time = models.BigIntegerField()

    class Meta:
        db_table = "FileLockTimestamp"


## Classes for syncwerk-server (use with 'syncwerk-server' database config)
class SharedRepo(models.Model):
    id = models.AutoField(primary_key=True)
    repo_id = LowerCaseCharField(max_length=36)
    from_email = models.CharField(max_length=255)
    to_email = models.CharField(max_length=255)
    permission = models.CharField(max_length=255)
    allow_view_history = models.BooleanField()
    allow_view_snapshot = models.BooleanField()
    allow_restore_snapshot = models.BooleanField()

    class Meta:
        db_table = "SharedRepo"

class MonthlyUserTraffic(models.Model):
    id = models.AutoField(primary_key=True, serialize=False)
    user = models.CharField(max_length=255)
    month = models.DateField()
    web_file_upload = models.BigIntegerField(default=0)
    web_file_download = models.BigIntegerField(default=0)
    sync_file_upload = models.BigIntegerField(default=0)
    sync_file_download = models.BigIntegerField(default=0)
    link_file_upload = models.BigIntegerField(default=0)
    link_file_download = models.BigIntegerField(default=0)

    class Meta:
        db_table = "MonthlyUserTraffic"
        managed = True

class VirusScannedHeader(models.Model):
    id = models.AutoField(primary_key=True)
    repo_id = LowerCaseCharField(max_length=36)
    scanned_head_id = LowerCaseCharField(max_length=255)

    class Meta:
        db_table = "VirusScannedHeader"
        managed = True

class ESIndexingHeader(models.Model):
    id = models.AutoField(primary_key=True)
    repo_id = LowerCaseCharField(max_length=36)
    indexed_head_id = LowerCaseCharField(max_length=255)

    class Meta:
        db_table = "ESIndexingHeader"
        managed = True

class VirusScanningInfectedFile(models.Model):
    id = models.AutoField(primary_key=True)
    repo_id = LowerCaseCharField(max_length=36)
    infected_file_path = models.TextField(max_length=1024)
    is_handled = models.BooleanField(default=False)
    is_false_positive = models.BooleanField(default=False)
    commit_id = models.CharField(max_length=255)
    detected_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "VirusScanningInfectedFile"
        managed = True

class EmailChangingRequest(models.Model):
    id = models.AutoField(primary_key=True)
    user_id = models.CharField(max_length=255)
    new_email = models.CharField(max_length=255)
    request_token = models.CharField(max_length=64)
    request_token_expire_time = models.DateTimeField(default=one_hour_hence)    
    new_email_confirmed = models.BooleanField(default=False)
    request_completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "EmailChangingRequest"
        managed = True

class StrIndex(Func):
    """
    Return a positive integer corresponding to the 1-indexed position of the
    first occurrence of a substring inside another string, or 0 if the
    substring is not found.
    """
    function = 'INSTR'
    arity = 2
    output_field = models.IntegerField()

    def as_postgresql(self, compiler, connection, **extra_context):
        return super(StrIndex, self).as_sql(compiler, connection, function='STRPOS', **extra_context)

class Reverse(Transform):
    function = 'REVERSE'
    lookup_name = 'reverse'

    def as_oracle(self, compiler, connection, **extra_context):
        # REVERSE in Oracle is undocumented and doesn't support multi-byte
        # strings. Use a special subquery instead.
        return super(Reverse, self).as_sql(
            compiler, connection,
            template=(
                '(SELECT LISTAGG(s) WITHIN GROUP (ORDER BY n DESC) FROM '
                '(SELECT LEVEL n, SUBSTR(%(expressions)s, LEVEL, 1) s '
                'FROM DUAL CONNECT BY LEVEL <= LENGTH(%(expressions)s)) '
                'GROUP BY %(expressions)s)'
            ),
            **extra_context
        )

class Replace(Func):
    function = 'REPLACE'

    def __init__(self, expression, text, replacement=Value(''), **extra):
        super(Replace, self).__init__(expression, text, replacement, **extra)


class EventLogManager(models.Manager):
    FOLDER_CHANGE_SEPERATOR = ">"
    PATH_SEPERATOR = '/'

    def decode_folder_change(self, event):
        
        from_f = None
        to_f = None

        location_change = None
        if event.action_type in [EventLogActionType.MOVED_FILE.value, EventLogActionType.RENAMED_FILE.value]:
            location_change = event.sub_folder_file
        elif event.action_type in [EventLogActionType.MOVED_DIR.value, EventLogActionType.RENAMED_DIR.value]:
            location_change = event.folder

        if location_change:
            changes = [change.strip() for change in location_change.split(self.FOLDER_CHANGE_SEPERATOR)]
            from_f = changes[0]
            to_f = changes[1] 

        return [from_f,to_f]
    
    

    def __get_from_f(self,queryset):
        return queryset.annotate(
            from_f=Case(
                When(
                    action_type__in=[EventLogActionType.MOVED_FILE.value, EventLogActionType.RENAMED_FILE.value],
                    then=Substr(
                        'sub_folder_file',
                        1,
                        StrIndex('sub_folder_file', Value(self.FOLDER_CHANGE_SEPERATOR)) - 1
                    )
                ),
                When(
                    action_type__in=[EventLogActionType.MOVED_DIR.value, EventLogActionType.RENAMED_DIR.value],
                    then=Substr(
                        'folder',
                        1, 
                        StrIndex('folder', Value(self.FOLDER_CHANGE_SEPERATOR)) - 1
                    )
                ),
                default=Value(None)
            )
        )
        

    def __get_to_f(self, queryset):
        return queryset.annotate(
            to_f=Case(
                When(
                    action_type__in=[EventLogActionType.MOVED_FILE.value, EventLogActionType.RENAMED_FILE.value],
                    then=Reverse(Substr(
                        Reverse(
                            ('sub_folder_file')
                        ),
                        1,
                        StrIndex(Reverse('sub_folder_file'), Value(self.FOLDER_CHANGE_SEPERATOR)) - 1
                    ))
                ),
                When(
                    action_type__in=[EventLogActionType.MOVED_DIR.value, EventLogActionType.RENAMED_DIR.value],
                    then=Reverse(Substr(
                        Reverse(
                            ('folder')
                        ),
                        1, 
                        StrIndex(Reverse(('folder')), Value(self.FOLDER_CHANGE_SEPERATOR)) - 1
                        ))
                ),
                default=Value(None)
            )
        )
        

    def get_folder_name(self, obj):
        if not obj.sub_folder_file or obj.sub_folder_file == self.PATH_SEPERATOR:
            return obj.folder
        return obj.sub_folder_file.split(self.PATH_SEPERATOR)

    def __get_folder_name(self,queryset):

        return queryset.annotate(
            folder_name=Case(
                When(
                    Q(sub_folder_file=None) | Q(sub_folder_file=self.PATH_SEPERATOR),
                    then=F('folder')
                ),
                When(
                    ~Q(
                        Q(sub_folder_file__contains=self.PATH_SEPERATOR) | Q(sub_folder_file=None)
                    ),
                    then=F('sub_folder_file')
                ),
                When(
                    ~Q(
                        Q(sub_folder_file=None) | Q(sub_folder_file=self.PATH_SEPERATOR)
                    ) & ~Q(folder=None),
                    then=Reverse(Substr(
                        Reverse(
                            ('sub_folder_file')
                        ),
                        1,
                        StrIndex(Reverse('sub_folder_file'), Value(self.PATH_SEPERATOR)) - 1
                    ))
                ),                
                default=Value(None)
            ))

    def __get_user_sub_folder_file(self, queryset, email, org_id=None):
        shared_sub_repo_conditions = []
        shared_repos = []
        if org_id:
            shared_repos = syncwerk_api.get_org_share_in_repo_list(org_id,email, -1, -1)
        else:
            shared_repos = syncwerk_api.get_share_in_repo_list(email, -1, -1)

        for repo in shared_repos:
            # This mean not sub repo
            if repo.origin_repo_id:
                shared_sub_repo_conditions.append(
                    When(
                        Q(folder_id=repo.origin_repo_id) & Q(sub_folder_file__startswith=repo.origin_path),
                        then=Replace(
                            F('sub_folder_file'),
                            Value(repo.origin_path),
                            Value(repo.name)
                        )
                    )
                )

        return queryset.annotate(
            user_sub_folder_file=Case(
                *shared_sub_repo_conditions,
                default=F('sub_folder_file')
            )
        )

    def __event_sentence_value(self, event_sentence):
        regex = "\%\((.+?)\)s"

        fields = re.findall(regex,event_sentence)
        splitted_sentence = re.split(regex,event_sentence)

        result = []
        for i, part in enumerate(splitted_sentence):
            if part in fields:
                result.append(F(part))
            elif part:
                result.append(Value(part))                 
        return Concat(*result)

    def get_action_type_sentence(self, action_type, obj=None, locale=None, format_str=True):
        # Default
        text = None

        # Activate locale translation
        if locale:
            activate(locale)

        # Get element
        agent_events = EventLogActionType.get_agent_events()
        folder_name = None
        changes = None
        if format_str:
            if obj:
                folder_name = self.get_folder_name(obj)
                changes = self.decode_folder_change(obj)
            else:
                raise ValueError("Require obj to format_str")
        


        # Get str by type
        if action_type == EventLogActionType.LOGIN_SUCCESS.value:
            # Login successfully
            text = _('Login successfully from %(ip_address)s')
            
            if format_str:
                text = text % {'ip_address': obj.ip_address}

        elif action_type == EventLogActionType.LOGIN_FAILED.value:
            # Login failed
            text = _('Login failed from %(ip_address)s')

            if format_str:
                text = text % {'ip_address': obj.ip_address}

        elif action_type == EventLogActionType.SEND_MAIL.value:
            # Send email
            text = _('Sent email to %(recipient)s')
            
            if format_str:
                text = text % {'recipient': obj.recipient}

        elif action_type in agent_events.keys():
            
            agent = agent_events[action_type]['agent']
            event = agent_events[action_type]['event']

            # Add repo permisison
            if event == EventLogActionType.ADD_REPO_PERM:
                if agent == AgentType.ALL.value:
                    text = _('Share to all: Share to all %(folder_name)s with permission %(permissions)s')

                    if format_str:
                        text = text % {
                                'folder_name': folder_name,
                                'permissions': obj.permissions
                                }
                elif agent == AgentType.USER_EMAIL.value or agent == AgentType.USER_USERNAME.value:
                    text = _('Share to %(recipient)s %(folder_name)s with permission %(permissions)s')

                    if format_str:
                        text = text % {
                        'recipient': obj.recipient,
                        'folder_name': folder_name,
                        'permissions': obj.permissions
                        }
                elif agent == AgentType.GROUP.value:
                    text = _('Share to group %(recipient)s %(folder_name)s with permission %(permissions)s')
                    
                    if format_str:
                        text = text % {
                        'recipient': obj.recipient,
                        'folder_name': folder_name,
                        'permissions': obj.permissions
                        }
            # Modify repo permisison
            elif event == EventLogActionType.MODIFY_REPO_PERM:
                if agent == AgentType.ALL.value:
                    text = _('Change all permission of %(folder_name)s to %(permissions)s')

                    if format_str:
                        text = text % {
                        'folder_name': folder_name,
                        'permissions': obj.permissions
                        }
                elif agent == AgentType.USER_EMAIL.value or agent == AgentType.USER_USERNAME.value:
                    text = _('Change %(recipient)s permission of %(folder_name)s to %(permissions)s')
                    
                    if format_str:
                        text = text % {
                        'recipient': obj.recipient,
                        'folder_name': folder_name,
                        'permissions': obj.permissions
                        }
                elif agent == AgentType.GROUP.value:
                    text = _('Change group %(recipient)s permission of %(folder_name)s to %(permissions)s')
                    
                    if format_str:
                        text = text % {
                        'recipient': obj.recipient,
                        'folder_name': folder_name,
                        'permissions': obj.permissions
                        } 
            # Delete repo permisison
            elif event == EventLogActionType.DELETE_REPO_PERM:
                if agent == AgentType.ALL.value:
                    text = _('Remove share to all of %(folder_name)s')
                    
                    if format_str:
                        text = text % {
                        'folder_name': folder_name
                        }
                elif agent == AgentType.USER_EMAIL.value or agent == AgentType.USER_USERNAME.value:
                    text = _('Remove share to %(recipient)s of folder %(folder_name)s')
                    
                    if format_str:
                        text = text % {
                        'recipient': obj.recipient,
                        'folder_name': folder_name
                        }
                elif agent == AgentType.GROUP.value:
                    text = _('Remove share to group %(recipient)s of %(folder_name)s')
                    
                    if format_str:
                        text = text % {
                        'recipient': obj.recipient,
                        'folder_name': folder_name
                        }
        
        elif action_type == EventLogActionType.CREATE_SHARE_LINK.value:
            # Create share link
            text = _('Create share link of %(folder_name)s with permission %(permissions)s')
            
            if format_str:
                text = text % {
                'folder_name': folder_name,
                'permissions': obj.permissions}

        elif action_type == EventLogActionType.DELETE_SHARE_LINK.value:
            # Remove share link
            text = _('Remove share link of %(folder_name)s with permission %(permissions)s')
            
            if format_str:
                text = text % {
                'folder_name': folder_name,
                'permissions': obj.permissions}

        elif action_type == EventLogActionType.CREATE_UPLOAD_LINK.value:
            # Create upload link
            text = _('Create upload link of %(folder_name)s')
            
            if format_str:
                text = text % {
                'folder_name': folder_name}

        elif action_type == EventLogActionType.DELETE_UPLOAD_LINK.value:
            # Remove upload link
            text = _('Remove upload link of %(folder_name)s')
            
            if format_str:
                text = text % {
                'folder_name': folder_name}

        elif action_type == EventLogActionType.FILE_ACCESS.value:
            # File access
            text = _('Accessed file %(folder_name)s')
            
            if format_str:
                text = text % {
                'folder_name': folder_name}

        elif action_type == EventLogActionType.ADDED_FILE.value:
            # Added file
            text = _('%(name)s added file %(folder_name)s')
            
            if format_str:
                text = text % {
                'name' : obj.name,
                'sub_folder_file': folder_name}
                
        elif action_type == EventLogActionType.MODIFIED_FILE.value:
            # Modified file
            text = _('%(name)s modified file %(folder_name)s')
            
            if format_str:
                text = text % {
                'name' : obj.name,
                'sub_folder_file': folder_name}

        elif action_type == EventLogActionType.DELETED_FILE.value:
            # Deleted file
            text = _('%(name)s deleted file %(folder_name)s')
            
            if format_str:
                text = text % {
                'name' : obj.name,
                'sub_folder_file': folder_name}

        elif action_type == EventLogActionType.RENAMED_FILE.value:
            # Renamed file
            text = _('%(name)s renamed file %(from_f)s to %(to_f)s')
            
            if format_str:
                text = text % {
                'name' : obj.name,
                'from_f': changes[0],
                'to_f': changes[1]
            }
        
        elif action_type == EventLogActionType.MOVED_FILE.value:
            # Moved file
            text = _('%(name)s moved file %(folder_name)s from %(from_f)s to %(to_f)s')
            
            if format_str:
                text = text % {
                'name' : obj.name,
                'sub_folder_file' : folder_name,
                'from_f': changes[0],
                'to_f': changes[1]
            }

        elif action_type == EventLogActionType.ADDED_DIR.value:
            # Added dir
            text = _('%(name)s create new folder %(folder_name)s')
            
            if format_str:
                text = text % {
                'name' : obj.name,
                'folder_name': folder_name }
        
        elif action_type == EventLogActionType.RENAMED_DIR.value:
            # Renamed die
            text = _('%(name)s renamed folder %(from_f)s to %(to_f)s')
            
            if format_str:
                text = text % {
                'name' : obj.name,
                'from_f': changes[0],
                'to_f': changes[1]
            }
        
        elif action_type == EventLogActionType.MOVED_DIR.value:
            # Moved dir
            text = _('%(name)s moved folder %(folder_name)s from %(from_f)s to %(to_f)s')
            
            if format_str:
                text = text % {
                'name' : obj.name,
                'folder_name' : obj.folder,
                'from_f': changes[0],
                'to_f': changes[1]
            }
               

        elif action_type == EventLogActionType.DELETED_DIR.value:
            # Deleted dir
            text = _('%(name)s deleted folder %(folder_name)s')
            
            if format_str:
                text = text % {
                'name' : obj.name,
                'folder_name': folder_name}


        # Deactivate locale translation 
        if locale:
            deactivate()
        return text

    def __sentence_value(self, action_type):

        agent_events = EventLogActionType.get_agent_events()

        text = self.get_action_type_sentence(action_type, format_str=False)

        if text:
            return self.__event_sentence_value(text)
        return Value(None)

    def with_user_sub_folder_file(self, email, org_id=None, queryset=None):
        if not queryset:
            queryset = self
        
        return self.__get_user_sub_folder_file(queryset, email, org_id)

    def with_raw_sentence(self, format_str=True, queryset=None):
        if not queryset:
            queryset = self

        queryset = self.__get_folder_name(queryset)
        queryset = self.__get_from_f(queryset)
        queryset = self.__get_to_f(queryset)

        cases = []
        
        # Action types
        for action_type in EventLogActionType.getValues():
            cases.append(
                When(
                    action_type=action_type,
                    then=self.__sentence_value(action_type)
                )
            )


        return queryset.annotate(
            raw_sentence=Case(
                *cases,
                default=Value('None'),
                output_field=models.TextField()
                )
            )
        


class EventLog(models.Model):
    id = models.AutoField(db_index=True,primary_key=True)
    user_id = models.CharField(db_index=True, max_length=255,blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    ip_address = models.CharField(blank=True, db_index=True, max_length=45, null=True)
    device_name = models.TextField(blank=True, null=True)
    folder = models.TextField(blank=True, null=True)
    folder_id = models.TextField(blank=True, null=True)
    sub_folder_file = models.TextField(blank=True, null=True)
    action_type = models.CharField(blank=True, db_index=True, max_length=255, null=True)
    recipient = models.TextField(blank=True, null=True)
    permissions = models.CharField(blank=True, db_index=True, max_length=255, null=True)
    updated_at = models.DateTimeField(db_index=True,default=timezone.now)

    objects = EventLogManager()
    class Meta:
        abstract = True

class AuditLog(EventLog):

    @staticmethod
    def createAuditLog(user_id, name, ip_address, device_name, folder, folder_id, sub_folder_file, action_type, recipient, permissions):
        # Create Auditlog model 
        return AuditLog.objects.create(
            user_id = user_id,
            name = name, 
            ip_address = ip_address,
            device_name = device_name,
            folder = folder,
            folder_id = folder_id,
            sub_folder_file = sub_folder_file,
            action_type= action_type,
            recipient = recipient,
            permissions = permissions
        )

    @staticmethod
    def deleteAllAuditLog():
        # Delete all Audit Log
        return AuditLog.objects.all().delete()

    @staticmethod
    def getAuditList(**kwargs):
        # Remove all None and empty string
        criteria = dict((k,v) for k,v in kwargs.iteritems() if v is not None or v == '')

        # Query
        return AuditLog.objects.filter(**criteria)

    class Meta:
        db_table = "AuditLog"

class UserActivity(EventLog):

    class Meta:
        db_table = "UserActivity"

    def get_locale_str(self, locale=None, format_str=True):
        return UserActivity.objects.get_action_type_sentence(self.action_type,self,locale,format_str)
    
    def __str__(self):
        return self.get_locale_str()

class MeetingRoom(models.Model):
    id = models.AutoField(primary_key=True, serialize=False)
    b3_meeting_id = models.CharField(max_length=255, unique=True)
    room_name = models.CharField(max_length=255)
    attendee_pw = models.CharField(max_length=255)
    moderator_pw = models.CharField(max_length=255)
    status = models.CharField(max_length=16, default="STOPPED")
    owner_id = models.CharField(max_length=255)
    share_token = models.CharField(max_length=32, blank=True, null=True, default=None, unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    mute_participants_on_join = models.BooleanField(default=False)
    require_mod_approval = models.BooleanField(default=False)
    allow_any_user_start = models.BooleanField(default=False)
    all_users_join_as_mod = models.BooleanField(default=False)
    allow_recording = models.BooleanField(default=False)
    max_number_of_participants = models.IntegerField(default=0)
    welcome_message = models.TextField()
    private_setting_id = models.IntegerField(default=-1)
    require_meeting_password = models.BooleanField(default=False)
    live_stream_active = models.BooleanField(default=False)
    live_stream_feedback_active = models.BooleanField(default=False)
    live_stream_url = models.CharField(max_length=255)
    live_stream_meeting_key = models.CharField(max_length=255)

    class Meta:
        db_table = "MeetingRooms"

class BBBPrivateSetting(models.Model):
    id = models.AutoField(primary_key=True, serialize=False)
    setting_name = models.CharField(max_length=255, default="Unammed configuration")
    bbb_server = models.TextField()
    bbb_secret = models.CharField(max_length=255)
    is_active = models.BooleanField(default=False)
    user_id = models.CharField(max_length=255)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    live_stream_token = models.CharField(max_length=255)
    live_stream_server = models.CharField(max_length=255)

    class Meta:
        db_table = "BBBPrivateSettings"

class MeetingRoomShare(models.Model):
    id = models.AutoField(primary_key=True, serialize=False)
    meeting_room_id = models.IntegerField()
    share_to_user = models.CharField(max_length=255)
    user_role = models.CharField(max_length=30)
    group_id = models.IntegerField(default=0)
    share_type = models.CharField(max_length=30, default="SHARED_TO_USER")
    created_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        db_table = "MeetingRoomShares"

class ProfileSettingManager(models.Manager):
    def get_profile_setting_by_user(self, username):
        """Get a user's profile setting.
        """
        try:
            return super(ProfileSettingManager, self).get(user=username)
        except ProfileSetting.DoesNotExist:
            return None

class ProfileSetting(models.Model):
    user = models.EmailField(unique=True)
    max_meetings = models.IntegerField(default=0)
    objects = ProfileSettingManager()

    class Meta:
        db_table = "ProfileSetting"

class MeetingRoomFile(models.Model):
    meeting_room_id = models.IntegerField()
    presentation_file = models.TextField(blank=True, null=True)

    class Meta:
        db_table = "MeetingRoomFile"


# Kanban
class KanbanUser(models.Model):
    id = models.AutoField(primary_key=True, serialize=False)
    owner_id = models.CharField(max_length=255)

    class Meta:
        db_table = "KanbanUser"


class KanbanProject(models.Model):
    id = models.AutoField(primary_key=True, serialize=False)
    project_name = models.CharField(max_length=255, db_index=True)
    owner_id = models.CharField(max_length=255)
    image = models.ImageField(
        blank=True, default="", upload_to="kanban_project/")
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    owners = models.ManyToManyField(
        KanbanUser, related_name='owners', blank=True)

    class Meta:
        db_table = "KanbanProject"

    def __str__(self):
        return self.project_name


class KanbanShareLink(models.Model):
    s_type = 'k'
    project = models.ForeignKey(KanbanProject, on_delete=models.CASCADE)
    username = LowerCaseCharField(max_length=255)
    token = models.CharField(
        max_length=100, unique=True, default=make_random_token)
    ctime = models.DateTimeField(auto_now_add=True)
    view_cnt = models.IntegerField(default=0)
    password = models.CharField(max_length=128, null=True)
    expire_date = models.DateTimeField(null=True)

    def is_owner(self, username):
        return self.project.owner_id == username




class KanbanShare(models.Model):
    SHARE_TYPE_USER = 'U'
    SHARE_TYPE_GROUP = 'G'
    SHARE_TYPE_CHOICES = (
        (SHARE_TYPE_USER, 'Shared to User'),
        (SHARE_TYPE_GROUP, 'Shared to Group'),
    )
    PERMISSION_CHOICES = (
        ('r', 'Read-only'),
        ('rw', 'Read/Write'),
    )
    kanban_project = models.ForeignKey(KanbanProject, on_delete=models.CASCADE)
    share_type = models.CharField(
        max_length=2, choices=SHARE_TYPE_CHOICES, default=SHARE_TYPE_USER)
    user_id = models.CharField(max_length=255, blank=True, null=True)
    group_id = models.IntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    permission = models.CharField(
        max_length=4, choices=PERMISSION_CHOICES, default='r')

    class Meta:
        unique_together = "kanban_project", "user_id"


class KanbanBoard(models.Model):
    id = models.AutoField(primary_key=True, serialize=False)
    kanban_project = models.ForeignKey(KanbanProject, on_delete=models.CASCADE)
    board_name = models.CharField(max_length=255, db_index=True)
    board_order = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "KanbanBoard"


class KanbanTag(models.Model):
    id = models.AutoField(primary_key=True, serialize=False)
    title = models.CharField(max_length=255, unique=True)
    color = models.CharField(max_length=6, default=random_color)

    def __str__(self):
        return self.title

    class Meta:
        db_table = "KanbanTag"


class KanbanColor(models.Model):
    id = models.AutoField(primary_key=True, serialize=False)
    title = models.CharField(max_length=255, db_index=True)
    color = models.CharField(max_length=255, db_index=True)

    class Meta:
        db_table =  "KanbanColor"



class KanbanTask(models.Model):
    id = models.AutoField(primary_key=True, serialize=False)
    order = models.IntegerField(default=0, db_index=True)
    kanban_board = models.ForeignKey(KanbanBoard, on_delete=models.CASCADE)
    title = models.CharField(max_length=255, db_index=True)
    description = models.TextField(max_length=255, blank=True)
    due_date = models.DateTimeField()
    completed = models.BooleanField()
    assignee_id = models.CharField(max_length=255)
    tags = models.ManyToManyField(KanbanTag, related_name='tags', blank=True)
    task_color = models.ManyToManyField(KanbanColor, related_name='task_color', blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "KanbanTask"
        ordering = 'order',

    def __str__(self):
        return self.title


class KanbanSubTask(models.Model):
    id = models.AutoField(primary_key=True, serialize=False)
    title = models.CharField(max_length=255, db_index=True)
    completed = models.BooleanField()
    kanban_task = models.ForeignKey(KanbanTask,
                                    on_delete=models.CASCADE,
                                    null=True)

    class Meta:
        db_table = "KanbanSubTask"


class KanbanComment(models.Model):
    id = models.AutoField(primary_key=True, serialize=False)
    comment = models.CharField(max_length=255, db_index=True)
    created_at = models.DateTimeField(default=timezone.now)
    owner_id = models.CharField(max_length=255)
    kanban_task = models.ForeignKey(KanbanTask, on_delete=models.CASCADE, null=True)

    class Meta:
        db_table =  "KanbanComment"


class KanbanHistory(models.Model):
    id = models.AutoField(primary_key=True, serialize=False)
    audit = models.CharField(max_length=255, db_index=True)
    created_at = models.DateTimeField(default=timezone.now)
    owner_id = models.CharField(max_length=255)
    kanban_task = models.ForeignKey(
        KanbanTask, on_delete=models.CASCADE, null=True)

    class Meta:
        db_table = "KanbanHistory"


class KanbanAttach(models.Model):
    id = models.AutoField(primary_key=True, serialize=False)
    title = models.CharField(max_length=255, db_index=True)
    image = models.FileField(
        blank=True, default="", upload_to="kanban_attach/")
    kanban_task = models.ForeignKey(
        KanbanTask, on_delete=models.CASCADE, null=True)

    class Meta:
        db_table = "KanbanAttach"


class KanbanSubscription(models.Model):
    task = models.ForeignKey(KanbanTask, on_delete=models.CASCADE)
    user_id = models.CharField(max_length=255)

    def __str__(self):
        return "%s - %s" % (task, user_id)

    class Meta:
        unique_together = "task", "user_id"
