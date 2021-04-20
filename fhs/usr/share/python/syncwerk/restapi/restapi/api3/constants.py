from aenum import Enum, NoAlias

class EnumChoice(Enum):
    _settings_ = NoAlias
    
    @classmethod
    def get_obj(cls, str):
        for obj in cls:
            if obj.value.lower() == str.lower():
                return obj.name
    
    @classmethod
    def get_obj_by_value(cls, str):
        for obj in cls:
            if obj.value.lower() == str.lower():
                return obj

    @classmethod
    def get_value_by_name(cls, str):
        for obj in cls:
            if obj.name.lower() == str.lower():
                return obj.value
    
    @classmethod
    def getChoices(cls):
        return ((obj.name, obj.value) for obj in cls)

    @classmethod
    def getValues(cls):
        return list(set([obj.value for obj in cls]))

    @classmethod
    def get_value(cls, obj):
        return obj.value

class AgentType(EnumChoice):
    GROUP = 'group'
    USER_EMAIL  = 'user'
    USER_USERNAME = 'user'
    ALL = 'all'


class EventLogActionType(EnumChoice):
    # Login
    LOGIN_SUCCESS = "Login successfully"
    LOGIN_FAILED = "Login failed"

    # Mail
    SEND_MAIL = "Send Email"

    # Repo permisison
    ADD_REPO_PERM = "Share to %s"
    MODIFY_REPO_PERM = "Change %s permission"
    DELETE_REPO_PERM = "Remove %s share"

    # Share link
    CREATE_SHARE_LINK = "Create share link"
    DELETE_SHARE_LINK = "Remove share link"

    # Upload link
    CREATE_UPLOAD_LINK = "Create upload link"
    DELETE_UPLOAD_LINK = "Remove upload link"

    # File access
    FILE_ACCESS = "File access"

    # File accions
    ADDED_FILE = "Added file"
    MOVED_FILE = "Moved file"
    RENAMED_FILE = "Renamed file"
    MODIFIED_FILE = "Modified file"
    DELETED_FILE = "Deleted file"

    # Dir actions
    ADDED_DIR = "Added dir"
    MOVED_DIR = "Moved dir"
    RENAMED_DIR = "Renamed dir"
    DELETED_DIR = "Deleted dir"

    @classmethod
    def get_value(cls, obj, agent=None):
        if '%s' in obj.value:
            if agent:
                return obj.value%AgentType.get_value_by_name(agent)
            else:
                raise ValueError('This action type need input agent')
        return obj.value
        
    @classmethod
    def get_value_by_name(cls, str, agent=None):
        for obj in cls:
            if obj.name.lower() == str.lower():
                return EventLogActionType.get_value(obj,agent)

    @classmethod
    def getValues(cls):
        choices = []
        agents = AgentType.getValues()
        for obj in cls:
            if '%s' in obj.value:
                for agent in agents:
                    choices.append(
                        obj.value%agent
                    )
            else:
                choices.append(obj.value)

        return choices

    @classmethod
    def get_value_by_etype(cls, etype, agent=None):
        etype_list = {
            'login-success': cls.LOGIN_SUCCESS,
            'login-failed': cls.LOGIN_FAILED,
            'send-mail': cls.SEND_MAIL,
            'add-repo-perm': cls.ADD_REPO_PERM,
            'modify-repo-perm': cls.MODIFY_REPO_PERM,
            'delete-repo-perm' : cls.DELETE_REPO_PERM,
            'create-share-link': cls.CREATE_SHARE_LINK,
            'delete-share-link': cls.DELETE_SHARE_LINK,
            'create-upload-link': cls.CREATE_UPLOAD_LINK,
            'delete-upload-link': cls.DELETE_UPLOAD_LINK,
            'file-access': cls.FILE_ACCESS,
            'added-file': cls.ADDED_FILE,
            'deleted-file': cls.DELETED_FILE,
            'added-dir':cls.ADDED_DIR,
            'deleted-dir': cls.DELETED_DIR,
            'modified-file': cls.MODIFIED_FILE,
            'renamed-file': cls.RENAMED_FILE,
            'moved-file': cls.MOVED_FILE,
            'renamed-dir': cls.RENAMED_DIR,
            'moved-dir': cls.MOVED_DIR
        }
        
        # Get obj
        obj = None
        if etype in etype_list:
            obj = etype_list[etype]                
        else:
            raise ValueError('Invalid input etype')
        
        return EventLogActionType.get_value(obj,agent)

    @classmethod
    def get_agent_events(cls):
        agent_events = {}

        # Get all event have agent
        events = [cls.ADD_REPO_PERM, cls.DELETE_REPO_PERM, cls.MODIFY_REPO_PERM]

        for agent in AgentType.getValues():
            for obj in events:
                agent_events[obj.value%agent] = { 'agent':agent, 'event':obj}

        return agent_events

class RepoPermission(EnumChoice):
    R = 'read only'
    RW = 'read/write'
    VIEW_DOWNLOAD = 'view_download'
    NONE = '-'

    @classmethod
    def get_value_by_name(cls, str):
        if str:
            for obj in cls:
                if obj.name.lower() == str.lower():
                    return obj.value
        return obj.NONE.value