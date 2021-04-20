class SyncwerkServerModelsRouter(object):
    """
    A router to control all database operations on models related to syncwerk-server
    """
    
    def db_for_read(self, model, **hints):
        """
        Point all operations which has app_label='syncwerk_server_models' models to 'syncwerk-server'
        """
        if model._meta.app_label == 'syncwerk_server_models':
            return 'syncwerk-server'
        return None
    def db_for_write(self, model, **hints):
        """
        Point all operations on syncwerk_server_models models to 'syncwerk-server'
        """
        if model._meta.app_label == 'syncwerk_server_models':
            return 'syncwerk-server'
        return None
    def allow_relation(self, obj1, obj2, **hints):
        """
        Allow relations if a model in the syncwerk_server_models is involved.
        """
        if obj1._meta.app_label == 'syncwerk_server_models' or \
           obj2._meta.app_label == 'syncwerk_server_models':
           return True
        return None
    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Make sure the syncwerk_server_models models only appears in the 'syncwerk-server' db
        database.
        """
        if app_label == 'syncwerk_server_models':
            return db == 'syncwerk-server'
        # api3 and syncwerk_server_models have conflicting tables
        # (FileLocks)
        # so don't allow creating models from api3 in syncwerk-server database
        if app_label == 'api3' and db == 'syncwerk-server':
            return False
        return None
