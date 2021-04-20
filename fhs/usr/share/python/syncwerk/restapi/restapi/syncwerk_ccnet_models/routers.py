class SyncwerkCcnetModelsRouter(object):
    """
    A router to control all database operations on models related to ccnet
    """
    
    def db_for_read(self, model, **hints):
        """
        Point all operations which has app_label='syncwerk_ccnet_models' models to 'ccnet'
        """
        if model._meta.app_label == 'syncwerk_ccnet_models':
            return 'ccnet'
        return None
    def db_for_write(self, model, **hints):
        """
        Point all operations on syncwerk_ccnet_models models to 'ccnet'
        """
        if model._meta.app_label == 'syncwerk_ccnet_models':
            return 'ccnet'
        return None
    def allow_relation(self, obj1, obj2, **hints):
        """
        Allow relations if a model in the syncwerk_ccnet_models is involved.
        """
        if obj1._meta.app_label == 'syncwerk_ccnet_models' or \
           obj2._meta.app_label == 'syncwerk_ccnet_models':
           return True
        return None
    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Make sure the syncwerk_ccnet_models models only appears in the 'ccnet' db
        database.
        """
        if app_label == 'syncwerk_ccnet_models':
            return db == 'ccnet'
        return None