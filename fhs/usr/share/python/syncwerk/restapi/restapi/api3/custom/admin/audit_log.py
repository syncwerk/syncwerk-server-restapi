import logging
import json
import os
import random
import datetime

from django.utils.translation import ugettext as _
from django.core.paginator import Paginator
from restapi.settings import ENABLE_AUDIT_LOG

logger = logging.getLogger(__name__)


from restapi.api3.models import AuditLog as AuditLogDBHandler

# Factory
class AuditLogHandlerFactory:
    @staticmethod
    def createHandler(storage='DB'):
        """Get Audit Log handler 
        
        Keyword Arguments:
            storage {str} -- [Handler type] (default: {'DB'})
        
        Returns:
            [Object] -- [Audit Log Handler]
        """        
        # DB storage
        if storage == 'DB':
            return AuditLogDBHandler
        
class AuditLog:
    __instance = None
    handler = AuditLogHandlerFactory.createHandler('DB')
    
    def __init__(self):
        if AuditLog.__instance != None:
            # Block create another AuditLog
            raise Exception("AuditLog is already created")
        else:
            AuditLog.__instance = self

    @staticmethod 
    def getInstance():
        if AuditLog.__instance == None:
            AuditLog()
        return AuditLog.__instance

    def createAuditLog(self, user_id, name, ip_address, device_name, folder, folder_id, sub_folder_file, action_type, recipient, permissions):
        return self.handler.createAuditLog(
            user_id = user_id,
            name = name, 
            ip_address = ip_address,
            device_name = device_name,
            folder = folder,
            folder_id = folder_id,
            sub_folder_file = sub_folder_file,
            action_type= action_type,
            recipient = recipient,
            permissions = permissions)
    
    def deleteAllAuditLog(self):
        return self.handler.deleteAllAuditLog()
    
    def getAuditList(self, user_id=None, name=None,  updated_at__gte=None, updated_at__lte=None, ip_address=None, device_name=None, folder=None, folder_id=None, sub_folder_file=None, action_type=None, recipient=None, permissions=None):
        """Retrive AuditLog object list in Page
        
        Keyword Arguments:
            user_id {[type]} -- [description] (default: {None})
            updated_at__gte {[type]} -- [Start update ] (default: {None})
            updated_at__lte {[type]} -- [End update] (default: {None})
            ip_address {[type]} -- [description] (default: {None})
            folder {[type]} -- [description] (default: {None})
            folder_id {[type]} -- [description] (default: {None})
            sub_folder_file {[type]} -- [description] (default: {None})
            action_type {[type]} -- [description] (default: {None})
            recipient {[type]} -- [description] (default: {None})
            permissions {[type]} -- [description] (default: {None})
            per_page {int} -- [description] (default: {10})
        
        Returns:
            [django.queryset] -- [Queryset object for view]
        """    
        # Queryset
        return self.handler.getAuditList(
            user_id=user_id,
            name__icontains=name,
            updated_at__date__gte=updated_at__gte,
            updated_at__date__lte=updated_at__lte,
            ip_address__icontains=ip_address,
            device_name__icontains=device_name,
            folder__icontains=folder,
            folder_id=folder_id,
            sub_folder_file__icontains=sub_folder_file,
            action_type=action_type,
            recipient__icontains=recipient,
            permissions=permissions).order_by('-updated_at')

    def getAuditListPage(self, user_id=None, name=None,  updated_at__gte=None, updated_at__lte=None, ip_address=None, device_name=None, folder=None, folder_id=None, sub_folder_file=None, action_type=None, recipient=None, permissions=None, per_page = 10, **kwargs):
        """Retrive AuditLog object list in Page
        
        Keyword Arguments:
            user_id {[type]} -- [description] (default: {None})
            updated_at__gte {[type]} -- [Start update ] (default: {None})
            updated_at__lte {[type]} -- [End update] (default: {None})
            ip_address {[type]} -- [description] (default: {None})
            folder {[type]} -- [description] (default: {None})
            folder_id {[type]} -- [description] (default: {None})
            sub_folder_file {[type]} -- [description] (default: {None})
            action_type {[type]} -- [description] (default: {None})
            recipient {[type]} -- [description] (default: {None})
            permissions {[type]} -- [description] (default: {None})
            per_page {int} -- [description] (default: {10})
        
        Returns:
            [django.core.paginator.Paginator] -- [Pagination object for view]
        """        
        # Queryset
        audit_log_list = self.getAuditList(
            user_id=user_id,
            name=name,
            updated_at__gte=updated_at__gte,
            updated_at__lte=updated_at__lte,
            ip_address=ip_address,
            device_name=device_name,
            folder=folder,
            folder_id=folder_id,
            sub_folder_file=sub_folder_file,
            action_type=action_type,
            recipient=recipient,
            permissions=permissions)
        # Pagination
        paginator = Paginator(audit_log_list, per_page)

        # return page object_list
        return paginator
    
    def getAuditListArray(self, user_id=None, name=None, updated_at__gte=None, updated_at__lte=None, ip_address=None, device_name=None, folder=None, folder_id=None, sub_folder_file=None, action_type=None, recipient=None, permissions=None, **kwargs):
        """Retrive AuditLog object list in Page
        
        Keyword Arguments:
            user_id {[type]} -- [description] (default: {None})
            updated_at__gte {[type]} -- [Start update ] (default: {None})
            updated_at__lte {[type]} -- [End update] (default: {None})
            ip_address {[type]} -- [description] (default: {None})
            folder {[type]} -- [description] (default: {None})
            folder_id {[type]} -- [description] (default: {None})
            sub_folder_file {[type]} -- [description] (default: {None})
            action_type {[type]} -- [description] (default: {None})
            recipient {[type]} -- [description] (default: {None})
            permissions {[type]} -- [description] (default: {None})
        
        Returns:
            [List] -- [List]
        """    
        return self.getAuditList(
            user_id=user_id,
            name=name,
            updated_at__gte=updated_at__gte,
            updated_at__lte=updated_at__lte,
            ip_address=ip_address,
            device_name=device_name,
            folder=folder,
            folder_id=folder_id,
            sub_folder_file=sub_folder_file,
            action_type=action_type,
            recipient=recipient,
            permissions=permissions).values()
        
    def clear_old_log(self, older_than):
        """Clear all old log older than
        
        Arguments:
            older_than {[datetime]} -- [description]
        
        Returns:
            [type] -- [description]
        """        
        return self.getAuditList(updated_at__lte=older_than).delete()
