#coding: UTF-8

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

'''This script would check if there is admin, and prompt the user to create a new one if non exist'''

import json
import sys
import os
import time
import re
import shutil
import glob
import subprocess
import hashlib
import getpass
import uuid
import warnings

from ConfigParser import ConfigParser

try:
    import readline # pylint: disable=W0611
except ImportError:
    pass


class RPC(object):
    def __init__(self):
        import ccnet
        ccnet_dir = os.environ['CCNET_CONF_DIR']
        central_config_dir = os.environ['SYNCWERK_CENTRAL_CONF_DIR']
        self.rpc_client = ccnet.CcnetThreadedRpcClient(
            ccnet.ClientPool(ccnet_dir, central_config_dir=central_config_dir))

    def get_db_email_users(self):
        return self.rpc_client.get_emailusers('DB', 0, 1)

    def create_admin(self, email, user):
        self.rpc_client.add_emailuser(email, user, 1, 1)
        return self.rpc_client.update_role_emailuser(email, 'superadmin')

def need_create_admin():
    users = rpc.get_db_email_users()
    return len(users) == 0

def create_admin(email, passwd):
    if rpc.create_admin(email, passwd) < 0:
        raise Exception('failed to create admin')
    else:
        print 'Syncwerk admin user created'


rpc = RPC()

def main():
    if not need_create_admin():
        return

    password_file = os.path.join(os.environ['SYNCWERK_CENTRAL_CONF_DIR'], 'admin.txt')
    if os.path.exists(password_file):
        with open(password_file, 'r') as fp:
            pwinfo = json.load(fp)
        email = pwinfo['email']
        passwd = pwinfo['password']
        os.unlink(password_file)
    else:
        print 'Error creating Syncwerk admin user'

    create_admin(email, passwd)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print '\n\n\n'
        print Utils.highlight('Aborted.')
        print
        sys.exit(1)
    except Exception, e:
        print
        print Utils.highlight('Error happened during creating syncwerk admin.')
        print
