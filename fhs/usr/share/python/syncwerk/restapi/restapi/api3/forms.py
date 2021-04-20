# Copyright (c) 2012-2016 Seafile Ltd.
# encoding: utf-8
import logging
import re

from django.conf import settings
from django import forms
from django.utils.translation import ugettext_lazy as _

from pyrpcsyncwerk import RpcsyncwerkError
from constance import config

from synserv import syncwerk_api, ccnet_api, ccnet_threaded_rpc
# from synserv import ccnet_threaded_rpc, unset_repo_passwd, is_passwd_set, \
#     syncwerk_api, ccnet_api

from restapi.base.accounts import User
from restapi.utils import is_valid_dirent_name
from restapi.role_permissions.utils import get_available_roles

from restapi.api3.utils.licenseInfo import parse_license_to_json, is_pro_version, get_machine_id

from restapi.utils import is_user_password_strong

logger = logging.getLogger(__name__)

def user_number_over_limit():
    # count users
    try:
        active_db_users = ccnet_api.count_emailusers('DB')
    except Exception as e:
        logger.error(e)
        active_db_users = 0

    try:
        active_ldap_users = ccnet_api.count_emailusers('LDAP')
    except Exception as e:
        logger.error(e)
        active_ldap_users = 0

    try:
        inactive_db_users = ccnet_api.count_inactive_emailusers('DB')
    except Exception as e:
        logger.error(e)
        inactive_db_users = 0

    try:
        inactive_ldap_users = ccnet_api.count_inactive_emailusers('LDAP')
    except Exception as e:
        logger.error(e)
        inactive_ldap_users = 0

    active_users = active_db_users + active_ldap_users if active_ldap_users > 0 \
        else active_db_users

    inactive_users = inactive_db_users + inactive_ldap_users if inactive_ldap_users > 0 \
        else inactive_db_users

    is_pro = is_pro_version()
    if is_pro:
        license_json = parse_license_to_json()
        if (active_users <= license_json['allowed_users']):
            return False
        else:
            return True
    else:
        if (active_users <= 3):
            return False
        else:
            return True

class AddUserForm(forms.Form):
    """
    Form for adding a user.
    """
    email = forms.EmailField()
    name = forms.CharField(max_length=64, required=False)
    department = forms.CharField(max_length=512, required=False)

    role_list = get_available_roles()
    admin_role_list = settings.ENABLED_ADMIN_ROLE_PERMISSIONS.keys()
    roles = role_list + admin_role_list

    role = forms.ChoiceField(choices=[ (i, i) for i in roles ])
	
    password1 = forms.CharField(widget=forms.PasswordInput())
    password2 = forms.CharField(widget=forms.PasswordInput())

    def clean_email(self):
        if user_number_over_limit():
            raise forms.ValidationError(_("The number of users exceeds the limit."))

        email = self.cleaned_data['email']
        try:
            user = User.objects.get(email=email)
            raise forms.ValidationError(_("A user with this email already exists."))
        except User.DoesNotExist:
            return self.cleaned_data['email']

    def clean_name(self):
        """
        should not include '/'
        """
        if "/" in self.cleaned_data["name"]:
            raise forms.ValidationError(_(u"Name should not include '/'."))

        return self.cleaned_data["name"]


    def clean(self):
        """
        Verifiy that the values entered into the two password fields
        match. Note that an error here will end up in
        ``non_field_errors()`` because it doesn't apply to a single
        field.

        """
        if 'password1' in self.cleaned_data and 'password2' in self.cleaned_data:
            if self.cleaned_data['password1'] != self.cleaned_data['password2']:
                raise forms.ValidationError(_("The two passwords didn't match."))
        return self.cleaned_data

class RegistrationForm(forms.Form):
    """
    Form for registering a new user account.

    Validates that the requested email is not already in use, and
    requires the password to be entered twice to catch typos.
    """
    attrs_dict = { 'class': 'input' }

    email = forms.CharField(widget=forms.TextInput(attrs=dict(attrs_dict,
                                                               maxlength=75)),
                             label=_("Email address"))
    userid = forms.RegexField(regex=r'^\w+$',
                              max_length=40,
                              required=False,
                              widget=forms.TextInput(),
                              label=_("Username"),
                              error_messages={ 'invalid': _("This value must be of length 40") })

    password1 = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict, render_value=False),
                                label=_("Password"))
    password2 = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict, render_value=False),
                                label=_("Password (again)"))

    @classmethod
    def allow_register(self, email):
        prog = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",
                          re.IGNORECASE)
        return False if prog.match(email) is None else True

    def clean_email(self):
        if user_number_over_limit():
            raise forms.ValidationError(_("The number of users exceeds the limit."))

        email = self.cleaned_data['email']
        if not self.allow_register(email):
            raise forms.ValidationError(_("Enter a valid email address."))

        emailuser = ccnet_threaded_rpc.get_emailuser(email)
        if not emailuser:
            return self.cleaned_data['email']
        else:
            raise forms.ValidationError(_("User %s already exists.") % email)

    def clean_userid(self):
        if self.cleaned_data['userid'] and len(self.cleaned_data['userid']) != 40:
            raise forms.ValidationError(_("Invalid user id."))
        return self.cleaned_data['userid']

    def clean_password1(self):
        if 'password1' in self.cleaned_data:
            pwd = self.cleaned_data['password1']

            if bool(config.USER_STRONG_PASSWORD_REQUIRED) is True:
                if bool(is_user_password_strong(pwd)) is True:
                    return pwd
                else:
                    raise forms.ValidationError(
                        _(("%(pwd_len)s characters or more, include "
                           "%(num_types)s types or more of these: "
                           "letters(case sensitive), numbers, and symbols")) %
                        {'pwd_len': config.USER_PASSWORD_MIN_LENGTH,
                         'num_types': config.USER_PASSWORD_STRENGTH_LEVEL})
            else:
                return pwd

    def clean_password2(self):
        """
        Verifiy that the values entered into the two password fields
        match. Note that an error here will end up in
        ``non_field_errors()`` because it doesn't apply to a single
        field.

        """
        if 'password1' in self.cleaned_data and 'password2' in self.cleaned_data:
            if self.cleaned_data['password1'] != self.cleaned_data['password2']:
                raise forms.ValidationError(_("The two password fields didn't match."))
        return self.cleaned_data

class DetailedRegistrationForm(RegistrationForm):
    attrs_dict = { 'class': 'input' }

    try:
        from restapi.settings import REGISTRATION_DETAILS_MAP
    except:
        REGISTRATION_DETAILS_MAP = None

    if REGISTRATION_DETAILS_MAP:
        name_required = REGISTRATION_DETAILS_MAP.get('name', False)
        dept_required = REGISTRATION_DETAILS_MAP.get('department', False)
        tele_required = REGISTRATION_DETAILS_MAP.get('telephone', False)
        note_required = REGISTRATION_DETAILS_MAP.get('note', False)
    else:
        # Backward compatible
        name_required = dept_required = tele_required = note_required = True

    name = forms.CharField(widget=forms.TextInput(
            attrs=dict(attrs_dict, maxlength=64)), label=_("name"),
                           required=name_required)
    department = forms.CharField(widget=forms.TextInput(
            attrs=dict(attrs_dict, maxlength=512)), label=_("department"),
                                 required=dept_required)
    telephone = forms.CharField(widget=forms.TextInput(
            attrs=dict(attrs_dict, maxlength=100)), label=_("telephone"),
                                required=tele_required)
    note = forms.CharField(widget=forms.TextInput(
            attrs=dict(attrs_dict, maxlength=100)), label=_("note"),
                           required=note_required)