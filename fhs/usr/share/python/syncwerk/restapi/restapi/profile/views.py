# Copyright (c) 2012-2016 Seafile Ltd.
# encoding: utf-8
from django.conf import settings
import json
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.shortcuts import render
from django.contrib import messages
from django.utils.translation import ugettext as _

import synserv
from synserv import syncwerk_api

from forms import DetailedProfileForm
from models import Profile, DetailedProfile
from restapi.auth.decorators import login_required
from restapi.utils import is_org_context, is_pro_version, is_valid_username
from restapi.base.accounts import User
from restapi.base.templatetags.restapi_tags import email2nickname
from restapi.contacts.models import Contact
from restapi.options.models import UserOptions, CryptoOptionNotSetError
from restapi.utils import is_ldap_user
from restapi.utils.two_factor_auth import has_two_factor_auth
from restapi.views import get_owned_repo_list

@login_required
def edit_profile(request):
    """
    Show and edit user profile.
    """
    username = request.user.username
    form_class = DetailedProfileForm

    if request.method == 'POST':
        form = form_class(request.POST)
        if form.is_valid():
            form.save(username=username)
            messages.success(request, _(u'Successfully edited profile.'))

            return HttpResponseRedirect(reverse('edit_profile'))
        else:
            messages.error(request, _(u'Failed to edit profile'))
    else:
        profile = Profile.objects.get_profile_by_user(username)
        d_profile = DetailedProfile.objects.get_detailed_profile_by_user(
            username)

        init_dict = {}
        if profile:
            init_dict['nickname'] = profile.nickname
            init_dict['login_id'] = profile.login_id
            init_dict['contact_email'] = profile.contact_email
            init_dict['list_in_address_book'] = profile.list_in_address_book
        if d_profile:
            init_dict['department'] = d_profile.department
            init_dict['telephone'] = d_profile.telephone

        form = form_class(init_dict)

    # common logic
    try:
        server_crypto = UserOptions.objects.is_server_crypto(username)
    except CryptoOptionNotSetError:
        # Assume server_crypto is ``False`` if this option is not set.
        server_crypto = False

    sub_lib_enabled = UserOptions.objects.is_sub_lib_enabled(username)

    default_repo_id = UserOptions.objects.get_default_repo(username)
    if default_repo_id:
        default_repo = syncwerk_api.get_repo(default_repo_id)
    else:
        default_repo = None

    owned_repos = get_owned_repo_list(request)
    owned_repos = filter(lambda r: not r.is_virtual, owned_repos)

    if settings.ENABLE_WEBDAV_SECRET:
        decoded = UserOptions.objects.get_webdav_decoded_secret(username)
        webdav_passwd = decoded if decoded else ''
    else:
        webdav_passwd = ''

    resp_dict = {
            'form': form,
            'server_crypto': server_crypto,
            "sub_lib_enabled": sub_lib_enabled,
            'ENABLE_ADDRESSBOOK_OPT_IN': settings.ENABLE_ADDRESSBOOK_OPT_IN,
            'default_repo': default_repo,
            'owned_repos': owned_repos,
            'is_pro': is_pro_version(),
            'is_ldap_user': is_ldap_user(request.user),
            'two_factor_auth_enabled': has_two_factor_auth(),
            'ENABLE_CHANGE_PASSWORD': settings.ENABLE_CHANGE_PASSWORD,
            'ENABLE_WEBDAV_SECRET': settings.ENABLE_WEBDAV_SECRET,
            'webdav_passwd': webdav_passwd,
    }

    if has_two_factor_auth():
        from restapi.two_factor.models import StaticDevice, default_device

        try:
            backup_tokens = StaticDevice.objects.get(
                user=request.user.username).token_set.count()
        except StaticDevice.DoesNotExist:
            backup_tokens = 0

        resp_dict['default_device'] = default_device(request.user)
        resp_dict['backup_tokens'] = backup_tokens

    return render(request, 'profile/set_profile.html', resp_dict)

@login_required
def user_profile(request, username):
    if is_valid_username(username):
        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
            user = None
    else:
        user = None

    if user is not None:
        nickname = email2nickname(user.username)
        contact_email = Profile.objects.get_contact_email_by_user(user.username)
        d_profile = DetailedProfile.objects.get_detailed_profile_by_user(
            user.username)
    else:
        nickname = ''
        contact_email = ''
        d_profile = None

    return render(request, 'profile/user_profile.html', {
            'user': user,
            'nickname': nickname,
            'contact_email': contact_email,
            'd_profile': d_profile,
            })

@login_required
def get_user_profile(request, user):
    data = {
            'email': user,
            'user_nickname': '',
            'user_intro': '',
            'err_msg': '',
            'new_user': ''
        }
    content_type = 'application/json; charset=utf-8'

    try:
        user_check = User.objects.get(email=user)
    except User.DoesNotExist:
        user_check = None

    if user_check:
        profile = Profile.objects.filter(user=user)
        if profile:
            profile = profile[0]
            data['user_nickname'] = profile.nickname
            data['user_intro'] = profile.intro
    else:
        data['user_intro'] = _(u'Has not accepted invitation yet')

    if user == request.user.username or \
            Contact.objects.filter(user_email=request.user.username,
                                   contact_email=user).count() > 0:
        data['new_user'] = False
    else:
        data['new_user'] = True

    return HttpResponse(json.dumps(data), content_type=content_type)

@login_required
def delete_user_account(request):
    if request.method != 'POST':
        raise Http404

    username = request.user.username

    if username == 'demo@syncwerk.com':
        messages.error(request, _(u'Demo account can not be deleted.'))
        next = request.META.get('HTTP_REFERER', settings.SITE_ROOT)
        return HttpResponseRedirect(next)

    user = User.objects.get(email=username)
    user.delete()

    if is_org_context(request):
        org_id = request.user.org.org_id
        synserv.ccnet_threaded_rpc.remove_org_user(org_id, username)

    return HttpResponseRedirect(settings.LOGIN_URL)

@login_required
def default_repo(request):
    """Handle post request to create default repo for user.
    """
    if request.method != 'POST':
        raise Http404

    repo_id = request.POST.get('dst_repo', '')
    referer = request.META.get('HTTP_REFERER', None)
    next = settings.SITE_ROOT if referer is None else referer

    repo = syncwerk_api.get_repo(repo_id)
    if repo is None:
        messages.error(request, _('Failed to set default library.'))
        return HttpResponseRedirect(next)

    if repo.encrypted:
        messages.error(request, _('Can not set encrypted library as default library.'))
        return HttpResponseRedirect(next)

    username = request.user.username
    UserOptions.objects.set_default_repo(username, repo.id)
    messages.success(request, _('Successfully set "%s" as your default library.') % repo.name)
    return HttpResponseRedirect(next)
