import logging



from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response
from restapi.api3.throttling import UserRateThrottle

from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.permissions import IsAdminUser

from restapi.utils import is_org_context, get_user_repos
from restapi.wiki.models import Wiki, DuplicateWikiNameError
from restapi.wiki.utils import is_valid_wiki_name, slugfy_wiki_name
from restapi.utils.repo import is_group_repo_staff
from restapi.views import check_folder_permission
from restapi.share.utils import is_repo_admin
from restapi.api3.utils.wiki import (clean_page_name, get_wiki_pages, get_inner_file_url,
                               get_wiki_dirent, get_wiki_page_object, get_wiki_dirs_by_path)

from synserv import syncwerk_api, edit_repo,get_file_id_by_path 

from django.db import IntegrityError
from pyrpcsyncwerk import RpcsyncwerkError

from django.utils.translation import ugettext as _

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class WikisView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get list wiki',
        operation_description='''Get current user wiki list''',
        tags=['wikis'],
        manual_parameters=[
            openapi.Parameter(
                name='type',
                in_='query',
                type='string',
                description='''- mine: only get wikis that the user is the owner \n
- shared: only get wikis that shared to the user \n
- group: only get wikis that belongs to the group that the user is in\n
- org: only get wikis that belongs to the organization that the user is in.\n
    
If not provided, then get all of the above''',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Wiki list retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "updated_at": "2019-02-01T02:37:29+00:00",
                                "owner_nickname": "admin",
                                "link": "https://alpha.syncwerk.com/rest/wikis/test-wiki/",
                                "name": "test wiki",
                                "permission": "private",
                                "owner": "admin@alpha.syncwerk.com",
                                "created_at": "2019-02-01T02:06:00+00:00",
                                "id": 1,
                                "slug": "test-wiki"
                            },
                            {
                                "updated_at": "2019-02-01T02:14:46+00:00",
                                "owner_nickname": "admin",
                                "link": "https://alpha.syncwerk.com/rest/wikis/test-wiki-2/",
                                "name": "test wiki 2",
                                "permission": "private",
                                "owner": "admin@alpha.syncwerk.com",
                                "created_at": "2019-02-01T02:14:45+00:00",
                                "id": 2,
                                "slug": "test-wiki-2"
                            },
                            {
                                "updated_at": "2019-02-18T03:42:14+00:00",
                                "owner_nickname": "admin",
                                "link": "https://alpha.syncwerk.com/rest/wikis/test-wiki-4/",
                                "name": "test wiki 4",
                                "permission": "private",
                                "owner": "admin@alpha.syncwerk.com",
                                "created_at": "2019-02-01T02:21:39+00:00",
                                "id": 4,
                                "slug": "test-wiki-4"
                            }
                        ]
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": 'Token invalid'
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error',
                examples={
                    'application/json': {
                        "message": "Internal server error",
                        "data": None
                    }
                }
            ),
        }
    )
    def get(self, request, format=None):
        """List all wikis.
        """
        # parse request params
        filter_by = {
            'mine': False,
            'shared': False,
            'group': False,
            'org': False,
        }

        rtype = request.GET.get('type', "")
        if not rtype:
            # set all to True, no filter applied
            filter_by = filter_by.fromkeys(filter_by.iterkeys(), True)

        for f in rtype.split(','):
            f = f.strip()
            filter_by[f] = True

        username = request.user.username
        org_id = request.user.org.org_id if is_org_context(request) else None
        (owned, shared, groups, public) = get_user_repos(username, org_id)

        filter_repo_ids = []
        if filter_by['mine']:
            filter_repo_ids += ([r.id for r in owned])

        if filter_by['shared']:
            filter_repo_ids += ([r.id for r in shared])

        if filter_by['group']:
            filter_repo_ids += ([r.id for r in groups])

        if filter_by['org']:
            filter_repo_ids += ([r.id for r in public])

        filter_repo_ids = list(set(filter_repo_ids))
        ret = [x.to_dict() for x in Wiki.objects.filter(
            repo_id__in=filter_repo_ids)]

        return api_response(data=ret)


    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Add a wiki',
        operation_description='''Add a new wiki''',
        tags=['wikis'],
        manual_parameters=[
            openapi.Parameter(
                name='name',
                in_='formData',
                type='string',
                description='name of the new wiki',
            ),
            openapi.Parameter(
                name='use_exist_repo',
                in_='formData',
                type='boolean',
                description='use an existing folder to create the repo. "name" should not be provided if this is true',
            ),
            openapi.Parameter(
                name='repo_id',
                in_='formData',
                type='boolean',
                description='if use_exist_repo is true, then this is the folder id of the folder to be used.',
            ),
        ],
        responses={
            200: openapi.Response(
                description='New wiki created successfully.',
                examples={
                    'application/json': {
                        "message": "New wiki created successfully",
                        "data": None
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": 'Token invalid'
                    }
                }
            ),
            403: openapi.Response(
                description='Operation not permitted',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            404: openapi.Response(
                description='Folder not found',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error',
                examples={
                    'application/json': {
                        "message": "Internal server error",
                        "data": None
                    }
                }
            ),
        }
    )
    def post(self, request, format=None):
        """Add a new wiki.
        """
        use_exist_repo = request.POST.get('use_exist_repo', '')
        if not use_exist_repo:
            msg = _('Use exist repo is invalid')
            return api_error(code=400, msg=msg)

        username = request.user.username

        org_id = -1
        if is_org_context(request):
            org_id = request.user.org.org_id
        
        if use_exist_repo == 'false':
            name = request.POST.get('name', '')
            if not name:
                msg = _('Name is invalid')
                return api_error(code=400, msg=msg)
            if not is_valid_wiki_name(name):
                msg = _('Name can only contain letters, numbers, blank, hyphen or underscore.')
                return api_error(code=400, msg=msg)
            try:
                wiki = Wiki.objects.add(name, username, org_id=org_id)
            except DuplicateWikiNameError:
                msg = _('%s is taken by others, please try another name.') % name
                return api_error(code=400, msg=msg)
            except IntegrityError:
                msg = 'Internal Server Error'
                return api_error(code=500, msg=msg)

            # create home page
            page_name = "home.md"
            try:
                syncwerk_api.post_empty_file(wiki.repo_id, '/',
                                            page_name, request.user.username)
            except RpcsyncwerkError as e:
                logger.error(e)
                msg = _('Internal Server Error')
                return api_error(code=500, msg=msg)

            return api_response(code=200, msg=_("New wiki created successfully")) 

        if use_exist_repo == 'true':
            repo_id = request.POST.get('repo_id', '')
            if not repo_id:
                msg = _('Repo id is invalid.')
                return api_error(code=400, msg=msg)

            repo = syncwerk_api.get_repo(repo_id)
            if not repo:
                error_msg = _('Library %s not found.') % repo_id
                return api_error(code=404, msg=error_msg)

            # repo owner
            is_repo_owner = syncwerk_api.is_repo_owner(username, repo_id)

            if not is_repo_owner:
                repo_admin = is_repo_admin(username, repo_id)

                if not repo_admin:
                    is_group_repo_admin = is_group_repo_staff(repo_id, username)

                    if not is_group_repo_admin:
                        error_msg = _('Permission denied.')
                        return api_error(code=403, msg=error_msg)

            try:
                wiki = Wiki.objects.add(wiki_name=repo.repo_name, username=username, 
                        repo_id=repo.repo_id, org_id=org_id)
            except DuplicateWikiNameError:
                msg = _('%s is taken by others, please try another name.') % repo.repo_name
                return api_error(code=400, msg=msg)
            except IntegrityError:
                msg = _('Internal Server Error')
                return api_error(code=500, msg=msg)

            # create home page if not exist
            page_name = "home.md"
            if not syncwerk_api.get_file_id_by_path(repo_id, "/" + page_name):
                try:
                    syncwerk_api.post_empty_file(repo_id, '/', page_name, username)
                except RpcsyncwerkError as e:
                    logger.error(e)
                    msg = _('Internal Server Error')
                    return api_error(code=500, msg=msg)

            return api_response(code=200, msg=_("New wiki created successfully")) 

class WikiView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Delete a wiki',
        operation_description='''Delete a wiki''',
        tags=['wikis'],
        manual_parameters=[
            openapi.Parameter(
                name='slug',
                in_='path',
                type='string',
                description='wiki slug',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Wiki removed successfully.',
                examples={
                    'application/json': {
                        "message": "Wiki deleted successfully",
                        "data": None
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": 'Token invalid'
                    }
                }
            ),
            403: openapi.Response(
                description='Operation not permitted',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            404: openapi.Response(
                description='Folder not found',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error',
                examples={
                    'application/json': {
                        "message": "Internal server error",
                        "data": None
                    }
                }
            ),
        }
    )
    def delete(self, request, slug):
        """Delete a wiki.
        """
        username = request.user.username
        try:
            owner = Wiki.objects.get(slug=slug).username
        except Wiki.DoesNotExist:
            error_msg = _('Wiki not found.')
            return api_error(code=404, msg=error_msg)
        if owner != username:
            error_msg = _('Permission denied.')
            return api_error(code=403, msg=error_msg)

        Wiki.objects.filter(slug=slug).delete()

        return api_response(code=200, msg=_("Wiki removed successfully."))
    
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Rename a wiki',
        operation_description='''Rename a wiki''',
        operation_id='wiki_rename',
        tags=['wikis'],
        manual_parameters=[
            openapi.Parameter(
                name='slug',
                in_='path',
                type='string',
                description='wiki slug',
            ),
            openapi.Parameter(
                name='wiki_name',
                in_='formData',
                type='string',
                description='new name for the wiki',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Wiki renamed successfully.',
                examples={
                    'application/json': {
                        "message": "Wiki renamed successfully",
                        "data": None
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": 'Token invalid'
                    }
                }
            ),
            403: openapi.Response(
                description='Operation not permitted',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            404: openapi.Response(
                description='Folder not found',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error',
                examples={
                    'application/json': {
                        "message": "Internal server error",
                        "data": None
                    }
                }
            ),
        }
    )
    def post(self, request, slug):
        """Rename a Wiki
        """
        username = request.user.username

        try:
            wiki = Wiki.objects.get(slug=slug)
        except Wiki.DoesNotExist:
            error_msg = _("Wiki not found.")
            return api_error(code=404, msg=error_msg)

        if wiki.username != username:
            error_msg = _("Permission denied.")
            return api_error(code=403, msg=error_msg)

        wiki_name = request.POST.get('wiki_name', '')
        if not wiki_name:
            error_msg = _('Name is required.')
            return api_error(code=400, msg=error_msg)

        if not is_valid_wiki_name(wiki_name):
            msg = _('Name can only contain letters, numbers, blank, hyphen or underscore.')
            return api_error(code=400, msg=msg)

        wiki_slug = slugfy_wiki_name(wiki_name)

        wiki_exist = Wiki.objects.filter(slug=wiki_slug)
        if wiki_exist.exists():
            msg = _('%s is taken by others, please try another name.') % wiki_name
            return api_error(code=400, msg=msg)

        if edit_repo(wiki.repo_id, wiki_name, '', username):
            wiki.slug = wiki_slug
            wiki.name = wiki_name
            wiki.save()
        else:
            return api_error(code=500,
                             msg=_("Unable to rename wiki"))

        return api_response(code=200, msg=_("Rename wiki successfully."))

class WikiPagesView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get wiki pages',
        operation_description='''Get all pages of a wiki''',
        tags=['wikis'],
        manual_parameters=[
            openapi.Parameter(
                name='slug',
                in_='path',
                type='string',
                description='wiki slug',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Wiki pages retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "updated_at": "2019-02-01T02:37:29+00:00",
                            "pages": [
                                {
                                    "last_modifier_name": "admin",
                                    "last_modifier": "admin@alpha.syncwerk.com",
                                    "repo_id": "32c13cd4-3752-46bc-b1cf-cff4d50a671f",
                                    "link": "https://alpha.syncwerk.com/rest/wikis/test-wiki/home",
                                    "name": "home",
                                    "file_edit_link": "https://alpha.syncwerk.com/rest/repo/32c13cd4-3752-46bc-b1cf-cff4d50a671f/file/edit/?p=/home.md",
                                    "last_modifier_contact_email": "admin@alpha.syncwerk.com",
                                    "file_link": "http://127.0.0.1:8082/files/eead6eb8-17c0-41af-aaf8-2bc477281058/home.md",
                                    "file_path": "/home.md",
                                    "updated_at": "2019-02-01T02:37:29+00:00"
                                }
                            ],
                            "owner_nickname": "admin",
                            "link": "https://alpha.syncwerk.com/rest/wikis/test-wiki/",
                            "name": "test wiki",
                            "permission": "private",
                            "owner": "admin@alpha.syncwerk.com",
                            "created_at": "2019-02-01T02:06:00+00:00",
                            "id": 1,
                            "slug": "test-wiki"
                        }
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": 'Token invalid'
                    }
                }
            ),
            403: openapi.Response(
                description='Operation not permitted',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            404: openapi.Response(
                description='Folder not found',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error',
                examples={
                    'application/json': {
                        "message": "Internal server error",
                        "data": None
                    }
                }
            ),
        }
    )
    def get(self, request, slug):
        """List all pages in a wiki.
        """
        from django.utils.translation import ugettext as _
        try:
            wiki = Wiki.objects.get(slug=slug)
            error_msg = _('Wiki not found.')
        except Wiki.DoesNotExist:
            error_msg = _('Wiki not found.')
            return api_error(code=404, msg=error_msg)

        # perm check
        if not wiki.has_read_perm(request.user):
            error_msg = _("Permission denied")
            return api_error(code=403, msg=error_msg)

        try:
            repo = syncwerk_api.get_repo(wiki.repo_id)
            if not repo:
                error_msg = _("Wiki library not found.")
                return api_error(code=404, msg=error_msg)
        except RpcsyncwerkError:
            error_msg = _("Internal Server Error")
            return api_error(code=500, msg=error_msg)

        pages = get_wiki_pages(repo)
        wiki_pages_object = []
        for _, page_name in pages.iteritems():
            wiki_page_object = get_wiki_page_object(wiki, page_name)
            wiki_pages_object.append(wiki_page_object)

        # sort pages by name
        wiki_pages_object.sort(lambda x, y: cmp(x['name'].lower(),
                                                y['name'].lower()))

        wiki_obj = wiki.to_dict()
        wiki_obj['pages']=wiki_pages_object

        return api_response(code=200, data=wiki_obj)
    
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Add wiki page',
        operation_description='''Get a new page to wiki''',
        tags=['wikis'],
        manual_parameters=[
            openapi.Parameter(
                name='slug',
                in_='path',
                type='string',
                description='wiki slug',
            ),
            openapi.Parameter(
                name='name',
                in_='formData',
                type='string',
                description='page name',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Wiki pages created successfully.',
                examples={
                    'application/json': {
                        "message": "Page created successfully",
                        "data": None
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": 'Token invalid'
                    }
                }
            ),
            403: openapi.Response(
                description='Operation not permitted',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            404: openapi.Response(
                description='Folder not found',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error',
                examples={
                    'application/json': {
                        "message": "Internal server error",
                        "data": None
                    }
                }
            ),
        }
    )
    def post(self, request, slug):
        """ Add a page in a wiki
        """
        try:
            wiki = Wiki.objects.get(slug=slug)
        except Wiki.DoesNotExist:
            error_msg = _("Wiki not found.")
            return api_error(code=404, msg=error_msg)

        # perm check
        username = request.user.username
        if wiki.username != username:
            error_msg = _('Permission denied.')
            return api_error(code=403, msg=error_msg)

        page_name = request.POST.get('name', '')
        if not page_name:
            error_msg = _('name invalid')
            return api_error(code=400, msg=error_msg)

        page_name = clean_page_name(page_name)
        filename = page_name + ".md"
        filepath = "/" + page_name + ".md"

        try:
            repo = syncwerk_api.get_repo(wiki.repo_id)
            if not repo:
                error_msg = _("Wiki library not found.")
                return api_error(code=404, msg=error_msg)
        except RpcsyncwerkError:
            error_msg = _("Internal Server Error")
            return api_error(code=500, msg=error_msg)

        # check whether file exists
        if get_file_id_by_path(repo.id, filepath):
            error_msg = _('Page "%s" already exists.') % filename
            return api_error(code=400, msg=error_msg)

        try:
            syncwerk_api.post_empty_file(repo.id, '/',
                                        filename, request.user.username)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = _('Internal Server Error')
            return api_error(code=500, msg=error_msg)

        wiki_page_object = get_wiki_page_object(wiki, page_name)

        return api_response(code=200, data=wiki_page_object)