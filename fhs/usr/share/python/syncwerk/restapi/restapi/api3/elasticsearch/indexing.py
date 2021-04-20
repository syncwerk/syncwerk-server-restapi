from restapi.syncwerk_server_models.models import FolderBranch
from restapi.api3.models import ESIndexingHeader

from objectstorage import commit_mgr, fs_mgr, block_mgr
from objectstorage.commit_differ import CommitDiffer
from synserv import syncwserv_threaded_rpc, syncwerk_api, get_repo
import os
from fscrawler import FsCrawler
import tempfile
from es import es_delete, es_search
import magic
from searching import get_search_results
class Request(object):
    username="admin"
class Repo(object):
    id="acb2aaa6-e490-4cfa-a390-6f9e30e13f62"
fscrawl = FsCrawler()
def can_index(file):
    allowed = "Composite", "Document", "File", "V2", "Document", "Microsoft", "Word", "Microsoft", "Excel", "Microsoft", "PowerPoint", "PDF", "OpenDocument", "Text", "text"
    file_type = magic.from_file(file)
    for allowed_type in allowed:
        if allowed_type in file_type:
            return True
    return false

def start_indexing():
    # results = es_search("file1", {
    #     "repo_id": "acb2aaa6-e490-4cfa-a390-6f9e30e13f62",
    #     "parent_path": '/'
    # })
    # results = get_search_results(Request(), Repo(), '/', '', 'file1')
    # print(results)
    all_folders = FolderBranch.objects.all()
    for folder in all_folders:
        indexing_root_id = '0000000000000000000000000000000000000000'
        commit_id = folder.commit_id
        repo_id = folder.repo_id
        try:
            indexing_header = ESIndexingHeader.objects.get(repo_id=repo_id)
            print(commit_id, indexing_header.indexed_head_id)
            if indexing_header.indexed_head_id == commit_id:
                continue
            else:
                indexing_root_id = commit_mgr.get_commit_root_id(indexing_header.repo_id, 1, indexing_header.indexed_head_id)
        except Exception:
            indexing_header = None
        repo_details = get_repo(repo_id)
        # repo_owner = syncwerk_api.get_repo_owner(repo_id)
        current_head_root_id = commit_mgr.get_commit_root_id(folder.repo_id, 1, folder.commit_id)
        # print(repo_details.name, repo_owner)
        # print(folder.repo_id, folder.commit_id, folder.name)
        # print(current_head_root_id)
        commit_differ_obj = CommitDiffer(repo_id, 1, indexing_root_id, current_head_root_id)
        ret_added_files, ret_deleted_files, ret_added_dirs, ret_deleted_dirs, modified_files, renamed_files, moved_files, renamed_dirs, moved_dirs = commit_differ_obj.diff()
        # print diffs, commit_id
        # for i in diffs[1]:
        #     print(i.__dict__)
        # list_file_to_scan = diffs[0] + diffs[4]
        # print(list_file_to_scan)
        for file_obj in ret_added_files + modified_files:
            file_path = file_obj.path
            file_name = os.path.basename(file_path)
            file_id = file_path.replace('/', '_')
            parent_path = os.path.dirname(file_path)
            print "NEW FILE:", file_id, file_name, file_path

            temp_fd, temp_path = tempfile.mkstemp()
            syncw_file = fs_mgr.load_syncwerk(repo_details.id, 1, file_obj.obj_id)
            for block in syncw_file.blocks:
                os.write(temp_fd, block_mgr.load_block(repo_details.id, 1, block))
            if can_index(temp_path):
                tags = {
                    "external" : {
                        "file_name" : file_name,
                        "repo_id" : repo_id,
                        "parent_path" : parent_path,
                    }
                }
                fscrawl.index_file(temp_path, file_name, file_id, tags)
            os.unlink(temp_path)

        for file_obj in ret_deleted_dirs + ret_deleted_files:
            file_path = file_obj.path
            file_name = os.path.basename(file_path)
            file_id = file_obj.path.replace('/', '_')
            print "Delete Directory/file:", file_id, file_name, file_path
            es_delete(file_id)

        for file_obj in ret_added_dirs:
            file_path = file_obj.path
            file_name = os.path.basename(file_path)
            file_id = file_obj.path.replace('/', '_')
            parent_path = os.path.dirname(file_path)
            print "Add Directory:", file_id, file_name, file_path
            tags = {
                "external": {
                    "file_name": file_name,
                    "repo_id": repo_id,
                    "parent_path": parent_path,
                }
            }
            fscrawl.index_dir(file_path, file_name, file_id, tags)

        if indexing_header is None:
            print("Creating ESIndexingHeader")
            new_indexing_header = ESIndexingHeader()
            new_indexing_header.repo_id = repo_id
            new_indexing_header.indexed_head_id = commit_id
            new_indexing_header.save()
        else:
            indexing_header.indexed_head_id = commit_id
            indexing_header.save()
