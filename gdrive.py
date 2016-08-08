import os
import errno
import argparse
import hashlib
import json
import httplib2

import oauth2client
from oauth2client import client
from oauth2client import tools

from apiclient import discovery
from googleapiclient.http import MediaIoBaseDownload

AUTH = {
    'scopes': 'https://www.googleapis.com/auth/drive',
    'client_secret_file': 'client_secret.json',
    'application_name': 'Drive API Quickstart'
}

def get_credentials():
    """
    Gets valid user credentials from storage.
    If nothing has been stored, or if the stored credentials are invalid,
    the OAuth2 flow is completed to obtain the new credentials.
    Returns:
        Credentials, the obtained credential.
    """
    home_dir = os.path.expanduser('~')
    credential_dir = os.path.join(home_dir, '.credentials')
    if not os.path.exists(credential_dir):
        os.makedirs(credential_dir)
    credential_path = os.path.join(credential_dir,
                                   'drive-quickstart.json')

    store = oauth2client.file.Storage(credential_path)
    credentials = store.get()
    flags = argparse.ArgumentParser(parents=[tools.argparser]).parse_args()

    if not credentials or credentials.invalid:
        flow = client.flow_from_clientsecrets(AUTH['client_secret_file'], AUTH['scopes'])
        flow.user_agent = AUTH['application_name']
        credentials = tools.run_flow(flow, store, flags)
        print('Storing credentials to ' + credential_path)
    return credentials


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def is_folder(item):
    return item['mimeType'] == "application/vnd.google-apps.folder"

def is_downloadable(item):
    return 'downloadUrl' in item

def delete_file(service, file_id):
    return service.files().delete(fileId=file_id).execute()

def trash_file(service, file_id):
    return service.files().trash(fileId=file_id).execute()

def file_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as desc:
        for chunk in iter(lambda: desc.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def download_file(service, item, download_folder='./data/', overwrite=False):
    if not is_downloadable(item):
        return False

    local_path = download_folder + item['path']

    if os.path.isfile(local_path) and not overwrite:
        if file_md5(local_path) == item['md5Checksum']:
            return False
        else:
            print("Corrupt file '%s'" % local_path)

    mkdir_p(os.path.dirname(local_path))

    with open(local_path, "wb") as destination:
        request = service.files().get_media(fileId=item['id'])
        downloader = MediaIoBaseDownload(destination, request)
        done = False

        while done is False:
            _, done = downloader.next_chunk()

    if file_md5(local_path) != item['md5Checksum']:
        raise Exception("Download for '%s' failed, wrong checksum" % local_path)

    return True

def rreplace(string, find, replace, max_replaces=1):
    pieces = string.rsplit(find, max_replaces)
    return replace.join(pieces)

def files_with_parent(service, parent, max_depth=None, depth=0, path=None):
    if parent is None:
        if depth == 0:
            return parent
        else:
            return []

    if depth == 0:
        path = parent['title'] + '/'

    query = "'%s' in parents" % parent['id']
    items = get_all_files(service, query)

    if not items:
        if depth == 0:
            return parent
        else:
            return []

    result = []

    for item in items:
        if is_folder(item) and (max_depth is None or depth < max_depth):
            new_path = path + item['title'] + '/'
            item['children'] = files_with_parent(service, item, max_depth, depth + 1, new_path)

        item['path'] = path + item['title']
        result.append(item)

    if depth == 0:
        parent['children'] = result
        return parent

    return result

def print_tree(parent, ident='├── ', is_root=True):
    directories_count = 0
    files_count = 0
    downloadable_files_count = 0

    if parent is None:
        print('Nothing to print')
        return

    if is_root:
        print(parent['path'])

    if parent is None or 'children' not in parent:
        return

    items = parent['children']
    for item in items:
        if item == items[len(items) - 1]:
            ident = rreplace(ident, '├', '└')

        if is_folder(item):
            directories_count += 1
            print('{0}{1}'.format(ident, item['title']))

            if 'children' in item:
                if item == items[len(items) - 1]:
                    new_indent = rreplace(ident, '|   ', '    ')
                    new_indent = rreplace(new_indent, '└', '├')

                    if is_root:
                        new_indent = '    ' + new_indent
                    else:
                        new_indent = '|   ' + new_indent
                else:
                    new_indent = '|   ' + ident

                new_counts = print_tree(item, new_indent, False)

                directories_count += new_counts[0]
                files_count += new_counts[1]
                downloadable_files_count += new_counts[2]
        else:
            files_count += 1

            if is_downloadable(item):
                downloadable_files_count += 1

            print('{0}{1}'.format(ident, item['title']))

    if is_root:
        print('\n%d directories, %d files, %d downloadable files' % \
                (directories_count, files_count, downloadable_files_count))

    return (directories_count, files_count, downloadable_files_count)

def get_permission_id(service, email):
    return service.permissions()\
                .getIdForEmail(email=email)\
                .execute()['id']

def remove_permission_with_id(service, file_id, permission_id):
    return  service \
                .permissions() \
                .delete(fileId=file_id, permissionId=permission_id) \
                .execute()

def remove_permission_with_email(service, file_id, email):
    permissions = get_file_permissions(service, file_id)
    for permission in permissions:
        if 'emailAddress' in permission and permission['emailAddress'] == email:
            remove_permission_with_id(service, file_id, permission['id'])

def share_with(service, file_id, email, role='writer', send_notification_emails=False):
    body = {}
    body['type'] = 'user'
    body['role'] = role
    body['value'] = email

    return service.permissions()\
                .insert(fileId=file_id,\
                        sendNotificationEmails=send_notification_emails,\
                        body=body)\
                .execute()

def make_owner(service, file_id, owner_id):
    body = {}
    body['role'] = 'owner'
    return service.permissions()\
                  .update(fileId=file_id,\
                          permissionId=owner_id,
                          body=body, transferOwnership='true')\
                  .execute()

def get_service():
    credentials = get_credentials()

    if not credentials:
        print('Authentication failed')
        return

    http = credentials.authorize(httplib2.Http())
    return discovery.build('drive', 'v2', http=http)

def apply_function(item, apply_to_file, apply_to_folder, function):
    if is_folder(item):
        if apply_to_folder:
            function(item)
    elif apply_to_file:
        function(item)

def for_each_file(item, apply_to_file, apply_to_folder, function, reverse=True):
    if item is None:
        return

    if not reverse:
        apply_function(item, apply_to_file, apply_to_folder, function)

    if 'children' in item:
        for child in item['children']:
            for_each_file(child, apply_to_file, apply_to_folder, function, reverse)

    if reverse:
        apply_function(item, apply_to_file, apply_to_folder, function)

def file_from_path(service, path, depth=0, parent=None):
    path_files = path.split('/')
    path_to_folder = path_files[len(path_files) - 1] == ''

    file_name = path_files[depth]
    query = "title = '%s'" % file_name

    if depth + 1 != len(path_files) or path_to_folder:
        query += " and mimeType = 'application/vnd.google-apps.folder'"

    if not parent:
        query += " and 'root' in parents"
    else:
        query += " and '%s' in parents" % parent

    result = service.files()\
                    .list(q=query, spaces='drive')\
                    .execute()\
                    .get('items', [])

    if len(result) > 1:
        raise Exception("File search for '%s', path '%s' returned more than one result" %
                        (file_name, path))

    if not len(result):
        return None

    if depth + 1 == len(path_files) or (path_to_folder and depth + 2 == len(path_files)):
        item = result[0]
        item['path'] = path.strip('/')
        return item

    return file_from_path(service, path, depth + 1, result[0]['id'])

def get_all_files(service, query=None):
    result = []
    page_token = None

    while True:
        params = {
            'maxResults': 1000
        }

        if query:
            params['q'] = query

        if page_token:
            params['pageToken'] = page_token

        files = service.files().list(**params).execute()

        result.extend(files['items'])
        page_token = files.get('nextPageToken')

        if not page_token:
            break
    return result

def get_file_permissions(service, file_id):
    permissions = service.permissions().list(fileId=file_id).execute()
    return permissions.get('items', [])

def change_owner_remove_access_item(service, old_owner_email, new_owner_email, new_owner_id, item):
    print(item['title'])

    if item['owners'][0]['emailAddress'] == old_owner_email:
        if is_downloadable(item):
            download_file(service, item)
            trash_file(service, item['id'])
        else:
            share_with(service, item['id'], new_owner_email)
            make_owner(service, item['id'], new_owner_id)
            remove_permission_with_id(service, item['id'], item['owners'][0]['permissionId'])
    else:
        remove_permission_with_email(service, item['id'], old_owner_email)

def change_owner_remove_access(service, root_path, old_owner_email, new_owner_email):
    root = file_from_path(service, root_path)
    root = files_with_parent(service, root)

    print_tree(root)

    new_owner_id = get_permission_id(service, new_owner_email)
    for_each_file(root, True, True, lambda item: change_owner_remove_access_item(service, \
                         old_owner_email, new_owner_email, new_owner_id, item))

def add_orphan_items_to_folder(service, folder_path):
    folder = file_from_path(service, folder_path)

    items = get_all_files(service, 'trashed = false')
    print('Total files count %d' % len(items))

    orphan_count = 0
    for item in items:
        if not len(item['parents']):
            orphan_count += 1

    print('Orphan files count %d' % orphan_count)

    for item in items:
        if not len(item['parents']):
            print(item['title'])
            add_to_my_drive(service, item['id'], folder['id'])

def add_to_my_drive(service, file_id, folder_id):
    return service.parents().insert(fileId=file_id, body={'id': folder_id}).execute()

def add_file_to_folder(service, item, folder_id):
    return service.files().update(
        fileId=item['id'],
        addParents=folder_id,
        removeParents=item['parents']).execute()

def json_pretty_print(data):
    print(json.dumps(data, indent=2))