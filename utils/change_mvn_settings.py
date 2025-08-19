import pymongo
import requests
import os
from reachable_incompatibilities_no_entry import reachability
from config import MONGO_HOST, MONGO_PORT

def sort(versionlist):
    session = requests.Session()
    res = session.post(f'http://localhost:8080/sort', data={'versionlist': versionlist})
    res.raise_for_status()
    session.close()

    return res.content.decode().split("|")

def get_verisons(group, artifact):
    ret = []
    mongo_connection = pymongo.MongoClient(MONGO_HOST,
                port =MONGO_PORT)
    maven = mongo_connection['library-crawler']['maven']
    docs =maven.find({'group': group, 'artifact':artifact})
    if docs:
        for doc in docs:
            ret.append(doc['version'])
    return ret

def change(pom_path, old_version, new_version):
    os.system(f'sed -i -E "s/{old_version}/{new_version}/" {pom_path}')

def change_back(pom_path, old_version, new_version):
    os.system(f'sed -i -E "s/{new_version}/{old_version}/" {pom_path}')

def attempt_all_versions(pom_path, old_version, group, artifact):
    versions = get_verisons(group, artifact)
    versions = sort('|'.join(versions))
    res = {}
    for new_version in versions[versions.index(old_version)+1:]:
        change(pom_path, old_version, new_version)
        count = reachability()
        res[new_version] = count
        change_back(pom_path, old_version, new_version)

    print(res)
if __name__ == '__main__':
    pom_path = '/Users/lyuye/workspace/remediation/ironjacamar2/web/pom.xml'
    old_version = '9.4.41.v20210516'
    group = 'org.eclipse.jetty'
    artifact = 'jetty-webapp'
    attempt_all_versions(pom_path, old_version, group, artifact)
