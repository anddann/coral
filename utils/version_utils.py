from collections import defaultdict

import requests
from config import semver_host, semver_port
from utils.db_utils import get_default_version, get_all_versions
def _sort(versionlist, session=None):
    versionlist = '|'.join(versionlist)
    if session == None:
        session = requests.session()
    res = session.post('http://' + semver_host + f':{semver_port}/sort', data={'versionlist': versionlist})

    res.raise_for_status()
    res = res.content.decode().split('|')
    res = [p.replace('\"', '').replace(' ', '+') for p in res]
    if res ==['']:
        res = []
    return res

def check_in_range(versionlist, range, session=None):
    ret = []
    with requests.Session() as session:
        for version in versionlist:
            res = session.get(f'http://{semver_host}:{semver_port}/checkinrange?version={version}&range={range}'\
                .replace(' ', '%20').replace('[', '%5B').replace(']', '%5D'))
            res.raise_for_status()
            session.close()
            if res.content.decode() == 'true':
                ret.append(version)
    return ret


def get_non_dev_vers(candidates, ori_ver):
    ret = []
    for candidate in candidates:
        if candidate == ori_ver:
            ret.append(candidate)
            continue
        if 'rc' in candidate.lower() or 'beta' in candidate.lower() or 'alpha' in candidate.lower() or 'milstone' in candidate.lower() or '-b' in candidate.lower():
            continue
        ret.append(candidate)
    if len(ret) ==0:
        return candidates
    return ret


def is_dev(candidate):
    if 'rc' in candidate.lower() or 'beta' in candidate.lower() or 'alpha' in candidate.lower() or 'milstone' in candidate.lower() or '-b' in candidate.lower():
        return True
    else:
        return False


def is_major(ver1, ver2):
    try:
        major1 = int(ver1.split('.')[0])
        major2 = int(ver2.split('.')[0])
        if major1== major2:
            return False
        else:
            return True
    except:
        return False

def get_upgrade_versions(original_version, versions):
    versions = _sort(versions)
    if original_version in versions:
        uppers = versions[versions.index(original_version):]
        lowers = versions[:versions.index(original_version)]
        return uppers, lowers
    else:
        versions.append(original_version)
        versions = _sort(versions)
        uppers = versions[versions.index(original_version):]
        lowers = versions[:versions.index(original_version)]
        return uppers, lowers

def get_minor_version(version):
    if version.count('.') == 2:
        ma, mi, pa = version.split('.')
        return mi
    elif version.count('.') == 1:
        ma, mi, = version.split('.')
        return mi
    return None



def get_non_major_vers(c, gav, candidates):
    g,a,v = gav.split('|')
    maven = c['library-crawler']['maven']
    versions = list()
    major = v.split('.')[0]
    all = []
    for doc in maven.find({
        'group': g,
        'artifact': a
    }):
        if doc['version'].split('.')[0] == major:
            versions.append(doc['version'])
        all.append(doc['version'])
    if len(versions)<1:
        versions = list(filter(lambda x: x in candidates, all))
    else:
        versions = list(filter(lambda x: x in candidates, versions))
    if len(versions) ==0:
        versions = list(filter(lambda x: x in candidates, all))

    return versions

def get_other_major_vers(c, gav, candidates):
    g,a,v = gav.split('|')
    maven = c['library-crawler']['maven']
    versions = list()
    major = v.split('.')[0]
    all = []
    for doc in maven.find({
        'group': g,
        'artifact': a
    }):
        if doc['version'].split('.')[0] != major:
            versions.append(doc['version'])
        all.append(doc['version'])
    if len(versions) ==0:
        versions = list(filter(lambda x: x in candidates, all))

    return versions

def get_closest_default(parent_node, dep_ga, dep_candidates, c):
    maven = c['library-crawler']['maven']
    maven_deps = c['library-crawler']['maven_deps']
    versions = _sort(get_all_versions(dep_ga, maven))
    min_distance = 1000
    ret = dep_candidates[-1]
    default = get_default_version(parent_node.get_preferred_gav(), dep_ga, maven_deps)
    # check semantic rules
    if '[' in default and ']' in default and ',' not in default:
        return default.replace('[', '').replace(']', '')
    # If the dep is not found
    if default == '':
        return dep_candidates[-1]
    if default not in versions:
        versions.append(default)
        versions = _sort(versions)
    for cand in dep_candidates:
        current_distance = abs(versions.index(default) - versions.index(cand))
        if current_distance < min_distance:
            min_distance = current_distance
            ret = cand
    return ret


def get_averaged_defaults(parent_nodes, dep_ga, dep_original_version, dep_candidates, c):
    maven = c['library-crawler']['maven']
    maven_deps = c['library-crawler']['maven_deps']
    defaults = []
    versions = get_all_versions(dep_ga, maven)
    min_distance = 1000
    ret = dep_candidates[-1]
    for parent_node in parent_nodes:
        default = get_default_version(parent_node.get_gav(), dep_ga, maven_deps)
        if default!= '':
            defaults.append(default.replace('-SNAPSHOT', ''))
        else:
            defaults.append(dep_original_version)
    versions.extend(defaults)
    versions = _sort(versions)

    for cand in dep_candidates:

        current_distance = sum([abs(versions.index(d) - versions.index(cand)) for d in defaults])
        if current_distance<min_distance:
            min_distance = current_distance
            ret = cand
    return ret




def get_least_deps_introducing_versions(c, gav, versions):
    """
    return list of lists [[least deps vers], [2nd least], [3rd...], ...]
    """
    g,a,v = gav.split('|')
    gav = gav.replace('|', ':')
    deps_size = {}
    ret = []
    ret2 = []
    maven_deps = c['library-crawler']['maven_deps']
    doc = maven_deps.find_one({'parent': gav})
    if doc:
        current_size = len(doc['dependencies'])
    else:
        return [list(versions)]
    for ver in versions:
        doc = maven_deps.find_one({'parent': g+':'+a+':'+ver})
        if doc:
            if len(doc['dependencies'])>current_size:
                ret2.append(ver)
            else:
                ret.append(ver)
        else:
            ret.append(ver)
    if len(ret)==0:
        return [ret2, ret2]
    return [ret, ret2]

def get_latest_version(g, a, c):
    maven = c['library-crawler']['maven']
    docs = maven.find({'group': g, 'artifact': a}).sort('_id', -1)
    v = None
    for doc in docs:
        v = doc['version']
        break
    return v


def split_version_list(versions):
    if len(versions)<=10:
        return {'other': versions}
    ret = defaultdict(list)
    # split by minor version
    groups_minor = defaultdict(list)
    for ver in versions:
        if '.' in ver:
            minor = ver.split('.')[0]+'.'+ver.split('.')[1]
            groups_minor[minor].append(ver)
        else:
            ret['other'].append(ver)

    # split by major version
    groups_major = defaultdict(list)
    # for ver in versions:
    #     if '.' in ver:
    #         major = ver.split('.')[0]
    #         groups_major[major].append(ver)
    #     else:
    #         ret['other'].append(ver)
    if len(groups_minor.keys())>len(groups_major.keys()):
        for key in groups_minor:
            ret[groups_minor[key][0]+'|'+groups_minor[key][-1]] = groups_minor[key]
    else:
        for key in groups_major:
            ret[groups_major[key][0]+'|'+groups_major[key][-1]] = groups_major[key]

    return ret


def sort_by_AST():
    pass



