import copy
import json
from pprint import pprint

import requests

from config import graph_api_host, graph_api_port
from evaluation.get_dep_tree import get_cve
from utils.db_utils import get_all_versions

def get_unreachable_fewest_vul_vers(gav, c, vul_versions):
    g, a, v = gav.split('|')
    # All versions are vulnerable
    maven = c['library-crawler']['maven']
    body = {
        "name": a,
        "vendor": g,
        "version": v,
        "platform": "maven"
    }
    least_cves = 999
    least_cve_vers = set()
    for ver in vul_versions:
        current_cve = len(get_cve(g + '|' + a + '|' + ver))
        if current_cve < least_cves:
            least_cve_vers = set()
            least_cve_vers.add(ver)
            least_cves = current_cve
        elif current_cve == least_cves:
            least_cve_vers.add(ver)
    return least_cve_vers


def get_vul_versions(gav, c, clean_versions):
    g, a, v = gav.split('|')
    maven = c['library-crawler']['maven']
    all_versions = set(get_all_versions(g + '|' + a, maven))
    return all_versions-clean_versions


def get_edges_from_deptree(deptree, root):
    def get_gav(d):
        return d['libraryVendor']+'|'+d['libraryName']+'|'+d['version']
    ret = []
    visited = set()
    breadth = deptree['dependenciesList']
    for dirct in breadth:
        ret.append([root, get_gav(dirct)])
        visited.add(root+get_gav(dirct))

    while len(breadth)>0:
        tmp = [*breadth]
        breadth = []
        for lib in tmp:
            for dep in lib['dependenciesList']:
                if get_gav(lib) + get_gav(dep) in visited:
                    continue
                ret.append([get_gav(lib), get_gav(dep)])
                visited.add(get_gav(lib) + get_gav(dep))
                breadth.extend(lib['dependenciesList'])
    return ret


def get_dependency_tree(directs, c):
    maven = c['library-crawler']['maven']
    body =[]
    unfound = []
    for gav in directs:
        g, a, v = gav.split('|')
        # if not maven.find_one({'group': g, 'artifact': a, 'version': v}):
        #     unfound.append(gav)
        #     continue
        body.append({
            "name": a,
            "vendor": g,
            "version": v,
            "platform": "maven"
        })
    response = requests.post(f'http://{graph_api_host}:{graph_api_port}/allDependencies', json=body)
    if response.status_code == 200:
        try:
            return response.json()
        except:
            return {}
    else:
        print(json.loads(response.content.decode())['errorMessage'])
        if 'Library Version not found' in json.loads(response.content.decode())['errorMessage']:
            pgav = json.loads(response.content.decode())['errorMessage'].replace('Library Version not found: ', '')
            error_gav = pgav.replace('maven:', '').replace(':', '|')
            body = []
            for gav in directs:
                if gav == error_gav:
                    continue
                g, a, v = gav.split('|')
                body.append({
                    "name": a,
                    "vendor": g,
                    "version": v,
                    "platform": "maven"
                })
            response = requests.post(f'http://{graph_api_host}:{graph_api_port}/allDependencies', json=body)
            if response.status_code == 200:
                try:
                    return response.json()
                except:
                    return {}
        return {}


def get_clean_versions(gav, c):
    g, a, v = gav.split('|')
    body = {
        "name": a,
        "vendor": g,
        "version": v,
        "platform": "maven"
    }
    response = requests.post(f'http://{graph_api_host}:{graph_api_port}/cleanVers', json=body)
    if response.status_code == 200:
        res = set(each['version'] for each in response.json())
        if response.json()==[]:
            response = requests.post(f'http://{graph_api_host}:{graph_api_port}/issues', json=body)
            if response.status_code == 200:
                if response.json() != []:
                    # All vers vul
                    return set()
                else:
                    return set({v})
            else:
                return res
        else:
            return res
    else:
        return set()

def get_issues(item):
    '''
        Called after check_issues_input. At this stage, expect the input to be
        properly formatted. Results are also formatted before returning.
    '''
    session = requests.Session()
    session.trust_env = False


    result_item = dict(item)
    # scan_id = item['scan_id'] if 'scan_id' in item else 'EMPTY_SCAN_ID'
    # g,a,v = item.split('|')
    issues_api_input = {
        'platform': 'maven',
        'vendor': item['vendor'],
        'name': item['name'],
        'version': item['version'],
        'scan_id': 0
    }
    # Get issues in the default dependency tree
    res = session.post(f'http://{graph_api_host}:{graph_api_port}/issues',
                       json=issues_api_input)
    if res.status_code == 404:
        res = {}
    else:
        res = res.json()
    # Format and add the issues to the result
    result_item['issues'] = format_issues_result_list(res)
    return result_item

def format_issues_result_list(items):
    '''
        Formats the result of the issues core API to the expected format.
        Returns an empty list if something cannot be properly formatted.
    '''
    formatted_results = []
    try:
        for item in items:
            formatted = {
                'artifact_id': item['libraryVersion']['libraryName'],
                'group_id': item['libraryVersion']['libraryVendor'],
                'platform': item['libraryVersion']['libraryPlatform'],
                'language': 'java',
                'version': item['libraryVersion']['version'],
                'public_id': item['issue'],
                'scan_issue_id': 0 # Dummy value
            }
            formatted_results.append(formatted)
    except Exception as e:
        print('[ERROR] Graph api formatting:', e)
    return formatted_results

def get_remediation(d):
    '''
    Called after check_remediation_input. At this stage,
    expect the input to be properly formatted. Results are also
    formatted before returning.
    {
        "scan_id": "12345",
        "dependency_list": [
            {
                "artifact_id": "rails",
                "group_id": "",
                "version": "5.2.3",
                "platform": "Rubygem",
                "language": "Ruby",
                "issues": [
                    {
                        "group_id": "",
                        "artifact_id": "",
                        "version": "",
                        "public_id": ""
                    }
                ]
            }
        ]
    }
    '''
    results = []
    if isinstance(d, dict):
        scan_id = d['scan_id'] if 'scan_id' in d else "EMPTY_SCAN_ID"
        data = d['dependency_list']
    elif isinstance(d, list):
        scan_id = "EMPTY_SCAN_ID"
        data = d
    session = requests.Session()
    session.trust_env = False
    dependency_api_input = []
    all_issues = []
    for item in data:
        g,a,v = item.split('|')
        issue_input = {
            'platform': 'maven',
            'vendor': g,
            'name': a,
            'version': v,
            'scan_id': scan_id
        }

        each_issues = get_issues(issue_input)
        all_issues.append(each_issues)
    # print(dependency_api_input)
    # dependencies_list = get_unique_dependencies_coordinates(dependency_result, scan_id)

        # Get fix version for each issue
    for item in all_issues:
        fix_input_list = list(map(lambda issue: {
            'platform': 'maven',
            'vendor': issue['group_id'],
            'name': issue['artifact_id'],
            'version': issue['version'],
            'issue': issue['public_id'],
            'scan_id': scan_id
        }, item['issues']))
        fix_result = session.post(f'http://{graph_api_host}:{graph_api_port}/fix',
                                  json=fix_input_list).json()
        # Append fix version result to the final result object
        result_item = dict(item)
        result_item['issues'] = []
        if len(item['issues']) == len(fix_result):
            for fix_input, fix_output in zip(item['issues'], fix_result):
                # child_coordinate = make_library_version_coordinates(fix_input)
                # child_exists = child_coordinate in dependencies_list
                # print(child_exists, child_coordinate)
                res_obj = copy.copy(fix_input)
                res_obj['fix_version'] = fix_output['fixVersion']
                # res_obj['error'] = ("Dependency version does not exist in default tree" if not child_exists
                #                     else fix_output['error'])
                result_item['issues'].append(res_obj)

            # Get recommended fix version for the root node
            remediation_api_input = {
                'platform': 'maven',
                'vendor': item['vendor'],
                'name': item['name'],
                'version': item['version'],
                'scan_id': scan_id
            }
            res = session.post(f'http://{graph_api_host}:{graph_api_port}/remediation',
                               json=remediation_api_input).json()

            result_item['recommendation'] = format_remediation_result_item(res, scan_id)

        results.append(result_item)

    return results

def format_remediation_result_item(result, scan_id):
    '''
    Formats the result of the remediation core API to the expected format.
    Returns None if something cannot be properly formatted.
    '''

    formatted_result = {}
    try:
        formatted_result = {
            'version': result['remediationVersion']['version'],
            'type': result['remediationType'],
            'issue_count': int(result['numVulnerabilities']),
            'issues_in_version': result['vulnerabilities']
        }
    except Exception as e:
        print('[ERROR] Scantist graph api error',  e)
        return {}
    return formatted_result


def test_scantist():
    gav = 'io.netty|netty-all|4.0.36.Final'
    # g,a,v = gav.split(':')
    d = [gav]
    pprint(get_remediation(d))