import csv
import json
import re
import subprocess
from collections import defaultdict
from pprint import pprint
import os
# from download_all_jar import download_jar
from config import download_path, graph_api_port, graph_api_host, m2_path, working_dir
import sys
import requests
import logging

from pom_dep_extractor.extract_pom_dep import populate_dep

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

# inspect_paths = [
#     config.workspace+'/remediation/sortpom',
#     config.workspace+'/remediation/mall',
#     config.workspace+'/remediation/javaee-essentials-pom',
#     config.workspace+'/remediation/metasfresh-parent-legacy',
#     config.workspace+'/remediation/pom-manipulation-ext',
#     config.workspace+'/remediation/netty-example',
#     config.workspace+'/remediation/snyk-maven-plugin',
#     config.workspace+'/remediation/eclipse-external-annotations-m2e-plugin',
#     config.workspace+'/remediation/write-text-files-maven-plugin',
#     config.workspace+'/remediation/htmlcompressor-maven-plugin',
#     config.workspace+'/remediation/flexmojos-m2e-connector',
#     config.workspace+'/remediation/javaee-essentials-pom',
#     config.workspace+'/remediation/ironjacamar'
#
# ]
# inspect_paths = []
# testcases = '/root/testCases/'
# for folder in os.listdir(testcases):
#     inspect_paths.append(testcases+folder)



def serialize_subgraph(subgraph):
    ret = set()
    for edge in subgraph:
        ret.add(edge[0])
        ret.add(edge[1])
    return ret

def get_mvn_dep_tree(path, large_scale=False):
    pairs = []
    deps = {}
    ids = {}
    cwd = os.getcwd()
    os.chdir(path)
    logging.debug(path)
    if large_scale:
        with open(os.path.join(path, 'deptree.txt')) as f:
            output= f.read().split('\n')
    else:
        try:
            subprocess.check_output('mvn dependency:tree', stderr=subprocess.STDOUT, shell=True)
            output = subprocess.check_output('mvn dependency:tree -DoutputType=tgf', stderr=subprocess.STDOUT, shell=True).decode().split('\n')
        except Exception as e:
            raise RuntimeError('mvn dependency:tree error')
            logging.debug('mvn command error', e)
            os.chdir(cwd)
            return deps, pairs
    module_flag = True
    start = False

    edge_begin = False
    next_root = False
    root = ''
    for l in output:
        if not l.startswith('[INFO]'):
            continue
        res = re.search('--- dependency:.*:tree \(default-cli\) @ (.+) ---', l)
        if res:
            # only parse one, stop before next starts
            if deps!={}:
                break
            module = res.group(1)
            module_flag = True
            start = True
            edge_begin = False
            next_root = True
            continue
        if next_root and start:
            root = l.split(' ')[-1]
            root = root.replace(':jar', '').replace(':pom', '').replace(':war', '').replace(':bundle', '')\
                .replace(':rar', '').replace(':eclipse-plugin', '').replace(':', '|')
            if 'maven-plugin-api' not in root:
                root = root.replace('|maven-plugin', '')
            if root.count('|') == 3:
                gavsp = root.split('|')
                g, a, v = gavsp[0], gavsp[1], gavsp[3]
                root = g+'|'+a+'|'+v
            next_root = False
            id = l.split(' ')[1]
            ids[id] = root
            continue
        if '#' in l:
            start = False
            edge_begin = True
            continue
        if (not start and not edge_begin) or not module_flag:
            continue
        if '-----------' in l:
            edge_begin = False
        if edge_begin and l.count(' ')>2:
            _, src, dst, compile = l.split(' ')
            if compile =='test':
                continue
            if src in ids and dst in ids:
                pairs.append([ids[src], ids[dst]])
            continue
        if l=='[INFO] ':
            module_flag = False
            continue
        if start:
            # if 'pom' in l:
            #     continue
            tmp = l.split(' ')
            id = tmp[1]
            latter = tmp[2]
            #_, id, latter = l.split(' ')
            gav = latter.split(':')
            scope = gav[-1]
            v = gav[-2]
            if scope =='test':
                continue
            if len(gav)<4:
                # logging.debug('Special: '+ gav)
                continue
            g = gav[0]
            a = gav[1]

            # if gav[3].startswith('jdk'):
            #     v = gav[4]
            # else:
            #     v = gav[3]
            jar = gav[2]
            # print(g, a ,v)
            ids[id] = g+'|'+a+'|'+v
            deps[g+'|'+a+'|'+v] = {'jar': jar, 'type': type}
    print('Number of deps:', len(deps))
    os.chdir(cwd)
    return deps, pairs, root


def get_cve_from_file(gav):
    if not os.path.exists((working_dir+'vulnerabilities/vul_mapping.json')):

        with open(working_dir+'vulnerabilities/vul_edges_unique.csv') as f:
            mapping = defaultdict(list)
            for l in csv.reader(f):
                mapping[l[1]].append(l[0])
        with open(working_dir+'vulnerabilities/vul_mapping.json', 'w') as f:
            json.dump(mapping, f)
    else:
        mapping = json.load(open(working_dir+'vulnerabilities/vul_mapping.json'))
    g, a, v = gav.split('|')
    ret = mapping.get(g+':'+a+':'+v, [])
    return set(each for each in ret if 'SEC' not in each)

def get_cve(gav):
    g, a, v = str(gav).split('|')
    body = {
        "name": a,
        "vendor": g,
        "version": v.replace('-SNAPSHOT', ''),
        "platform": "maven"
    }
    response = requests.post(f'http://{graph_api_host}:{graph_api_port}/issue4one', json=body)
    if response.status_code == 200:
        return set(each for each in response.json() if 'SEC' not in each)
    else:
        print('[WARNING] Get issue exception', g, a, v)
        return set()

def get_cves(deps):
    ret = set()
    for gav in deps:
        # ret = ret.union(get_cve(gav))
        ret = ret.union(get_cve_from_file(gav))
    return ret

def get_cves_dict(deps):
    ret = {}
    for gav in deps:
        # cves = get_cve(gav)
        cves = get_cve_from_file(gav)
        if len(cves)!=0:
            ret[gav] = cves
    return ret

def get_default_gavs(edges, edges2, maven_deps, root):
    """
    return default dict : {parent: [new, old]}
    """
    defaults = defaultdict(list)
    for edge in edges2:
        src = edge[0]
        dst = edge[1]
        if src == root:
            for ed in edges:
                if ed[0]==src:
                    g1, a1, v1 = ed[1].split('|')
                    g2, a2, v2 = dst.split('|')
                    if g1==g2 and a1==a2 and v1!=v2:
                        defaults[src].append([dst, ed[1]])
            continue
        populate_dep(src)
        doc = maven_deps.find_one({'parent': src.replace('|', ':')})
        if doc:
            for dep in doc['dependencies']:
                try:
                    g, a, v = dep['dep'].split(':')
                except:
                    logging.debug('Special GAV:', dep['dep'])
                    continue
                if g+'|'+a in dst:
                    if v.lower()!= dst.split('|')[-1].lower():
                        defaults[src].append([dst, dep['dep'].replace(':', '|')])
                    else:
                        break
        else:
            for ed in edges:
                if ed[0]==src:
                    g1, a1, v1 = ed[1].split('|')
                    g2, a2, v2 = dst.split('|')
                    if g1==g2 and a1==a2 and v1!=v2:
                        defaults[src].append([dst, ed[1]])

    return defaults

def walk_subgraph(edges_, root):
    ret = []
    root_edges = []
    edges = [e for e in edges_]

    rest = edges
    while len(edges) >0:
        subgraph = set()
        count = len(subgraph)
        while count!=len(subgraph) or count ==0:
            count =len(subgraph)
            for edge in edges:
                if root in edge:
                    rest.remove(edge)
                    root_edges.append(edge)
                    continue
                if len(subgraph)==0:
                    subgraph = [edge]
                    rest.remove(edge)
                else:
                    if edge[0] in serialize_subgraph(subgraph) or edge[1] in serialize_subgraph(subgraph):
                        subgraph.append(edge)
                        rest.remove(edge)
            edges = rest
        ret.append(subgraph)

    # Restore root edges to each subgraph
    added_root_edges = []
    for subgraph in ret:
        nodes = serialize_subgraph(subgraph)
        for root_edge in root_edges:
            if root_edge[1] in nodes:
                subgraph.append(root_edge)
                added_root_edges.append(root_edge)
    for root_edge in root_edges:
        if not root_edge in added_root_edges:
            ret.append([root_edge])



    return ret

def supplement_edges(c, deps, edges):
    maven_deps = c['library-crawler']['maven_deps']
    edge_dict = defaultdict(set)
    for edge in edges:
        dg, da, dv = edge[1].split('|')
        edge_dict[edge[0]].add(dg+'|'+da)
    dep_libs = {}
    for dep in deps:
        g, a, v = dep.split('|')
        dep_libs[g+'|'+a] = v
    for dep in deps:
        g,a,v = dep.split('|')
        doc = maven_deps.find_one({'parent': g+':'+a+':'+v})
        if doc:
            for dep_dep in doc['dependencies']:
                dg, da, dv = dep_dep['dep'].split(':')
                if dg+'|'+da not in edge_dict[dep] and dep_dep['dScope'] in {'compile', 'runtime'} \
                        and dep_dep['isoptional']=='false' and dg+'|'+da in dep_libs:
                    edges.append([dep, dg+'|'+da+'|'+dep_libs[dg+'|'+da]])
    return edges

def get_subgraphs_from_deptree(c, dep_tree):
    cwd = os.getcwd()
    # Substitute indirect deps with new versions
    edges = []
    deps = set()

    current = dep_tree['root']['dependenciesList']
    root = dep_tree['root']['libraryVendor'] + '|' + dep_tree['root']['libraryName'] + '|' + dep_tree['root']['version']
    for direct in current:
        edges.append([root, direct['libraryVendor'] + '|' + direct['libraryName'] + '|' + direct['version']])
    while len(current) > 0:
        tmp = [*current]
        current = []
        for node in tmp:
            node_gav = node['libraryVendor'] + '|' + node['libraryName'] + '|' + node['version']
            deps.add(node_gav)
            for dep_node in node['dependenciesList']:
                dep_gav = dep_node['libraryVendor'] + '|' + dep_node['libraryName'] + '|' + dep_node['version']
                edges.append([node_gav, dep_gav])
                current.append(dep_node)
    edges = supplement_edges(c, deps, edges)
    os.chdir(cwd)
    # subgraphs = walk_subgraph(edges, root)
    info = {
        'cves': get_cves_dict(deps),
        'direct': get_direct_deps(edges, root),
        'root': root,
        'deps': deps,
        'edges': edges
    }
    return info

def get_original_dep_tree(c, dep_path, large_scale=False):
    cwd = os.getcwd()
    deps, edges, root = get_mvn_dep_tree(dep_path, large_scale)
    edges = supplement_edges(c, deps, edges)
    os.chdir(cwd)
    # subgraphs = walk_subgraph(edges, root)
    info = {
        'cves': get_cves_dict(deps),
        'direct': get_direct_deps(edges, root),
        'root': root,
        'deps': deps,
        'edges': edges
    }

    # for subgraph in subgraphs:
    #     subgraph_deps = {each[0] for each in subgraph}.union({each[1] for each in subgraph})
    #     if root in subgraph_deps:
    #         subgraph_deps.remove(root)
    #     old_cves = get_cves_dict(subgraph_deps)
    #     direct_deps = get_direct_deps(subgraph)
    #     a = {
    #         'subgraph': subgraph,
    #         'cves': old_cves,
    #         'direct': direct_deps,
    #         'root': root,
    #         'deps': subgraph_deps,
    #         'edges': edges
    #     }
    #     info.append(a)
    return info

def get_direct_deps(edges, root):
    if len(edges)>0:
        ret = []
        for edge in edges:
            if edge[0] == root:
                ret.append(edge[1])
        return ret
    else:
        return []

def get_graph_api_deps(gavs):
    body = []
    for gav in gavs:
        g, a, v = gav.split('|')
        body.append({
            "name": a,
            "vendor": g,
            "version": v,
            "platform": "maven"
        })
    response = requests.post(f'http://{graph_api_host}:{graph_api_port}/allDependencies', json=body)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception('[ERROR] Graph-api Error', gavs)
def get_graph_deps(old_subgraph, new_lib_vers):
    old_directs = old_subgraph['direct']
    new_directs = []
    root = old_subgraph['root']

    # Get new libs
    new_libs = {}
    for lib_ver in new_lib_vers:
        g,a,v = lib_ver.split('|')
        new_libs[g+'|'+a] = v
    # Substitute libver with new versions
    for direct in old_directs:
        g,a,v = direct.split('|')
        new_directs.append(g+'|'+a+'|'+new_libs.get(g+'|'+a, v))

    # Get default direct deps
    response = get_graph_api_deps(new_directs)

    # Substitute indirect deps with new versions
    edges = []
    deps = set()
    current = response['root']['dependenciesList']
    for direct in current:
        edges.append([root, direct['libraryVendor']+'|'+direct['libraryName']+'|'+direct['version']])
    while len(current) > 0:
        tmp=[*current]
        current = []
        for node in tmp:
            node_gav = node['libraryVendor'] + '|' + node['libraryName'] + '|' + new_libs.get(node['libraryVendor'] + '|' + node['libraryName'], node['version'])
            deps.add(node_gav)
            for dep_node in node['dependenciesList']:
                dep_gav = dep_node['libraryVendor'] + '|' + dep_node['libraryName'] + '|' + new_libs.get(dep_node['libraryVendor'] + '|' + dep_node['libraryName'], dep_node['version'])
                edges.append([node_gav, dep_gav])
                current.append(dep_node)
    return deps, edges

# def get_graph_dep_tree(c, old_subgraph, new_lib_vers):
#     maven_deps = c['library-crawler']['maven_deps']
#     deps2, edges2 = get_graph_deps(old_subgraph, new_lib_vers)
#     edges2 = supplement_edges(c, deps2, edges2)
#     defaults = get_default_gavs(old_subgraph['subgraph'], edges2, maven_deps)
#     new_cves = get_cves(deps2)
#     with open('upgraded_deps.json', 'w') as f:
#         write = []
#         for key, value in defaults.items():
#             for pair in value:
#                 write.append(pair)
#         f.write(json.dumps(write))
#     return new_cves, edges2



def get_pom_dep_tree(c, old_edges, dep_path_2):
    maven_deps = c['library-crawler']['maven_deps']
    cwd = os.getcwd()
    deps2, edges2, root = get_mvn_dep_tree(dep_path_2)
    edges2 = supplement_edges(c, deps2, edges2)
    defaults = get_default_gavs(old_edges, edges2, maven_deps, root)
    # new_cves = get_cves(deps2)
    cve_dict = get_cves_dict(deps2)
    os.chdir(cwd)
    # root = next(iter(deps2))
    # for key in deps:
    #     if key in deps2:
    #         continue
    #     g, a, v = key.split('|')
    #     diff[key] = {}
    #     for k in deps2:
    #         g2, a2, v2 = k.split('|')
    #         if g == g2 and a == a2:
    #             diff[key]['second_version'] = v2
    #     diff[key] = {**diff[key], **deps[key]}

    # pprint(defaults)


    # with open('maven_info_filter.json', 'w') as f:
    #     write = []
    #     # for key in diff:
    #     for key, value in defaults.items():
    #         for pair in value:
    #             g, a, v = pair[0].split('|')
    #             write.append({
    #                 "group_id": g,
    #                 "library_name": a,
    #                 "version_name": v
    #             })
    #             g, a, v = pair[1].split('|')
    #             write.append({
    #                 "group_id": g,
    #                 "library_name": a,
    #                 "version_name": v
    #             })
    #     for key, value in deps.items():
    #         g, a, v = key.split('|')
    #         write.append({
    #             "group_id": g,
    #             "library_name": a,
    #             "version_name": v
    #         })
    #     f.write(json.dumps(write))
    # download_jar()
    # with open('upgraded_deps.json', 'w') as f:
    #     write = []
    #     for key, value in defaults.items():
    #         for pair in value:
    #
    #             g1, a1, v1 = pair[0].split('|')
    #             g2, a2, v2 = pair[1].split('|')
    #             write.append([os.path.join(download_path, a1 + '-' + v1 + '.jar'),
    #                           os.path.join(download_path, a2 + '-' + v2 + '.jar')])
    #     f.write(json.dumps(write))

    with open('upgraded_deps.json', 'w') as f:
        write = []
        for key, value in defaults.items():
            for pair in value:
                write.append(pair)
        f.write(json.dumps(write))
    return cve_dict, edges2, root

def get_all_versions(gav, maven):
    gavs = []
    g, a, v = gav.split('|')
    for doc in maven.find({'group':g, 'artifact':a}):
        gavs.append(g+'|'+a+'|'+doc['version'])
    return gavs
# def save_dep_cves(c):
#     existing = ''
#     if os.path.exists('mvn_out/components.csv'):
#         with open('mvn_out/components.csv', 'r') as f:
#             existing = f.read()
#     with open('mvn_out/manual_cves.csv', 'a') as f, open('mvn_out/components.csv', 'a') as f2:
#         writer= csv.writer(f, lineterminator = '\n')
#         writer2 = csv.writer(f2, lineterminator='\n')
#         for path in inspect_paths:
#             cves = set()
#             name = path.split('/')[-1]
#             if name in existing:
#                 continue
#             deps, edges = get_mvn_dep_tree(path)
#             for dep in deps:
#                 writer2.writerow([name, dep])
#                 for gav in get_all_versions(dep, c['library-crawler']['maven']):
#                     cves = cves.union(get_cve(gav))
#             for cve in set(cves):
#                 writer.writerow([name, cve])



# if __name__ =='__main__':
    # if len(sys.argv) >1 and sys.argv[1] == 'single':
    #     with open('../maven_info_filter.json', 'w') as f:
    #         write = []
    #         g,a,v = jar1.split("|")
    #         write.append({
    #             "group_id": g,
    #             "library_name": a,
    #             "version_name": v
    #         })
    #         g, a, v = jar2.split("|")
    #         write.append({
    #             "group_id": g,
    #             "library_name": a,
    #             "version_name": v
    #         })
    #         f.write(json.dumps(write))
    #     # download_jar()
    #     with open('upgraded_deps.json', 'w') as f:
    #         write = []
    #
    #         g1, a1, v1 = jar1.split('|')
    #         g2, a2, v2 = jar2.split('|')
    #         write.append([os.path.join(download_path, a1 + '-' + v1 + '.jar'),
    #                       os.path.join(download_path, a2 + '-' + v2 + '.jar')])
    #         f.write(json.dumps(write))
    #     exit()
    # get_pom_dep_tree()
