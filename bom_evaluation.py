import csv
import json
import os
import networkx as nx
import subprocess
import pymongo
import random

from compatibility.get_break import revapi_jar
from evaluation.testing_compilation_n_unit_tests import test_compilation, test_unit_test
from old_entry import create_nx_graph, get_attributes
from collections import defaultdict
from revapi_return_apis import get_incompatible_apis
from networkx.readwrite.adjlist import write_adjlist
from jar_config import main_jar, dep_path_2
from config import from_pom, mongodb_port, mongodb_host, check_reachabiliity, working_dir
from evaluation.get_dep_tree import get_pom_dep_tree, get_original_dep_tree, supplement_edges, \
    get_mvn_dep_tree, get_cves, get_cve, get_cves_dict
from time import time

from temp_scripts.github_issue_analysis import dissect_version
from utils.class_method_parser import clean_args_for_cve_mappings
from utils.graph_api import get_remediation, get_dependency_tree, get_edges_from_deptree, get_clean_versions
from utils.miscellaneous import get_jar_path
from utils.parse_japicmp import get_japicmp, run_original_japicmp
from utils.db_utils import get_cvss, get_all_versions
from utils.prune_graph_methods_for_reachability import prune_graph
from utils.pom_modifier import update_pom
from call_graph.construct_call_graphs import create_call_graph, create_call_graph_dict
from utils.version_utils import _sort, is_dev, is_major

# Always regenerate call graph
regeneration = False


def read_local_call_graph(project_name, edges, root, jar):
    project_name = project_name.replace('/', '_')
    if os.path.exists(working_dir+'graphs/'+project_name+'.json') and os.path.getsize(working_dir+'graphs/'+project_name+'.json')!=0:
        return json.load(open(working_dir+'graphs/'+project_name+'.json'))
    else:
        call_graph = create_call_graph_dict(edges, root, jar)
        os.makedirs('graphs', exist_ok=True)
        open(working_dir+'graphs/'+project_name+'.json', 'w').write(json.dumps(call_graph))
        return call_graph

def getApis(jar, libname):
    process = subprocess.Popen(
        ['java', '-jar', 'libs/apiGetter.jar', jar, libname],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    apis = set()
    with open('apis/'+libname+'_APIs.csv') as f:
        for l in csv.reader(f):
            apis.add(l[0])
    return apis

def check_reachable(G, direct, target_jar, target_libname, target_jar2):
    apis = getApis(target_jar, target_libname)
    incomp_apis = get_incompatible_apis(target_jar, target_jar2)
    incomp_apis = incomp_apis.union(get_japicmp(target_jar, target_jar2))
    inter = apis.intersection(incomp_apis)
    problematic_apis = {}
    nodes = G.nodes
    for api in inter:
        if api in nodes:
            flag = False
            delete_parents = set()
            # filter out the nodes called with the target lib
            for parent in G.in_edges(api, data=False):
                if parent[0] not in apis:
                    flag = True
                else:
                    delete_parents.add(parent[0])
            # filter with flag
            if not flag:
                continue
            # delete edges in the targed lib to save traversal time
            for par in delete_parents:
                G.remove_edge(par, api)
            try:
                for path in nx.algorithms.simple_paths.shortest_simple_paths(G, direct, api):
                    if path[-2] not in apis:
                        problematic_apis[api] = path
                        break
            except Exception as e:
                print(e)

    return problematic_apis

def generate_csv(jar, main_class='com.macro.mall.MallAdminApplication', regeneration=False, order=''):
    # print(os.path.getsize('graph/'+jar.split('/')[-1].replace('.jar', '.csv')))
    if not os.path.exists('graph/'+order+jar.split('/')[-1].replace('.jar', '.csv')) or os.path.getsize('graph/'+order+jar.split('/')[-1].replace('.jar', '.csv'))==0 or regeneration:
        os.system('java -jar sootTest-1.0-SNAPSHOT-jar-with-dependencies.jar '+jar+' '+order+jar.split('/')[-1].replace('.jar', '')+' '+main_class)
    return 'graph/'+order+jar.split('/')[-1].replace('.jar', '.csv'), 'graph/'+order+jar.split('/')[-1].replace('.jar', '_NameList.csv')#, 'graph/'+jar.split('/')[-1].replace('.jar', '_api.csv')

def get_main_jar_apis(jar, regeneration=False):
    if not os.path.exists('graph/main_'+jar.split('/')[-1].replace('.jar', '_api.csv')) or os.path.getsize('graph/main_'+jar.split('/')[-1].replace('.jar', '_api.csv'))==0 or regeneration:
        os.system('java -jar singleJarAPI-1.0-SNAPSHOT-jar-with-dependencies.jar '+jar+' main_'+jar.split('/')[-1].replace('.jar', ''))
    with open('graph/main_'+jar.split('/')[-1].replace('.jar', '_api.csv')) as f:
        apis = set()
        for l in csv.reader(f):
            apis.add(l[0])
    return apis

def construct_networkx_graph(name, main_apis, cg_csv, order):
    with open(cg_csv, 'r') as fp:
        a = csv.reader(fp)
        edges = defaultdict(set)
        for l in a:
            edges[l[0]].add(l[1])
    virtual_root = 'virtual_root'
    visited = set()
    G, file_entrypoints = create_nx_graph(virtual_root)
    direct = file_entrypoints[0]
    for api in main_apis:
        pkg, clss, method_name, arguments = get_attributes(api)
        G.add_node(api, path=pkg, class_name=clss, method=method_name, arguments=arguments)
        G.add_edge(direct, api)

    tmp = main_apis
    while tmp:
        next = tmp
        tmp = []
        for son in next:
            sig = son
            if sig not in visited:
                visited.add(sig)
                for grandson in edges[son]:
                    grandsig = grandson
                    pkg, clss, method_name, arguments = get_attributes(son)
                    G.add_node(sig, path=pkg, class_name=clss, method=method_name, arguments=arguments)
                    pkg, clss, method_name, arguments = get_attributes(grandson)
                    G.add_node(grandsig, path=pkg, class_name=clss, method=method_name, arguments=arguments)
                    G.add_edge(sig, grandsig)
                    if grandsig not in visited:
                        tmp.append(grandson)
    print('Graph generated')

    write_adjlist(G, 'networkx_graph/'+order+name)
    return G

def get_reachable_incompatibility_via_subgraph(name, main_apis, cg_csv, target_jar,  target_jar2, G=None):
    target_libname = target_jar.split('/')[-1].replace('.jar', '')
    if G != None:
        return check_reachable(G, 'virtual_root', target_jar, target_libname, target_jar2)
    else:
        raise ValueError('Graph not found')

def get_reachable_cve(G, affected_methods, cves):
    if G == None:
        raise ValueError('Graph not found')
    unsure_cves = set(cves) - set(affected_methods.values())
    reachable_cves = set()
    unreachable_cves = set()
    for method in affected_methods.keys():
        if method in G.nodes:
            reachable_cves.add(affected_methods[method])
        else:
            unreachable_cves.add(affected_methods[method])
    return reachable_cves, unreachable_cves, unsure_cves

def calculate_fixing_rate(order, connection, coll='java_bom_tmp'):
    collection = connection['remediation'][coll]
    doc = collection.find_one({'order': order})
    ori_doc = collection.find_one({'order': '0'})
    # reachable_cve_fix = sum([float(ori_doc['cvss'][cve]) for cve in [item for item in ori_doc['reachable_cves'] if item not in doc['reachable_cves']]])
    # print('Reachable fixing is: ', reachable_cve_fix)
    current_reachable_cve_count = len(doc['reachable_cves'])
    print('Current # reachable CVEs: ', current_reachable_cve_count)
    # IC = sum([float(doc['cvss'][cve]) for cve in [item for item in doc['reachable_cves'] if item not in ori_doc['all_cves']]])
    # print(' CVE score is:', IC)
    remaining_unreachable_cves = sum([float(doc['cvss'][cve]) for cve in doc['unreachable_cves']])
    print('Remaining unreachable cves:', remaining_unreachable_cves)
    AI = doc['incom_apis']
    print('API incompatibility is:', AI)

    efforts = doc['efforts']

    return current_reachable_cve_count, remaining_unreachable_cves, AI, efforts



# def get_incom_apis(pair, connection):
#     gav1, gav2 = pair
#     gav1 = gav1.replace('[', '').replace(']', '')
#     gav2 = gav2.replace('[', '').replace(']', '')
#     # target_libname = target_jar.split('/')[-1].replace('.jar', '')
#     # if not os.path.exists(target_jar) or not os.path.exists(target_jar2):
#     #     print('Jar missing', target_jar, target_jar2)
#     # apis = getApis(target_jar, target_libname)
#     incomp_apis = set()#get_incompatible_apis(target_jar, target_jar2)
#     incomp_apis = incomp_apis.union(get_japicmp(gav1, gav2, connection))
#     # inter = apis.intersection(incomp_apis)
#     return incomp_apis


def pre_compute_subgraphs(c, dep_path, large_scale=False):
    subgraphs = get_original_dep_tree(c, dep_path, large_scale)
    return subgraphs

def get_evaluation_dep_tree(connection, x):
    mapping = connection['remediation']['moo_mapping']
    mappings = mapping.find_one({'key': 'mapping'})
    order = mapping.find_one({'key': 'order'})
    new_lib_vers = []
    for i, lib in enumerate(order['order']):
        # print(mappings[lib])
        # print(x)
        # print(i)
        ver = mappings[lib][str(random.randint(0, len(mappings[lib])-1))]
        g,a,v = lib.split('|')
        new_lib_vers.append(g+'|'+a+'|'+ver)
    return new_lib_vers

def pre_evaluate(connection, subgraph, main_jar, order='0'):
    start_time = time()
    new_edges = subgraph['subgraph']
    curent_order = str(order)
    root = subgraph['root']
    new_cves = subgraph['cves']
    if check_reachabiliity:
        one_time_graph = create_call_graph(new_edges, root, main_jar)
    else:
        one_time_graph = set()

    reachable_cves, unreachable_cves, unsure_cves = get_reachable_cves(one_time_graph, new_cves, connection)

    cvss = calculate_cvss(new_cves, connection)

    save_current_metrics(curent_order, reachable_cves, unreachable_cves, unsure_cves, 0, cvss, 0, connection)
    print('Pre-evaluation took:', "%.2f" % (time() - start_time), 's')




def calculate_efforts_spans_dev_major(old_libvers, new_libvers, c):
    efforts = 0
    spans = 0
    dev = 0
    major = 0
    # for new_lib, new_v in new_libvers.items():
    #     v_old = old_libvers.get(new_lib, '')
    #     if v_old != '' and v_old!= new_v:
    #         # efforts
    #         efforts+=1
    #         # spans
    #         all_versions = get_all_versions(new_lib, c['library-crawler']['maven'])
    #         if len(all_versions)==0:
    #             spans+=1
    #         if new_v not in all_versions:
    #             all_versions.append(new_v)
    #         if v_old not in all_versions:
    #             all_versions.append(v_old)
    #         all_versions = _sort(all_versions)
    #         spans+= abs(all_versions.index(new_v) - all_versions.index(v_old))
    #         # dev
    #         if not is_dev(v_old) and is_dev(new_v):
    #             dev+=1
    #         # major
    #         if is_major(v_old, new_v):
    #             major +=1
    #     elif v_old == '':
    #         efforts+=1
    for old_lib, old_v in old_libvers.items():
        v_new = new_libvers.get(old_lib, '')
        if v_new != '' and v_new!= old_v:
            # efforts
            efforts+=1
            # spans
            all_versions = get_all_versions(old_lib, c['library-crawler']['maven'])
            if len(all_versions)==0:
                spans+=1
            if old_v not in all_versions:
                all_versions.append(old_v)
            if v_new not in all_versions:
                all_versions.append(v_new)
            all_versions = _sort(all_versions)
            spans+= abs(all_versions.index(old_v) - all_versions.index(v_new))
            # dev
            if not is_dev(old_v) and is_dev(v_new):
                dev+=1
            # major
            if is_major(old_v, v_new):
                major +=1
        elif v_new == '':
            efforts+=1
    return efforts, spans, dev, major


def dictionarize_graph(edges):
    outs = defaultdict(set)
    ins = defaultdict(set)
    for edge in edges:
        outs[edge[0]].add(edge[1])
        ins[edge[1]].add(edge[0])
    return outs, ins



def evaluate_original_for_benchmark(project, project_path, root_jar):
    connection = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    # if connection['remediation']['benchmark_metrics'].find_one({'project': project, 'order': '0'}) and connection['remediation']['benchmark_metrics'].find_one({'project': project, 'order': 'Tool'}):
    #     print('Project already evaluated')
    #     connection.close()
    #     return None, None
    path = project_path[project]['original']
    main_jar = project_path[project]['jar']
    # get original deps
    cwd = os.getcwd()
    deps, edges, root = get_mvn_dep_tree(path)

    edges = supplement_edges(connection, deps, edges)
    os.chdir(cwd)

    # visualize(edges, deps)


    # evaluation
    start_time = time()
    # root = next(iter(deps))
    old_cves = get_cves(deps)
    if check_reachabiliity:
        one_time_graph = read_local_call_graph(project, edges, root, root_jar)
    else:
        one_time_graph = dict()
    print('Call graph took:', "%.2f" % (time() - start_time), 's')

    start_time2 = time()
    reachable_cves, unreachable_cves, unsure_cves = get_reachable_cves(one_time_graph, old_cves, connection)
    cvss = calculate_cvss(old_cves, connection)
    print('Reachable CVE took:', "%.2f" % (time() - start_time2), 's')
    save_benchmark_metrics(project, '0', reachable_cves, unreachable_cves, unsure_cves, 0, cvss, 0, 0, 0, 0, len(deps), connection)
    print('Pre-evaluation took:', "%.2f" % (time() - start_time), 's')
    connection.close()
    return edges, root


def evaluate_original_for_large_scale(project, path, root_jar):
    connection = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    # get original deps
    cwd = os.getcwd()
    deps, edges, root = get_mvn_dep_tree(path, True)

    edges = supplement_edges(connection, deps, edges)
    # visualize(edges, deps)
    os.chdir(cwd)

    # evaluation
    start_time = time()
    # root = next(iter(deps))
    old_cves = get_cves(deps)
    if check_reachabiliity:
        one_time_graph = read_local_call_graph(project, edges, root, root_jar)
    else:
        one_time_graph = {}
    print('Call graph took:', "%.2f" % (time() - start_time), 's')

    start_time2 = time()
    reachable_cves, unreachable_cves, unsure_cves = get_reachable_cves(one_time_graph, old_cves, connection)
    cvss = calculate_cvss(old_cves, connection)
    print('Reachable CVE took:', "%.2f" % (time() - start_time2), 's')
    save_benchmark_metrics(project, '0', reachable_cves, unreachable_cves, unsure_cves, 0, cvss, 0, 0, 0, 0, len(deps), connection, large_scale=True)
    print('Pre-evaluation took:', "%.2f" % (time() - start_time), 's')
    connection.close()
    return edges, root

def get_libvers(edges):
    ret = dict()
    for edge in edges:
        # if edge[0] is None or edge[1] is None:
        #     d =2
        g, a, v = str(edge[0]).split('|')
        ret[g+'|'+a] = v
        g, a, v = str(edge[1]).split('|')
        ret[g + '|' + a] = v
    return ret



def evaluate_other_tools(project, path, old_edges, tool_name, root_jar):
    connection = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)

    new_cves_dict, new_edges, root = get_pom_dep_tree(connection, old_edges, path)
    new_cves = []
    for cves in new_cves_dict.values():
        new_cves.extend(cves)
    # print('Deps derived')

    old_libvers = get_libvers(old_edges)
    new_libvers = get_libvers(new_edges)
    # Calc diff
    efforts, spans, dev, major = calculate_efforts_spans_dev_major(old_libvers, new_libvers, connection)
    start_time = time()
    if check_reachabiliity:
        one_time_graph = read_local_call_graph(project+'_'+tool_name, new_edges, root, root_jar)
    else:
        one_time_graph = set()

    # with open('call_graph.json', 'w') as f:
    #     f.write(json.dumps(list(one_time_graph)))

    print('Call graph took:', "%.2f" % (time() - start_time), 's')

    start_time = time()
    total_incom = incom_calculation(tool_name, connection, one_time_graph)
    print('Incom calculation took:', "%.2f" % (time() - start_time), 's')

    start_time = time()
    reachable_cves, unreachable_cves, unsure_cves = get_reachable_cves(one_time_graph, new_cves, connection)
    print('Reachable CVE took:', "%.2f" % (time() - start_time), 's')
    cvss = calculate_cvss(new_cves, connection)

    save_benchmark_metrics(project, tool_name, reachable_cves, unreachable_cves, unsure_cves, total_incom, cvss, efforts, spans, dev, major, len(new_libvers.keys()),
                         connection)

    # current_reachable_cve_count, remaining_unreachable_cves, AI, efforts = calculate_fixing_rate(tool_name,
    #                                                                                              connection, coll='benchmark_metrics')
    connection.close()




def evaluate(x, order, old_subgraph, test_path=None):
    connection = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    print('Evaluation starts')
    new_lib_vers = get_evaluation_dep_tree(connection, x)
    print('New versions obtained')

    efforts = calculate_efforts_spans_dev_major(new_lib_vers, old_subgraph, connection)

    old_edges = old_subgraph['subgraph']
    if from_pom:
        update_pom(os.path.join(dep_path_2, 'pom.xml'), new_lib_vers)
        print('Pom updated')
        new_cves, new_edges = get_pom_dep_tree(connection, old_edges, test_path)
    # else:
    #     new_cves, new_edges = get_graph_dep_tree(connection, old_subgraph, new_lib_vers)
    print('Deps derived')
    curent_order = str(order)

    start_time = time()
    one_time_graph = create_call_graph(new_edges, new_edges[0][0], main_jar)
    print('Call graph took:', "%.2f" % (time()-start_time), 's')
    start_time = time()
    total_incom = incom_calculation(curent_order, connection, one_time_graph)
    print('Incom calculation took:', "%.2f" % (time()-start_time), 's')

    start_time = time()
    reachable_cves, unreachable_cves, unsure_cves = get_reachable_cve(one_time_graph, new_cves, connection)
    print('Reachable CVE took:', "%.2f" % (time()-start_time), 's')
    cvss = calculate_cvss(new_cves, connection)


    save_current_metrics(curent_order, reachable_cves, unreachable_cves, unsure_cves, total_incom, cvss, efforts, connection)

    current_reachable_cve_count, remaining_unreachable_cves, AI, efforts = calculate_fixing_rate(curent_order, connection, coll='java_bom_tmp')
    connection.close()
    return current_reachable_cve_count, remaining_unreachable_cves, AI, efforts



def get_reachable_cves(one_time_graph, cves, connection):
    cve_func_coll = connection['remediation']['cve_funcs']
    graph, classes = prune_graph(one_time_graph)
    unsure_cves = set()
    reachable_cves = set()
    unreachable_cves = set()
    for cve in cves:
        doc = cve_func_coll.find_one({'cve': cve})
        if not doc:
            unsure_cves.add(cve)
        else:
            if len(doc['methods']) != 0:
                if len(clean_args_for_cve_mappings(graph).intersection(clean_args_for_cve_mappings(doc['methods'])))>0:
                    reachable_cves.add(cve)
                else:
                    unreachable_cves.add(cve)
            else:
                if len(classes.intersection(doc['classes']))>0:
                    reachable_cves.add(cve)
                else:
                    unreachable_cves.add(cve)
    return list(reachable_cves), list(unreachable_cves), list(unsure_cves)

def get_incom_apis(c, ga, ver1, ver2):
    incom_coll = c['incom_apis'][ga]
    if ver1 == ver2:
        return []
    doc = incom_coll.find_one({'verp': ver1+'|'+ver2})
    jar1 = get_jar_path(ga + '|' + ver1)
    jar2 = get_jar_path(ga + '|' + ver2)
    if doc:
        if len(doc['apis']) == 0 and 'revapi' not in doc:
            print('Calculating revapi', ga, ver1, ver2)
            apis = revapi_jar(jar1, jar2)
            incom_coll.update_one({'verp': ver1+'|'+ver2}, {'$set': {'apis': apis, 'revapi': True}})
            return [api.replace(' ', '') for api in apis]
        return [api.replace(' ', '') for api in doc['apis']]
    else:
        print('Calculating', ga, ver1, ver2, '\r', end='', flush=True)
        apis = list(run_original_japicmp(jar1, jar2))
        if len(apis) == 0:
            apis = revapi_jar(jar1, jar2)
        incom_coll.insert_one({'verp': ver1+'|'+ver2,
            'apis': apis, 'revapi': True
        }, bypass_document_validation=True)
        incom_coll.create_index('verp')
        return [api.replace(' ', '') for api in apis]


def save_benchmark(project, other_tool, efforts,
                           spans, dev, major, size, connection):
    collection = connection['remediation']['benchmark_metrics']
    if other_tool!='0':
        original_doc = collection.find_one({'order': '0', 'project': project})
        doc = {
            'project': project,
            'order': other_tool,
            'efforts': efforts,
            'spans': spans,
            'dev_upgrades': dev,
            'major_upgrades': major,
            'size': size
        }
    else:
        doc = {
            'project': project,
            'order': other_tool,
            'efforts': efforts,
            'spans': spans,
            'dev_upgrades': dev,
            'major_upgrades': major,
            'size': size
        }
    collection.update_one({'order': other_tool, 'project': project}, {'$set': doc})

def save_debug_metrics(project, other_tool, cve_dict, connection, large_scale=False):
    d = {}
    clean_vers_dict = {}
    for key in cve_dict:
        d[key] = {'cves': list(cve_dict[key]),
                  'cleanvers': list(get_clean_versions(key, connection))
                  }
    if large_scale:
        collection = connection['remediation']['large_scale_metrics']
    else:
        collection = connection['remediation']['benchmark_metrics']

    doc = {
        'cve_dict':d,
    }
    collection.update_one({'order': other_tool, 'project': project}, {'$set': doc}, upsert=True)

def save_large_metrics(project, connection, pat, min, maj, pre, unknown, removed, direct, indirect):
    d = {
        'patch': pat,
        'minor': min,
        'major': maj,
        'prerelease': pre,
        'unknown_upgrades': unknown,
        'removed_old_ver': removed,
        'direct_dep':direct,
        'indirect_dep': indirect
    }
    collection = connection['remediation']['large_scale_metrics']
    doc = {'fixable': d}
    collection.update_one({'order': 'Tool', 'project': project}, {'$set': doc})

def save_benchmark_metrics(project, other_tool, reachable_cves, unreachable_cves, unsure_cves, total_incom, cvss, efforts,
                           spans, dev, major, size, connection, large_scale=False, new_cves_dict=None):
    if large_scale:
        collection = connection['remediation']['large_scale_metrics']
    else:
        collection = connection['remediation']['benchmark_metrics']
    if other_tool!='0':
        original_doc = collection.find_one({'order': '0', 'project': project})
        reachable_fix = len(original_doc['reachable_cves']) - len(reachable_cves)
        if reachable_fix<0:
            reachable_fix =0

        unrea_fix = len(original_doc['unreachable_cves']) + len(original_doc['unsure_cves']) - len(unreachable_cves) - len(unsure_cves)
        if unrea_fix<0:
            unrea_fix=0
        doc = {
            'project': project,
            'order': other_tool,
            'reachable_cves': list(reachable_cves),
            'unreachable_cves': list(unreachable_cves),
            'unsure_cves': list(unsure_cves),
            'incom_apis': total_incom,
            'reachable_fix': reachable_fix,
            'unreachable_fix': unrea_fix,
            'cvss': cvss,
            'efforts': efforts,
            'spans': spans,
            'dev_upgrades': dev,
            'major_upgrades': major,
            'size': size
        }
    else:
        doc = {
            'project': project,
            'order': other_tool,
            'reachable_cves': list(reachable_cves),
            'unreachable_cves': list(unreachable_cves),
            'unsure_cves': list(unsure_cves),
            'incom_apis': total_incom,
            'cvss': cvss,
            'efforts': efforts,
            'spans': spans,
            'dev_upgrades': dev,
            'major_upgrades': major,
            'size': size
        }

    if new_cves_dict:
        # convert value from set to list
        new_cves_dict = {k: list(v) for k, v in new_cves_dict.items()}
        doc['cve_dict'] = new_cves_dict
    collection.update_one({'order': other_tool, 'project': project}, {'$set': doc}, upsert=True)

def save_current_metrics(order, reachable_cves, unreachable_cves, unsure_cves, total_incom, cvss, efforts, connection):
    collection = connection['remediation']['java_bom_tmp']
    doc = {
        'order': order,
        'reachable_cves': list(reachable_cves),
        'unreachable_cves': list(unreachable_cves),
        'unsure_cves': list(unsure_cves),
        'incom_apis': total_incom,
        'cvss': cvss,
        'efforts': efforts
    }
    collection.update_one({'order': order}, {'$set': doc}, upsert=True)

def calculate_cvss(cves, connection):
    cvss_coll = connection['remediation']['cvss']
    cvss = get_cvss(cves, cvss_coll)
    print('CVE:', cves)
    return cvss

def incom_calculation(order, connection, one_time_graph=None):
    com_feature = connection['compatibility_features']['experiment']
    total_incom=0
    if order != '0':
        upgraded_deps = json.load(open(working_dir+'upgraded_deps.json'))
    else:
        upgraded_deps = []


    # apis = set()
    # Check incompatible APIs
    # with concurrent.futures.ProcessPoolExecutor() as executor:
    #     future_name = {executor.submit(get_incom_apis, connection, g+'|'+a, pair[0], pair[1]) for pair in upgraded_deps}
    #     for future in concurrent.futures.as_completed(future_name):
    #         if check_reachabiliity:
    #             incom_apis = future.result().intersection(one_time_graph)
    #             if len(incom_apis) > 0:
    #                 # apis[jar1.split('/')[-1].replace('.jar', '')+ '|'+ jar2.split('/')[-1].replace('.jar', '')] = list(incom_apis)
    #                 print('[] have incompatible apis:', len(incom_apis))
    #         else:
    #             # print(future.result())
    #             incom_apis = future.result()
    #         # apis = apis.union(incom_apis)
    #         total_incom += len(incom_apis)
    for pair in upgraded_deps:
        g, a, v1 = pair[0].split('|')
        v1 = v1.replace('[','').replace(']', '')
        g, a, v2 = pair[1].split('|')
        v2 = v2.replace('[','').replace(']', '')
        incom_apis = set(get_incom_apis(connection, g+'|'+a, v1, v2)).intersection(one_time_graph)
        # if len(incom_apis) > 0:
            # apis[jar1.split('/')[-1].replace('.jar', '')+ '|'+ jar2.split('/')[-1].replace('.jar', '')] = list(incom_apis)
            # print(gav1, gav2, 'have incompatible apis:', len(incom_apis))
        total_incom+=len(incom_apis)
        # print('')
    # apis_json = open('apis.json', 'w')
    # apis_json.write(json.dumps(list(apis)))
    # apis_json.close()


    # Check reachable CVEs
    # print('Total incompatibility apis:', total_incom)
    # print(time()-start, 'sec elapsed')
    return total_incom

def evaluation_special(depGraph):
    low_cand = []
    for node in depGraph.get_final_nodes():
        low = node.get_low_candidates()
        if len(low)>0:
            low_cand.append(node)
        cves = get_cve(node.get_preferred_gav())
        node.set_cves(cves)
    a = 1

def evaluate_all_smt(project, depGraph, original_jar, old_edges, project_path, connection=None):
    if connection==None:
        connection = pymongo.MongoClient(mongodb_host, port=mongodb_port)
    # evaluation_special(depGraph)
    old_libvers = get_libvers(old_edges)
    new_libvers = get_libvers(depGraph.get_edges())
    new_cves_dict = get_cves_dict([n.get_preferred_gav() for n in depGraph.get_final_nodes(False)])

    new_cves =[]
    for cves in new_cves_dict.values():
        new_cves.extend(cves)

    efforts, spans, dev, major = calculate_efforts_spans_dev_major(old_libvers, new_libvers, connection)
    # new_cves = get_cves([each.get_preferred_gav() for each in depGraph.get_final_nodes(False)])
    # print('Deps derived')

    start_time = time()
    if check_reachabiliity:
        one_time_graph = read_local_call_graph(depGraph.get_project_name()+'_all_smt', depGraph.get_edges(), depGraph.get_root().get_gav(), original_jar)
    else:
        one_time_graph = set()

    print('Call graph took:', "%.2f" % (time() - start_time), 's')

    # start_time = time()
    total_incom =0 #incom_calculation('Tool', connection, one_time_graph)
    # print('Incom calculation took:', "%.2f" % (time() - start_time), 's')

    start_time = time()
    reachable_cves, unreachable_cves, unsure_cves = get_reachable_cves(one_time_graph, new_cves, connection)
    print('Reachable CVE took:', "%.2f" % (time() - start_time), 's')
    cvss = calculate_cvss(new_cves, connection)

    save_benchmark_metrics(project, 'all_smt', reachable_cves, unreachable_cves, unsure_cves, total_incom, cvss, efforts, spans, dev, major, len(new_libvers.keys()),
                           connection)
    # print(new_cves_dict)
    # save_debug_metrics(project, 'Tool', new_cves_dict, connection)

    # save_benchmark(project, 'Tool', efforts, spans, dev, major, len(new_libvers.keys()),
    #                        connection)
    # current_reachable_cve_count, remaining_unreachable_cves, AI, efforts = calculate_fixing_rate('Tool',
    #                                                                                              connection,
    #                                                                                              coll='benchmark_metrics')
    connection.close()

def calculate_fixable_reasons(old_cves_dict, new_cves_dict, old_libvers, new_libvers, depGraph):
    pat = 0
    min = 0
    maj = 0
    pre = 0
    unknown = 0
    removed = 0
    direct = 0
    indirect = 0
    for gav in old_cves_dict:

        g,a,v = gav.split('|')
        ga = g+'|'+a
        cve_count = len(set(old_cves_dict[gav]) - set(new_cves_dict.get(ga+'|'+new_libvers.get(ga, ''), [])))
        maj1, min1, pat1 = dissect_version(old_libvers[ga])
        if ga in new_libvers:
            maj2, min2, pat2 = dissect_version(new_libvers[ga])
            if maj1 == maj2 and min1 == min2 and pat1 != pat2:
                pat += cve_count
            elif maj1 == maj2 and min1 != '' and min2 != '' and min1 != min2:
                min += cve_count
            elif maj1 != maj2 and maj1 != '' and maj2 != '':
                maj += cve_count
            elif maj1 == maj2 and min1 == min2 and pat1 == pat2 and pat1 != '' and pat2 != '':
                pre += cve_count
            else:
                unknown += cve_count
        else:
            removed+=cve_count




        lvl = depGraph.get_node(ga).get_lvl()
        if lvl == 1:
            direct += cve_count
        else:
            indirect += cve_count

    return pat, min, maj, pre, unknown, removed, direct, indirect

def evaluate_large_scale(project, depGraph, original_jar, old_edges, connection=None):
    if connection==None:
        connection = pymongo.MongoClient(mongodb_host, port=mongodb_port)
    # evaluation_special(depGraph)
    old_libvers = get_libvers(old_edges)
    new_libvers = get_libvers(depGraph.get_edges())
    old_cves_dict = get_cves_dict([ga+'|'+old_libvers[ga] for ga in old_libvers])
    new_cves_dict = get_cves_dict([n.get_preferred_gav() for n in depGraph.get_final_nodes(False)])

    new_cves = []
    for cves in new_cves_dict.values():
        new_cves.extend(cves)
    pat, min, maj, pre, unknown, removed, direct, indirect = calculate_fixable_reasons(old_cves_dict, new_cves_dict, old_libvers, new_libvers, depGraph)
    efforts, spans, dev, major = calculate_efforts_spans_dev_major(old_libvers, new_libvers, connection)
    # new_cves = get_cves([each.get_preferred_gav() for each in depGraph.get_final_nodes(False)])
    # print('Deps derived')

    start_time = time()
    if check_reachabiliity:
        one_time_graph = read_local_call_graph(depGraph.get_project_name()+'_tool', depGraph.get_edges(), depGraph.get_root().get_gav(), original_jar)
    else:
        one_time_graph = dict()

    print('Call graph took:', "%.2f" % (time() - start_time), 's')

    # start_time = time()
    total_incom =0 #incom_calculation('Tool', connection, one_time_graph)
    # print('Incom calculation took:', "%.2f" % (time() - start_time), 's')

    start_time = time()
    reachable_cves, unreachable_cves, unsure_cves = get_reachable_cves(one_time_graph, new_cves, connection)
    print('Reachable CVE took:', "%.2f" % (time() - start_time), 's')
    cvss = calculate_cvss(new_cves, connection)

    save_benchmark_metrics(project, 'Tool', reachable_cves, unreachable_cves, unsure_cves, total_incom, cvss, efforts, spans, dev, major, len(new_libvers.keys()),
                           connection, large_scale=True)
    # print(new_cves_dict)
    save_debug_metrics(project, 'Tool', new_cves_dict, connection, large_scale=True)
    save_large_metrics(project, connection, pat, min, maj, pre, unknown, removed, direct, indirect)
    # save_benchmark(project, 'Tool', efforts, spans, dev, major, len(new_libvers.keys()),
    #                        connection)
    # current_reachable_cve_count, remaining_unreachable_cves, AI, efforts = calculate_fixing_rate('Tool',
    #                                                                                              connection,
    #                                                                                              coll='benchmark_metrics')
    connection.close()

def evaluate_algo(project, depGraph, original_jar, old_edges, project_path, connection=None):
    if connection==None:
        connection = pymongo.MongoClient(mongodb_host, port=mongodb_port)
    # evaluation_special(depGraph)
    old_libvers = get_libvers(old_edges)
    new_cves_dict, new_edges, root = get_pom_dep_tree(connection, old_edges, project_path)
    new_cves =[]
    for cves in new_cves_dict.values():
        new_cves.extend(cves)
    new_libvers = get_libvers(new_edges)

    efforts, spans, dev, major = calculate_efforts_spans_dev_major(old_libvers, new_libvers, connection)
    # new_cves = get_cves([each.get_preferred_gav() for each in depGraph.get_final_nodes(False)])
    # print('Deps derived')

    start_time = time()
    if check_reachabiliity:
        one_time_graph = read_local_call_graph(depGraph.get_project_name()+'_tool', depGraph.get_edges(), depGraph.get_root().get_gav(), original_jar)
    else:
        one_time_graph = dict()

    print('Call graph took:', "%.2f" % (time() - start_time), 's')

    # start_time = time()
    total_incom =0 #incom_calculation('Tool', connection, one_time_graph)
    # print('Incom calculation took:', "%.2f" % (time() - start_time), 's')

    start_time = time()
    reachable_cves, unreachable_cves, unsure_cves = get_reachable_cves(one_time_graph, new_cves, connection)
    print('Reachable CVE took:', "%.2f" % (time() - start_time), 's')
    cvss = calculate_cvss(new_cves, connection)

    save_benchmark_metrics(project, 'Tool', reachable_cves, unreachable_cves, unsure_cves, total_incom, cvss, efforts, spans, dev, major, len(new_libvers.keys()),
                           connection, new_cves_dict=new_cves_dict)
    # print(new_cves_dict)
    # save_debug_metrics(project, 'Tool', new_cves_dict, connection)

    # save_benchmark(project, 'Tool', efforts, spans, dev, major, len(new_libvers.keys()),
    #                        connection)
    # current_reachable_cve_count, remaining_unreachable_cves, AI, efforts = calculate_fixing_rate('Tool',
    #                                                                                              connection,
    #                                                                                              coll='benchmark_metrics')
    connection.close()


def evaluate_baseline(project, edges, original_jar, old_edges, root, connection=None):
    if connection==None:
        connection = pymongo.MongoClient(mongodb_host, port=mongodb_port)
    old_libvers = get_libvers(old_edges)
    new_libvers = get_libvers(edges)
    # root = edges[0][0]
    efforts, spans, dev, major = calculate_efforts_spans_dev_major(old_libvers, new_libvers, connection)

    # exclude root
    tmp_libs = []
    for each in new_libvers:
        if each not in root:
            tmp_libs.append(each + '|' + new_libvers[each])

    new_cves = get_cves(tmp_libs)
    print('Deps derived')

    start_time = time()
    if check_reachabiliity:
        one_time_graph = read_local_call_graph(project+'_baseline', edges, root, original_jar)
    else:
        one_time_graph = set()

    # with open('call_graph.json', 'w') as f:
    #     f.write(json.dumps(list(one_time_graph)))

    print('Call graph took:', "%.2f" % (time() - start_time), 's')

    start_time = time()
    total_incom = incom_calculation('baseline', connection, one_time_graph)
    print('Incom calculation took:', "%.2f" % (time() - start_time), 's')

    start_time = time()
    reachable_cves, unreachable_cves, unsure_cves = get_reachable_cves(one_time_graph, new_cves, connection)
    print('Reachable CVE took:', "%.2f" % (time() - start_time), 's')
    cvss = calculate_cvss(new_cves, connection)

    save_benchmark_metrics(project, 'baseline', reachable_cves, unreachable_cves, unsure_cves, total_incom, cvss, efforts, spans, dev, major, len(new_libvers.keys()),
                           connection)

    connection.close()



def eval_scantist(project_name, original_path, original_jar, old_edges, root, connection=None):
    print('[INFO] Evaluating Scantist')
    # Run scantist
    if connection==None:
        connection = pymongo.MongoClient(mongodb_host, port=mongodb_port)
    subgraphs = get_original_dep_tree(connection, original_path)
    edges = subgraphs['edges']
    root = subgraphs['root']
    directs = []
    for edge in edges:
        if root == edge[0]:
            directs.append(edge[1])
    modified_directs = []

    remediated = get_remediation(directs)
    for change in remediated:
        g = change['vendor']
        a = change['name']
        v = change['version']
        if change['recommendation'] == {}:
            modified_directs.append(g + '|' + a + '|' + v)
            continue
        if change['recommendation']['type'] == 'UPGRADE' or change['recommendation']['type'] == 'DOWNGRADE':
            upgrade_to = change['recommendation']['version']
            modified_directs.append(g + '|' + a + '|' + upgrade_to)
        else:
            modified_directs.append(g + '|' + a + '|'+v)
    dep_tree = get_dependency_tree(modified_directs, connection)
    if dep_tree == {}:
        edges = []
    else:
        edges = get_edges_from_deptree(dep_tree['root'], root)

    old_libvers = get_libvers(old_edges)
    new_libvers = get_libvers(edges)

    # Save remediation results
    with open(working_dir+'remediation_results/'+project_name.replace('/', '-')+'_scantist.json', 'w') as f:
        res = []
        for ga in old_libvers:
            if ga in new_libvers:
                res.append({
                    'old': ga+'|'+old_libvers.get(ga),
                    'new': ga+'|'+new_libvers.get(ga)
                })
        f.write(json.dumps(res))

    # root = edges[0][0]
    efforts, spans, dev, major = calculate_efforts_spans_dev_major(old_libvers, new_libvers, connection)

    # exclude root
    tmp_libs = []
    for each in new_libvers:
        if each not in root:
            tmp_libs.append(each + '|' + new_libvers[each])

    new_cves = get_cves(tmp_libs)
    print('Deps derived')

    start_time = time()
    if check_reachabiliity:
        one_time_graph = read_local_call_graph(project_name+'_scantist', edges, root, original_jar)
    else:
        one_time_graph = set()

    # with open('call_graph.json', 'w') as f:
    #     f.write(json.dumps(list(one_time_graph)))

    print('Call graph took:', "%.2f" % (time() - start_time), 's')

    start_time = time()
    total_incom = incom_calculation('baseline', connection, one_time_graph)
    print('Incom calculation took:', "%.2f" % (time() - start_time), 's')

    start_time = time()
    reachable_cves, unreachable_cves, unsure_cves = get_reachable_cves(one_time_graph, new_cves, connection)
    print('Reachable CVE took:', "%.2f" % (time() - start_time), 's')
    cvss = calculate_cvss(new_cves, connection)

    save_benchmark_metrics(project_name, 'scantist', reachable_cves, unreachable_cves, unsure_cves, total_incom, cvss,
                           efforts, spans, dev, major, len(new_libvers.keys()),
                           connection)

    connection.close()



def testing_compilation_n_unit_tests_for_one(project, paths, tool, connection):
    collection = connection['remediation']['benchmark_metrics']
    if collection.find_one({'order': tool, 'project': project, 'compilation': True, 'unit_test': True}):
        return
    compilation_res, unit_test_res, if_have_test = False, False, True
    # set java version
    os.system('export JAVA_HOME=`/usr/libexec/java_home -v 1.8`')

    if tool == 'Tool':
        compilation_res = test_compilation(tool, project, paths['test'])
        if compilation_res:
            unit_test_res, if_have_test = test_unit_test(tool, project, paths['test'])
    elif tool == 'scantist':
        compilation_res = test_compilation(tool, project, paths['snyk'].replace('_snyk', '_scantist'))
        if compilation_res:
            unit_test_res, if_have_test = test_unit_test(tool, project, paths['snyk'].replace('_snyk', '_scantist'))
    elif tool == 'steady':
        compilation_res = test_compilation(tool, project, paths['snyk'].replace('_snyk', '_steady'))
        if compilation_res:
            unit_test_res, if_have_test = test_unit_test(tool, project, paths['snyk'].replace('_snyk', '_steady'))
    elif tool == '0':
        compilation_res = test_compilation(tool, project, paths['original'])
        if compilation_res:
            unit_test_res, if_have_test = test_unit_test(tool, project, paths['original'])
    else:
        compilation_res = test_compilation(tool, project, paths[tool])
        if compilation_res:
            unit_test_res, if_have_test = test_unit_test(tool, project, paths[tool])

    collection.create_index([("order", pymongo.DESCENDING), ("project", pymongo.ASCENDING)])

    collection.update_one({'order': tool, 'project': project}, {'$set': {
        'compilation': compilation_res,
        'has_unit_test': if_have_test,
        'unit_test': unit_test_res
    }}, upsert=True)
    return



if __name__ == '__main__':
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    evaluate(c,[2, 3,2, 4, 2, 0], 1)
    c.close()
