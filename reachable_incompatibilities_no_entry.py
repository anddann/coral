import csv
import json
import logging
import os
import networkx as nx
import signal
import subprocess
import pymongo
from old_entry import create_nx_graph, get_attributes, get_vulnerable_class
from collections import defaultdict
from revapi_return_apis import get_incompatible_apis
from networkx.readwrite.adjlist import read_adjlist, write_adjlist
from jar_config import jar, main_jar, original_jar, dep_path, dep_path_2
from config import download_path, working_dir
from evaluation.get_dep_tree import get_pom_dep_tree
from time import time
from utils.parse_japicmp import get_japicmp
from utils.db_utils import get_cvss
logging.getLogger("root").setLevel(logging.WARNING)
# Always regenerate call graph
regeneration = False
direct = True
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
    error = False
    try:
        if not os.path.exists(working_dir+'graph/'+order+jar.split('/')[-1].replace('.jar', '.csv')) or os.path.getsize(working_dir+'graph/'+order+jar.split('/')[-1].replace('.jar', '.csv'))==0 or regeneration:
            # os.system('java -jar '+ working_dir+'libs/sootTest-1.0-SNAPSHOT-jar-with-dependencies.jar '+jar+' '+order+jar.split('/')[-1].replace('.jar', '')+' '+main_class)
            output = subprocess.check_output('java -jar '+ working_dir+'libs/sootTest-1.0-SNAPSHOT-jar-with-dependencies.jar '+jar+' '+order+jar.split('/')[-1].replace('.jar', '')+' '+main_class, stderr=subprocess.STDOUT,
                                         shell=True).decode()
            print(output)
    except Exception as exc:
        print(exc)
        error = True
    return working_dir+'graph/'+order+jar.split('/')[-1].replace('.jar', '.csv').replace('.war', '.csv'), working_dir+'graph/'+order+jar.split('/')[-1].replace('.jar', '_NameList.csv').replace('.ar', '_NameList.csv'), error#, 'graph/'+jar.split('/')[-1].replace('.jar', '_api.csv')

def get_direct_dep_apis(direct_deps):

    apis = set()
    for dep in direct_deps:
        g,a,v = dep.split('|')
        path = os.path.join(download_path, a+'-'+v+'.jar')
        if not os.path.exists('graph/main_' + a+'-'+v+ '_api.csv') or os.path.getsize(
                'graph/main_' + a+'-'+ v+'_api.csv') == 0 or regeneration:
            os.system(
                'java -jar singleJarAPI-1.0-SNAPSHOT-jar-with-dependencies.jar ' + path + ' main_' + a+'-'+v)
        with open('graph/main_' + a+'-'+v+ '_api.csv') as f:
            for l in csv.reader(f):
                apis.add(l[0])
    return apis

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

def calculate_fixing_rate(order, collection):
    doc = collection.find_one({'order': order})
    ori_doc = collection.find_one({'order': '0_'})
    print('Fixing rate is: ', sum([float(ori_doc['cvss'][cve]) for cve in [item for item in ori_doc['all_cves'] if item not in doc['all_cves']]]))
    # for fixed_cve in ori_doc['all_cves']-doc['all_cves']:








def evaluate(c):
    collection = c['remediation']['java_tmp']
    old_cves, new_cves, direct_deps = get_pom_dep_tree(c)
    curent_order = ''
    os.makedirs('networkx_graph', exist_ok=True)
    reachability(original_jar, old_cves, '0_', c, direct_deps)
    reachability(jar, new_cves, curent_order, c, direct_deps)
    calculate_fixing_rate(curent_order, collection)

def reachability(jar, cves, order, c, direct_deps):
    collection = c['remediation']['java_tmp']
    cvss_coll = c['remediation']['cvss']

    #Skip the original calculation
    if order=='0_':
        if collection.find_one({'order': '0_'}):
            return


    # Get the actually reachable functions based on CVE-func mappings
    _, affected_methods, _ = get_vulnerable_class(cves)

    # if len(sys.argv)<3:
    #     print('Please enter jarfile path as first argument')
    #     exit()
    start = time()


    name = jar.split("/")[-1].replace('-jar-with-dependencies.jar', '')
    cg_csv, namelist_csv, error = generate_csv(jar, regeneration=regeneration, order=order)

    if direct:
        main_apis = get_direct_dep_apis(direct_deps)
    else:
        main_apis = get_main_jar_apis(main_jar, regeneration=regeneration)
    if order != '0_':
        upgraded_deps = json.load(open('upgraded_deps.json'))
    else:
        upgraded_deps = []
    total_incom = 0

    # Construct networkx graph if not
    G = None
    if os.path.exists('networkx_graph/'+order+name) and not regeneration:
        G = read_adjlist('networkx_graph/'+order+name, create_using=nx.DiGraph())
        print('Graph read from local file')
    else:
        G = construct_networkx_graph(name, main_apis, cg_csv, order)

    # Check reachable incompatible APIs
    for deps in upgraded_deps:
        jar1, jar2 = deps
        incom_apis = get_reachable_incompatibility_via_subgraph(name, main_apis, cg_csv, jar1, jar2, G=G)
        print(jar1.split('/')[-1], jar2.split('/')[-1])
        print(incom_apis)
        total_incom+=len(incom_apis)
        print('')

    # Check reachable CVEs
    reachable_cves, unreachable_cves, unsure_cves = get_reachable_cve(G, affected_methods, cves)
    cvss = get_cvss({*reachable_cves, *unreachable_cves, *unsure_cves}, cvss_coll)

    print('Reachable CVE:', reachable_cves)
    print('Unrechable CVE:', unreachable_cves)
    print('Unsure CVE:', unsure_cves)
    print('Total incompatibility apis:', total_incom)
    print(time()-start, 'sec elapsed')

    doc = {
        'order': order,
        'reachable': list(reachable_cves),
        'unreachable': list(unreachable_cves),
        'unsure': list(unsure_cves),
        'all_cves': list({*reachable_cves, *unreachable_cves, *unsure_cves}),
        'incom_apis': total_incom,
        'cvss': cvss
    }
    collection.update_one({'order': order}, {'$set':doc}, upsert=True)
    return total_incom

if __name__ == '__main__':
    c = pymongo.MongoClient('119.8.190.75',
                            port=8635,
                            username='rwuser',
                            password='Sc@ntist123',
                            authSource='admin',
                            authMechanism='SCRAM-SHA-256')





    evaluate(c)
    c.close()