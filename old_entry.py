import csv
import os
import re
import shutil
import sys
import networkx as nx
import java_manifest
from callgraph_normalization import sig_translation, formalize_cve_func
from collections import defaultdict

cve_cls_mapping = 'cve_func_10_22.csv'
def get_attributes(s):
    if ':' in s: 
        cl, method, = s.split(':')
        clss = cl.split('.')[-1]
        pkg = cl.replace(clss, '')
        method_name = ""
        arguments = ""
        method_match = re.search('(.*)\((.*)\)$', method)
        if method_match:
            method_name = method_match.group(1)
            arguments = method_match.group(2)
        return pkg, clss, method_name, arguments
    else:
        print(s)
        exit()
        return "", "", "", ""

def get_nodes_on_attr(G, **kwargs):
    ret = []
    for x, y in G.nodes(data=True):
        flag = True
        for key, value in kwargs.items():
            if key not in y or y[key] != value:
                flag = False
        if flag:
            ret.append(x)
    return ret

def connectivity(G, src, dst):
    return nx.node_connectivity(G, src, dst) > 0

def shortest_path(G, src, dst):
    return nx.shortest_path(G, src, dst)

def create_nx_graph(main_method):
    if not main_method:
        print('Main class is empty. No path info could be provided')
        exit()
    G = nx.DiGraph()
    file_entrypoints = []
    file_entry_node = main_method
    file_entrypoints.append(file_entry_node)
    G.add_node(file_entry_node)
    # Return the root nodes' names
    return G, file_entrypoints

def generate_nx_graph(root_file, main_class):
    if not main_class:
        print('Main class is empty. No path info could be provided')
        exit()
    G = nx.DiGraph()
    file_entrypoints = []
    with open(root_file, 'r') as fp:
        file_entry_node = "Virtual.Entrypoint.Node."+root_file.replace('graph/', '').replace('.csv', '')
        file_entrypoints.append(file_entry_node)
        G.add_node(file_entry_node)
        reader = csv.reader(fp)

        for line in reader:
            if ':' not in line[0] or ':' not in line[1]:
                print(f, line)
                exit()
            pkg, clss, method_name, arguments = get_attributes(line[0])
            src_sig = sig_translation(line[0])
            dst_sig = sig_translation(line[1])
            G.add_node(src_sig, path=pkg, class_name=clss, method=method_name, arguments=arguments)
            pkg, clss, method_name, arguments = get_attributes(line[1])
            G.add_node(dst_sig, path=pkg, class_name=clss, method=method_name, arguments=arguments)
            G.add_edge(src_sig, dst_sig)
            if line[0].startswith(main_class) and line[0].endswith('(java.lang.String[])'):
                G.add_edge(file_entry_node, src_sig)
            elif not main_class:
                G.add_edge(file_entry_node, dst_sig)
    return G, file_entrypoints

import zipfile

def get_main_class(zipFileName, pathName, namelist_csv=None):
    result = None
    f = zipfile.ZipFile(zipFileName, "r")
    if any(x.startswith(pathName.rstrip("/")) for x in f.namelist()):
        result = java_manifest.loads(f.read(pathName).decode("utf-8"))[0].get('Main-Class', None)
    f.close()
    if result is None and namelist_csv!=None:
        with open(namelist_csv) as f:
            reader = csv.reader(f)
            for l in reader:
                if ':main(java.lang.String[])' in l[0]:
                    result = l[0]
                    break
    return result

def get_vulnerable_class(cves=[]):
    classes = {}
    methods = {}
    cveset = set()
    with open(cve_cls_mapping) as f:
        cve_funcs = csv.reader(f)
        for index, line in enumerate(cve_funcs):
            if index==0:
                continue
            if line[0] not in cves:
                continue
            if line[17]:
                methods[line[17]] = line[0]
                cveset.add(line[0])
            classes[line[3]] = line[0]
            cveset.add(line[0])
    return classes, methods, cveset


def generate_csv(jar, main_class='', regeneration=False):
    # print(os.path.getsize('graph/'+jar.split('/')[-1].replace('.jar', '.csv')))
    if not os.path.exists('graph/'+jar.split('/')[-1].replace('.jar', '.csv')) or os.path.getsize('graph/'+jar.split('/')[-1].replace('.jar', '.csv'))==0 or regeneration:
        os.system('java -jar sootTest-1.0-SNAPSHOT-jar-with-dependencies.jar '+jar+' '+jar.split('/')[-1].replace('.jar', '')+' '+main_class)
    return 'graph/'+jar.split('/')[-1].replace('.jar', '.csv'), 'graph/'+jar.split('/')[-1].replace('.jar', '_NameList.csv')

def get_potentially_reachable_functions(f, cves=[]):
    """
    In case of only vulnerable class is available, take all methods of the class as vulnerable
    """
    classes, methods, cveset = get_vulnerable_class(cves)
    ret = defaultdict(list)
    with open(f) as fp:
        names = csv.reader(fp)
        for name in names:
            sig = sig_translation(name[0])
            if sig in methods.keys():
                ret[methods[sig]].append(sig)
            else:
                clss = name[0].split(':')[0]
                if clss:
                    if clss in classes:
                        ret[classes[clss]].append(sig)
    return ret, cveset-set(ret.keys())

def get_reachable_via_full_graph(cg_csv, main_class, cves, cve_funcs):
    # Generate topological graph based on call graph csv files
    G, file_entrypoints = generate_nx_graph(cg_csv, main_class)
    direct = file_entrypoints[0]
    print('File entry point:', direct)

    # Find and return paths of reachable CVEs
    output = {i: {} for i in cve_funcs.keys()}
    for cve, funcs in cve_funcs.items():
        for func in funcs:
            # output[cve][func] = []
            try:
                for path in nx.algorithms.simple_paths.shortest_simple_paths(G, direct, func):
                    output[cve][func] = path
                    break
            except Exception as e:
                # print(e)
                unreachable_cves.add(cve)
    uncertain_cves = cves
    for c in unreachable_cves:
        uncertain_cves.remove(c)
    return output, unreachable_cves, uncertain_cves

# def recursive(node, edges):
#
#     return visited, G

def get_reachable_via_subgraph(main_class, cg_csv, cves, cve_funcs):
    unreachable_cves = set()
    with open(cg_csv, 'r') as fp:
        a = csv.reader(fp)
        edges = defaultdict(set)
        for l in a:
            edges[l[0]].add(l[1])

    main_method = main_class+':main(java.lang.String[])'
    if main_method in edges.keys():
        visited = set()
        G, file_entrypoints = create_nx_graph(main_method)
        direct = file_entrypoints[0]
        tmp = [direct]
        while tmp:
            next = tmp
            tmp = []
            for son in next:
                sig = sig_translation(son)
                if sig not in visited:
                    visited.add(sig)
                    for grandson in edges[son]:
                        grandsig = sig_translation(grandson)
                        pkg, clss, method_name, arguments = get_attributes(son)
                        if son != main_method:
                            G.add_node(sig, path=pkg, class_name=clss, method=method_name, arguments=arguments)
                        pkg, clss, method_name, arguments = get_attributes(grandson)
                        G.add_node(grandsig, path=pkg, class_name=clss, method=method_name, arguments=arguments)
                        G.add_edge(sig, grandsig)
                        if grandsig not in visited:
                            # visited.add(grandsig)
                            tmp.append(grandson)

        # Find and return paths of reachable CVEs
        output = {i: {} for i in cve_funcs.keys()}
        for cve, funcs in cve_funcs.items():
            for func in funcs:
                # output[cve][func] = []
                # if func in visited:
                #     output[cve] = []
                #     break
                try:
                    for path in nx.algorithms.simple_paths.shortest_simple_paths(G, direct, func):
                        output[cve][func] = path
                        break
                except Exception as e:
                    print(e)
            if output[cve] == {}:
                unreachable_cves.add(cve)
                output.pop(cve)
    else:
        sys.exit('Main class not found in call graph')
    return output, unreachable_cves



#example-java-maven-1.0-SNAPSHOT-jar-with-dependencies.jar

if __name__ == '__main__':
    from time import time
    if len(sys.argv)<2:
        print('Please enter jarfile path as first argument')
        exit()
    start = time()
    unreachable_cves = set()
    uncertain_cves = set()

    # scanned CVE is read from a csv file
    with open('Ground truth - Reachability_example.csv') as f:
        reader = csv.reader(f)
        cves = []
        for l in reader:
            cves.append(l[0])

    # Formalize raw cve-func mappings table
    # formalize_cve_func()
    
    jar = sys.argv[1]
    # Generate the call graph csv files
    main_class = get_main_class(jar, "META-INF/MANIFEST.MF")
    cg_csv, namelist_csv = generate_csv(jar, main_class)
    # Get the actually reachable functions based on CVE-func mappings
    cve_funcs, unreachable_cves = get_potentially_reachable_functions(namelist_csv, cves)
    # Get main class based on the manifest file
    main_class = get_main_class(jar, "META-INF/MANIFEST.MF", namelist_csv)



    output, additional_unreachable_cves = get_reachable_via_subgraph(main_class, cg_csv, cves, cve_funcs)



    # output, unreachable_cves, uncertain_cves = get_reachable_via_full_graph(cg_csv, main_class, cves, cve_funcs)
    uncertain_cves = set(cves)
    uncertain_cves=uncertain_cves.difference(set(output.keys()))
    total_unreachable = unreachable_cves.union(additional_unreachable_cves)
    uncertain_cves = uncertain_cves.difference(total_unreachable)
    print('Reachable cves:', output)
    print('Uncertain cves:', uncertain_cves)
    print('Unreachable cves:', total_unreachable)

    print(time()-start, 'sec elapsed.')


    # Generate last output of 3 categories
    with open('Ground truth - Reachability_example_result.csv', 'w') as f:
        writer = csv.writer(f)
        cves = []
        for cve in cves:
            if cve in uncertain_cves:
                writer.append([cve, 'Uncertain'])
            elif cve in total_unreachable:
                writer.append([cve, 'Unrechable'])
            elif cve in output.keys():
                writer.append([cve, 'Rechable'])
            else:
                writer.append([cve, ''])