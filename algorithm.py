import csv
import json
import os

import pymongo
import pickle
from call_graph.construct_call_graphs import create_call_graph_dict
from config import working_dir, MONGO_HOST, MONGO_PORT
from bom_evaluation import pre_compute_subgraphs, dictionarize_graph, evaluate_algo, read_local_call_graph
from exceptions import NoSolutionFound
from evaluation.get_dep_tree import get_original_dep_tree, get_cve, get_subgraphs_from_deptree
from mip_library.script import distance_smt, all_smt
from structures.Node import Node
from structures.dependencyGraph import DependencyGraph
from utils.graph_api import get_dependency_tree, get_edges_from_deptree, get_remediation
from utils.version_utils import get_latest_version


def all_solver(project_name, original_path):
    c = pymongo.MongoClient(MONGO_HOST,
                            port=MONGO_PORT)

    subgraphs = get_original_dep_tree(c, original_path)
    edges = subgraphs['edges']
    root = subgraphs['root']
    directs = []
    for edge in edges:
        if root == edge[0]:
            directs.append(edge[1])
    modified_directs = []
    for direct in directs:
        g, a, v = direct.split('|')
        if len(get_cve(direct)) > 0:

            if a == 'slf4j-ext' or a == 'logback-classic':
                continue
            if 'client-adapter' in a:
                continue
            latest_version = get_latest_version(g, a, c)
            if latest_version:

                modified_directs.append(g + '|' + a + '|' + latest_version)
            else:
                modified_directs.append(direct)
        else:
            modified_directs.append(direct)
    dep_tree = get_dependency_tree(modified_directs, c)
    if dep_tree == {}:
        edges = []
    else:
        edges = get_edges_from_deptree(dep_tree['root'], root)
    with open('remediation_results/' + project_name.replace('/', '_') + '_baseline', 'wb') as handle:
        pickle.dump(edges, handle, protocol=pickle.HIGHEST_PROTOCOL)

    # distance_smt(edges, c, depGraph)
    print('[INFO] allSovler Completed!')

def baseline(project_name, original_path):
    c = pymongo.MongoClient(MONGO_HOST,
                            port=MONGO_PORT)

    subgraphs = get_original_dep_tree(c, original_path)
    edges = subgraphs['edges']
    root = subgraphs['root']
    directs = []
    for edge in edges:
        if root == edge[0]:
            directs.append(edge[1])
    modified_directs = []
    for direct in directs:
        g, a, v = direct.split('|')
        if len(get_cve(direct))>0:

            if a == 'slf4j-ext' or a =='logback-classic':
                continue
            if 'client-adapter' in a:
                continue
            latest_version = get_latest_version(g, a, c)
            if latest_version:

                modified_directs.append(g+'|'+a+'|'+latest_version)
            else:
                modified_directs.append(direct)
        else:
            modified_directs.append(direct)
    dep_tree = get_dependency_tree(modified_directs, c)
    if dep_tree=={}:
        edges = []
    else:
        edges = get_edges_from_deptree(dep_tree['root'], root)
    with open(working_dir+'remediation_results/'+project_name.replace('/', '_')+'_baseline', 'wb') as handle:
        pickle.dump(edges, handle, protocol=pickle.HIGHEST_PROTOCOL)
    print('[INFO] Baseline Completed!')




def product_remediation(graph_api_std_deptree, user_clss_file_path, project_name='dummy'):
    # name = jar.split("/")[-1].replace('-jar-with-dependencies.jar', '')
    c = pymongo.MongoClient(MONGO_HOST,
           port=MONGO_PORT)
    subgraphs = get_subgraphs_from_deptree(c, graph_api_std_deptree)
    initial_deps_ga = {gav.replace('|'+gav.split('|')[-1], '') for gav in subgraphs['deps']}
    depGraph = DependencyGraph(subgraphs, project_name)

    call_graph = read_local_call_graph(project_name, subgraphs['edges'], subgraphs['root'], user_clss_file_path)
    depGraph.get_root().set_preferred(depGraph.get_root().get_original_version())

    depGraph.set_callgraph(call_graph)
    # for subgraph in subgraphs:
    #     if len(subgraph['cves'])==0:
    #         continue
    # out_graph, in_graph = dictionarize_graph(subgraph['subgraph'])
    depGraph.set_lvls(subgraphs['root'])
    breadth = depGraph.root.get_sons()  # out_graph[subgraph['root']]

    # Initialize flattened
    depGraph.update_flattened_callee_graph()

    # DEbug
    # for node in depGraph.get_nodes().values():
    #     if node.get_lvl() ==0:
    #         print(node.ga)

    visited = []
    while (len(breadth) != 0):
        next_breadth = []
        for node in breadth:
            node_ga = node.get_ga()

            # skip removed nodes
            if node.get_lvl() == -1:
                continue

            # if node.get_ga() == 'com.caucho|hessian':  # 'javax.xml.stream|stax-api':#'javax.ejb|ejb-api':##:
                # print(depGraph.get_callgraph()[node.get_ga()])
                # aa = 9
            if node_ga in visited or len(node.get_parents()) == 0:
                continue
            print('[INFO] Setting', node.ga, 'at lvl', node.lvl)

            if node.get_ga() not in depGraph.callgraph.keys():
                node.set_preferred(node.get_original_version())
                continue

            # Skip node with lowered level
            if not node.check_parents_lvls(visited):
                continue

            backtrack = node.calculate_candidates_safer(c, depGraph)
            if backtrack:
                parents = node.get_parents()
                parents = Node.sort_by_lvl(parents, reverse=True)
                target_parent = parents[-1][0]
                if target_parent.get_lvl() == 0:
                    # backtrack to the root, then stay with original version
                    node.set_preferred(node.get_original_version())
                    target_parent.set_backtrack(True)
                    node.set_backtrack(True)
                    # if os.path.exists(working_dir+'remediation_results/'+project_name.replace('/', '_')):
                    #     os.remove(working_dir+'remediation_results/'+project_name.replace('/', '_'))
                    # return len(subgraphs['deps'])
                else:
                    target_parent.set_backtrack(True)
                    target_parent.get_hard_incom_vers().add(target_parent.get_preferred())
                    next_breadth.insert(0, target_parent)


            else:
                # try:
                backtrack_target = node.set_default_version(c, depGraph)
                if backtrack_target is not None:
                    parents = node.get_parents()
                    parents = Node.sort_by_lvl(parents, reverse=True)
                    target_parent = parents[-1][0]
                    if target_parent.get_lvl() == 0:
                        # backtrack to the root, then stay with original version
                        node.set_preferred(node.get_original_version())
                        target_parent.set_backtrack(True)
                        node.set_backtrack(True)
                        # if os.path.exists(working_dir+'remediation_results/'+project_name.replace('/', '_')):
                        #     os.remove(working_dir+'remediation_results/'+project_name.replace('/', '_'))
                        # return len(subgraphs['deps'])
                    else:
                        target_parent.set_backtrack(True)
                        target_parent.get_hard_incom_vers().add(target_parent.get_preferred())
                        next_breadth.insert(0, target_parent)
                # except NoSolutionFound:
                else:
                    depGraph.update_call_graph(node, c)
                    # Update flattened
                    depGraph.update_flattened_callee_graph()
                    depGraph.reset_sons_by_preferred(node, c)

                    next_breadth.extend(node.get_sons())
                    for each in depGraph.get_new_nodes_by_smt():
                        if each not in next_breadth:
                            next_breadth.append(each)
                    # set backtrack false if rerun completely
                    # if node.get_backtrack() == True:
                    #     for son in node.get_sons():
                    #         son.set_backtrack(True)
                    # node.set_backtrack(False)

                    depGraph.clear_nodes_by_smt()

            visited.append(node_ga)
        # To exclude non-initial deps for simplicity.
        breadth = [each for each in next_breadth if str(each) not in visited and each.get_ga() in initial_deps_ga]
    depGraph.recursion_group_delete_unconnected()
    # depGraph.check_preferred()
    os.makedirs('remediation_results/', exist_ok=True)
    with open(working_dir + 'remediation_results/' + project_name.replace('/', '_'), 'wb') as handle:
        pickle.dump(depGraph, handle, protocol=pickle.HIGHEST_PROTOCOL)
    depGraph.export_remediation_results()
    # with open('remediation_results/'+project_name, 'rb') as handle:
    #     depGraph = pickle.load(handle)
    #     depGraph.export_remediation_results()
    #
    # depGraph.check_preferred()
    # evaluate_algo(depGraph, c, original_jar)
    print('[INFO] Remediation Completed!')
    c.close()
    return len(subgraphs['deps'])

def remediation(project_name, original_path, original_jar, test_path=None, large_scale=False):
    # name = jar.split("/")[-1].replace('-jar-with-dependencies.jar', '')
    c = pymongo.MongoClient(MONGO_HOST,
                            port=MONGO_PORT
                            )
    subgraphs = pre_compute_subgraphs(c, original_path, large_scale)
    # if len(subgraphs['deps'])>100:
    #     return None
    depGraph = DependencyGraph(subgraphs, project_name)

    call_graph = read_local_call_graph(project_name, subgraphs['edges'], subgraphs['root'], original_jar)
    depGraph.get_root().set_preferred(depGraph.get_root().get_original_version())

    depGraph.set_callgraph(call_graph)
    # for subgraph in subgraphs:
    #     if len(subgraph['cves'])==0:
    #         continue
    # out_graph, in_graph = dictionarize_graph(subgraph['subgraph'])
    depGraph.set_lvls(subgraphs['root'])
    breadth = depGraph.root.get_sons()#out_graph[subgraph['root']]

    # Initialize flattened
    depGraph.update_flattened_callee_graph()

    # DEbug
    # for node in depGraph.get_nodes().values():
    #     if node.get_lvl() ==0:
    #         print(node.ga)

    visited = []
    while (len(breadth)!=0):
        next_breadth = []
        for node in breadth:
            node_ga = node.get_ga()

            # skip removed nodes
            if node.get_lvl()==-1:
                continue

            if node.get_ga() == 'com.caucho|hessian':#'javax.xml.stream|stax-api':#'javax.ejb|ejb-api':##:
                # print(depGraph.get_callgraph()[node.get_ga()])
                aa = 9
            if node_ga in visited or len(node.get_parents())==0:
                continue
            print('[INFO] Setting', node.ga, 'at lvl', node.lvl)

            if node.get_ga() not in depGraph.callgraph.keys():
                node.set_preferred(node.get_original_version())
                continue

            # Skip node with lowered level
            if not node.check_parents_lvls(visited):
                continue


            backtrack = node.calculate_candidates_safer(c, depGraph)
            if backtrack == 'hard':
                parents = node.get_parents()
                parents = Node.sort_by_lvl(parents, reverse=True)
                target_parent = parents[-1][0]
                if target_parent.get_lvl()==0:
                    # backtrack to the root, then stay with original version
                    node.set_preferred(node.get_original_version())
                    target_parent.set_backtrack(True)
                    node.set_backtrack(True)
                    # if os.path.exists(working_dir+'remediation_results/'+project_name.replace('/', '_')):
                    #     os.remove(working_dir+'remediation_results/'+project_name.replace('/', '_'))
                    # return len(subgraphs['deps'])
                else:
                    target_parent.set_backtrack(True)
                    target_parent.get_hard_incom_vers().add(target_parent.get_preferred())
                    next_breadth.insert(0, target_parent)


            else:
            # try:
                backtrack_target = node.set_default_version(c, depGraph)
                if backtrack_target is not None:
                    parents = node.get_parents()
                    parents = Node.sort_by_lvl(parents, reverse=True)
                    target_parent = parents[-1][0]
                    if target_parent.get_lvl() == 0:
                        # backtrack to the root, then stay with original version
                        node.set_preferred(node.get_original_version())
                        target_parent.set_backtrack(True)
                        node.set_backtrack(True)
                        # if os.path.exists(working_dir+'remediation_results/'+project_name.replace('/', '_')):
                        #     os.remove(working_dir+'remediation_results/'+project_name.replace('/', '_'))
                        # return len(subgraphs['deps'])
                    else:
                        target_parent.set_backtrack(True)
                        target_parent.get_hard_incom_vers().add(target_parent.get_preferred())
                        next_breadth.insert(0, target_parent)
                # except NoSolutionFound:
                else:
                    depGraph.update_call_graph(node, c)
                    # Update flattened
                    depGraph.update_flattened_callee_graph()
                    depGraph.reset_sons_by_preferred(node, c)

                    next_breadth.extend(node.get_sons())
                    for each in depGraph.get_new_nodes_by_smt():
                        if each not in next_breadth:
                            next_breadth.append(each)
            # set backtrack false if rerun completely
            # if node.get_backtrack() == True:
            #     for son in node.get_sons():
            #         son.set_backtrack(True)
            # node.set_backtrack(False)


                    depGraph.clear_nodes_by_smt()

            visited.append(node_ga)
        breadth = [each for each in next_breadth if str(each) not in visited]
    depGraph.recursion_group_delete_unconnected()
    depGraph.check_preferred()
    if large_scale:
        with open(working_dir + 'remediation_results_large_scale/' + project_name, 'wb') as handle:
            pickle.dump(depGraph, handle, protocol=pickle.HIGHEST_PROTOCOL)
    else:
        with open(working_dir+'remediation_results/'+project_name.replace('/', '_'), 'wb') as handle:
            pickle.dump(depGraph, handle, protocol=pickle.HIGHEST_PROTOCOL)

    # with open('remediation_results/'+project_name, 'rb') as handle:
    #     depGraph = pickle.load(handle)
    #
    # depGraph.check_preferred()
    # evaluate_algo(depGraph, c, original_jar)
    print('[INFO] Tool Remediation Completed!')
    c.close()
    return len(subgraphs['deps'])
    # def backtrack(node, visted):
    #     smallest_parents = node.__get_highest_parents()

def all_smt_remediation(project_name, original_path, original_jar):
    c = pymongo.MongoClient(MONGO_HOST,
                            port=MONGO_PORT)
    subgraphs = pre_compute_subgraphs(c, original_path)
    depGraph = DependencyGraph(subgraphs, project_name)

    call_graph = read_local_call_graph(project_name, subgraphs['edges'], subgraphs['root'], original_jar)
    depGraph.get_root().set_preferred(depGraph.get_root().get_original_version())

    depGraph.set_callgraph(call_graph)
    depGraph.set_lvls(subgraphs['root'])
    breadth = depGraph.root.get_sons()#out_graph[subgraph['root']]
    visited = []
    edges = []
    while (len(breadth) != 0):
        next_breadth = []
        for node in breadth:
            node_ga = node.get_ga()

            # skip removed nodes
            if node.get_lvl() == -1:
                continue

            if node_ga in visited or len(node.get_parents()) == 0:
                continue
            print('[INFO] **all_smt_bsl** Setting', node.ga, 'at lvl', node.lvl)

            if node.get_ga() not in depGraph.callgraph.keys():
                node.set_preferred(node.get_original_version())
                continue

            # Skip node with lowered level
            if not node.check_parents_lvls(visited):
                continue

            backtrack = node.calculate_candidates_safer(c, depGraph)

            for son in node.get_sons():
                edges.append([node, son])
            next_breadth.extend(node.get_sons())
            visited.append(node_ga)
        breadth = [each for each in next_breadth]
    try:
        all_smt(edges, c, depGraph)
    except:
        return len(subgraphs['deps'])

    depGraph.recursion_group_delete_unconnected()
    depGraph.check_preferred()
    with open(working_dir+'remediation_results/'+project_name.replace('/', '_')+'_all_smt', 'wb') as handle:
        pickle.dump(depGraph, handle, protocol=pickle.HIGHEST_PROTOCOL)

    # with open('remediation_results/'+project_name, 'rb') as handle:
    #     depGraph = pickle.load(handle)
    #
    # depGraph.check_preferred()
    # evaluate_algo(depGraph, c, original_jar)
    print('[INFO] all smt Remediation Completed!')
    c.close()
    return len(subgraphs['deps'])
