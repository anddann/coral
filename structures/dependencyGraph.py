import json
import os
from collections import defaultdict

from bom_evaluation import get_incom_apis, get_reachable_cves
from call_graph.construct_call_graphs import get_callees
from evaluation.get_dep_tree import get_cve
from exceptions.DependencyNotFound import DependencyNotFoundError
from exceptions.NoSolutionFound import NoSolutionFoundError
from pom_dep_extractor.extract_pom_dep import populate_dep
from structures.Node import Node
from evaluation.get_dep_tree import get_cves_dict
from utils.class_method_parser import get_class, clean_args_for_cve_mappings
from utils.db_utils import dictize_deps, get_all_versions
from utils.prune_graph_methods_for_reachability import prune_graph
from utils.version_utils import _sort, split_version_list, get_minor_version


class DependencyGraph:

    def __init__(self, subgraphs, project_name):
        self.project_name = project_name
        self.subgraphs = subgraphs
        self.edges = subgraphs['edges']
        self.callgraph = {}
        self.nodes = {}
        self.flattened_callees = set()
        self.final_nodes = {}
        # To be processed in loop for nodes added by SMT solver upgrades
        self.new_nodes_by_smt = []
        for edge in self.edges:
            src = self.get_node(edge[0].replace('|'+edge[0].split('|')[-1], ''))
            if not src:
                src = Node(edge[0])
                self.nodes[str(src)] = src
            dst = self.get_node(edge[1].replace('|'+edge[1].split('|')[-1], ''))
            if not dst:
                dst = Node(edge[1])
                self.nodes[str(dst)] = dst

            src.sons[str(dst)] = dst
            dst.parents[str(src)] = src
        self.root = self.get_node(subgraphs['root'].replace('|'+subgraphs['root'].split('|')[-1], ''))
        if self.root is None:
            self.root = Node(subgraphs['root'])
            if self.root.get_ga() not in self.nodes.keys():
                self.nodes[self.root.get_ga()] = self.root

    def get_project_name(self):
        return self.project_name

    def get_root(self):
        return self.root

    def get_new_nodes_by_smt(self):
        return self.new_nodes_by_smt

    def add_new_node_by_smt(self, node):
        self.new_nodes_by_smt.append(node)

    def clear_nodes_by_smt(self):
        self.new_nodes_by_smt = []

    def set_callgraph(self, callgraph):
        self.callgraph = callgraph

    def get_callgraph(self):
        return self.callgraph

    def get_edges(self):
        return self.edges

    def get_subgraphs(self):
        return self.subgraphs

    def get_node(self, node_ga):
        return self.nodes.get(node_ga, None)

    def get_nodes(self):
        return self.nodes

    def add_final_node(self, node):
        self.final_nodes[node.get_ga()] = node

    def get_final_nodes(self, includ_root=True):
        if includ_root:
            return self.final_nodes.values()
        else:
            tmp = [*self.final_nodes.values()]
            tmp.remove(self.root)
            return tmp

    def get_final_node_names(self):
        return [*self.final_nodes.keys()]

    def get_flattened_callees(self):
        return self.flattened_callees

    def set_flattened_callees(self, i):
        self.flattened_callees = i

    def add_new_node_by_parent(self, node_gav, parent):
        node_ga = node_gav.split('|')[0]+'|'+node_gav.split('|')[1]
        if not node_ga in self.nodes:
            self.nodes[node_ga] = Node(node_gav)
            self.nodes[node_ga].set_lvl(parent.get_lvl() + 1)
        if self.nodes[node_ga].get_lvl()>(parent.get_lvl()+1):
            self.nodes[node_ga].set_lvl(parent.get_lvl() + 1)
        parent.add_son(self.nodes[node_ga])
        self.nodes[node_ga].add_parent(parent)


    def exclude_reachable_incomaptible_versions(self, c, gav, versions, clean_versions=[]):
        g,a,v = gav.split('|')
        apis = self.get_flattened_callees()
        if len(apis) ==0:
            return versions
        candidates = []
        versions = _sort(versions)
        groups = {'other':versions}#split_version_list(versions)
        allowance = len(groups['other'])
        current_minor_version = get_minor_version(v)
        # exclude versions with reachable breaking apis
        for key, vers in groups.items():
            if key!='other':
                incom_apis = set(get_incom_apis(c, g+'|'+a, v, key))
                if not clean_args_for_cve_mappings(incom_apis).intersection(clean_args_for_cve_mappings(apis)):
                    candidates.extend(vers)
            else:
                for ver in vers:
                    # prioritize patch upgrade by securing same minor version
                    if current_minor_version is not None and get_minor_version(ver)!= current_minor_version and len(set(candidates).intersection(set(clean_versions)))>5:
                        break
                    # if candidates too many, break
                    if len(set(candidates).intersection(set(clean_versions))) > 10:
                        break
                    # allowance is up, break
                    if allowance == 0:
                        break
                    incom_apis = set(get_incom_apis(c, g + '|' + a, v, ver))
                    # if no incom api, add to candidates
                    if not clean_args_for_cve_mappings(incom_apis).intersection(clean_args_for_cve_mappings(apis)):
                        candidates.append(ver)
                    else:
                        # if not compatible, then try 2 more versions
                        if allowance>3:
                            allowance = 3
                    allowance-=1


        if len(candidates)!=0:
            self.get_node(g+'|'+a).set_candidates(candidates)
        return candidates

    def  exclude_reachable_vulnerable_versions(self, node_ga, cves_dict, c):
        graph, classes = prune_graph(self.callgraph)
        cve_funcs = None
        if c is not None:
            try:
                cve_funcs = c['remediation']['cve_funcs']
            except Exception:
                cve_funcs = None
        unreachable_versions = set()
        cve_visited = set()

        reachable_versions = set()
        for gav, cves in cves_dict.items():
            g,a,v = gav.split('|')
            if len(graph) ==0:
                unreachable_versions.add(v)
                continue
            isAnyReachable = False
            for cve in cves:
                if cve in cve_visited:
                    continue
                cve_visited.add(cve)
                doc = None
                if cve_funcs is not None:
                    try:
                        doc = cve_funcs.find_one({'cve': cve})
                    except Exception:
                        doc = None
                if doc:
                    # Tried to find funcs but failed
                    if 'notFound' in doc:
                        isAnyReachable= True
                        break

                    methods = set(doc['methods'])
                    clzzs_from_methods =get_class(methods)
                    if len(clean_args_for_cve_mappings(methods).intersection(clean_args_for_cve_mappings(graph)))>0:
                        isReachable = True
                        isAnyReachable = True
                        reachable_versions.add(v)
                    # if len(methods.intersection(apis))>0:
                        continue
                    clzzs = set(doc['classes']).union(clzzs_from_methods)
                    isReachable = False
                    for clzz in clzzs:
                        for api in graph:
                            if clzz in api:
                                isReachable = True
                                break
                        if isReachable:
                            break
                    if isReachable:
                        isAnyReachable = True
                        break
                else:
                    print('CVE func_missing:', cve)


            if not isAnyReachable:
                unreachable_versions.add(v)
            else:
                reachable_versions.add(v)

        return unreachable_versions, reachable_versions


    def update_call_graph(self, node, c):
        callgraph_db_direct = c['call_graphs_direct']
        callgraph_db_all = c['call_graphs_all']
        # original_callees = self.callgraph[node.get_ga()]
        parent_callers = set()
        for parent in node.get_parents():
            parent_callers = parent_callers.union(self.callgraph.get(parent.get_ga(), set()))
        self.callgraph[node.get_ga()] = list(get_callees(node.get_preferred_gav(), parent_callers, callgraph_db_direct, callgraph_db_all))


    def get_unreachable_vulnerable_versions_by_prioritization(self, node_ga, c, clean_versions):
        version_list = []

        maven = c['library-crawler']['maven']
        all_versions = [e for e in get_all_versions(node_ga, maven) if e not in clean_versions]

        cves_dict = get_cves_dict([node_ga+'|'+v for v in all_versions])
        unreachable_versions, reachable_versions = self.exclude_reachable_vulnerable_versions(node_ga, cves_dict, c)
        cve_counts = defaultdict(list)
        for gav in unreachable_versions:
            cve_counts[(len(cves_dict[gav]))].append(gav)
        counts = list(cve_counts.keys())
        counts.sort()
        for count in counts:
            versions_tmp = []
            for gav in cve_counts[count]:
                version = gav.split('|')[-1]
                versions_tmp.append(version)
            versions_tmp = _sort(versions_tmp)
            version_list.append(versions_tmp)
        if len(version_list) == 0 or len(version_list[0]) == 0:
            print('No solution found, set oringal')
            return [[self.get_node(node_ga).get_original_version()]]
            # raise NoSolutionFoundError("No version available for "+node_ga)
        return version_list

    def set_lvls(self, root):
        root_g, root_a, root_v = root.split('|')
        breadth = self.get_node(root_g+'|'+root_a).get_sons()
        lvl = 0
        visited = set()
        while (len(breadth) != 0):
            lvl += 1
            tmp = [each for each in breadth]
            breadth = []
            for node in tmp:
                # if node.get_ga()=='javax.transaction|jta':
                #     a = 1
                if str(node) in visited:
                    continue
                node.set_lvl(lvl)
                breadth.extend(node.get_sons())
                visited.add(str(node))

    def delete_node(self, node, current_parent=None):
        # Only remove relationships, but keep the node in original list
        current_parent.remove_son(node)
        node.remove_parent(current_parent)
        node.reset_lvl()

    def pop_node(self, node_ga):
        self.nodes.pop(node_ga)


    def reset_sons_by_preferred(self, node, c):
        new_version = node.get_preferred()
        if new_version==None:
            a =1
        maven_deps = None
        callgraph_db_direct = None
        callgraph_db_all = None
        if c is not None:
            try:
                maven_deps = c['library-crawler']['maven_deps']
                callgraph_db_direct = c['call_graphs_direct']
                callgraph_db_all = c['call_graphs_all']
                populate_dep(node.get_ga()+'|'+new_version, c)
            except Exception:
                pass

        doc = None
        if maven_deps is not None:
            try:
                doc = maven_deps.find_one({'parent': (node.get_ga()+'|'+new_version).replace('|', ':')})
            except Exception:
                doc = None

        if not doc:
            from utils.deps_dev_api import get_direct_deps_deps_dev
            ng, na = node.get_ga().split('|')
            directs = get_direct_deps_deps_dev(ng, na, new_version)
            if directs:
                deps = directs
            else:
                node.sons = {}
                print("[ERROR] Cannot find deps for: " + (node.get_ga()+'|'+new_version).replace('|', ':'))
                return []
        else:
            deps = dictize_deps(doc)
        # For fewer deps:
        for son in node.get_sons():
            if not son.get_ga() in deps:
                # try to delete the node if no other parents
                self.delete_node(son, current_parent=node)
        # For more deps:
        gas = [e.get_ga() for e in node.get_sons()]
        new_nodes = []
        for dep in deps:
            if not dep in gas:
                # try to add the new relationship
                self.add_new_node_by_parent(dep+'|'+deps[dep], node)
                new_nodes.append(self.nodes[dep])
                if dep not in self.callgraph:
                    all_parent_callers = []
                    for parent in self.get_node(dep).get_parents():
                        all_parent_callers.extend(self.callgraph.get(parent.get_ga(), set()))
                    if len(all_parent_callers)==0:
                        self.callgraph[dep] = []
                    else:
                        self.callgraph[dep] = list(get_callees(dep+'|'+deps[dep], all_parent_callers, callgraph_db_direct, callgraph_db_all))
                        if not os.path.exists('graphs'):
                            os.mkdir('graphs')
                        open('graphs/' + self.project_name + '.json', 'w').write(json.dumps(self.callgraph))
        return new_nodes

    def re_group_edges_after_remediation(self):
        self.edges = []
        for node in self.final_nodes.values():


            for son in node.get_sons():
                if node.get_ga() == self.root.get_ga():
                    self.edges.append([node.get_gav(), son.get_preferred_gav()])
                else:
                    self.edges.append([node.get_preferred_gav(), son.get_preferred_gav()])

    def update_flattened_callee_graph(self):
        for l in self.callgraph:
            self.flattened_callees = self.flattened_callees.union(self.callgraph[l])


    def recursion_group_delete_unconnected(self):
        self.edges = []
        visited = set()
        start = [self.get_root()]
        while len(start) > 0:
            tmp = [each for each in start]
            start = []
            for n in tmp:
                if n.get_preferred_gav() is not None:
                    self.add_final_node(n)
                else:
                    continue
                if n.ga in visited:
                    continue

                for son in n.get_sons():
                    if n.get_ga() == self.root.get_ga():
                        if son.get_preferred_gav() is not None:
                            self.edges.append([n.get_gav(), son.get_preferred_gav()])
                    else:
                        if son.get_preferred_gav() is not None and n.get_preferred_gav() is not None:
                            self.edges.append([n.get_preferred_gav(), son.get_preferred_gav()])

                    start.append(son)
                visited.add(n.ga)
    def check_preferred(self):
        to_be_deleted = []
        failed = False
        for node in self.get_final_nodes():
            # if len(node.get_parents()) ==0 and node.get_ga()!=depGraph.get_root().get_ga():
            #     to_be_deleted.append(node)
            if (node.get_preferred() == None or node.get_preferred() == '') and node.get_ga() != self.get_root().get_ga():
                print('Check failed', node.get_ga())
                failed = True

        # for to in to_be_deleted:
        #     depGraph.pop_node(to.get_ga())
        if not failed:
            print('[DEBUG] Check succeeded')
        else:
            raise NoSolutionFoundError("Preferred check failed")

    def export_remediation_results(self):
        results = {}
        for node in self.get_final_nodes():
            if (node.get_preferred() != None or node.get_preferred() != '') and node.get_ga() != self.get_root().get_ga():
                results[node.get_ga()] = {
                    'old_version': node.get_original_version(),
                    'new_version': node.get_preferred()
                }
        open('remediation_results/'+self.get_project_name()+'.json', 'w').write(json.dumps(results))

