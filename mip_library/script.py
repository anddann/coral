from itertools import product
from sys import stdout as out

import pymongo
from mip import Model, xsum, minimize, BINARY, OptimizationStatus, INTEGER
from collections import defaultdict

from config import mongodb_host, mongodb_port
from evaluation.get_dep_tree import get_cves_dict
from utils.db_utils import get_default_version, get_all_versions
from structures.Node import Node
from utils.graph_api import get_clean_versions
from utils.version_utils import _sort, check_in_range
from exceptions.DependencyVersionNotMatch import DependencyVersionNotMatchError

def example():
    # names of places to visit
    places = ['Antwerp', 'Bruges', 'C-Mine', 'Dinant', 'Ghent',
              'Grand-Place de Bruxelles', 'Hasselt', 'Leuven',
              'Mechelen', 'Mons', 'Montagne de Bueren', 'Namur',
              'Remouchamps', 'Waterloo']

    # distances in an upper triangular matrix
    dists = [[83, 81, 113, 52, 42, 73, 44, 23, 91, 105, 90, 124, 57],
             [161, 160, 39, 89, 151, 110, 90, 99, 177, 143, 193, 100],
             [90, 125, 82, 13, 57, 71, 123, 38, 72, 59, 82],
             [123, 77, 81, 71, 91, 72, 64, 24, 62, 63],
             [51, 114, 72, 54, 69, 139, 105, 155, 62],
             [70, 25, 22, 52, 90, 56, 105, 16],
             [45, 61, 111, 36, 61, 57, 70],
             [23, 71, 67, 48, 85, 29],
             [74, 89, 69, 107, 36],
             [117, 65, 125, 43],
             [54, 22, 84],
             [60, 44],
             [97],
             []]

    # number of nodes and list of vertices
    n, V = len(dists), set(range(len(dists)))

    # distances matrix
    c = [[0 if i == j
          else dists[i][j-i-1] if j > i
          else dists[j][i-j-1]
          for j in V] for i in V]

    model = Model()

    # binary variables indicating if arc (i,j) is used on the route or not
    x = [[model.add_var(var_type=BINARY) for j in V] for i in V]

    # continuous variable to prevent subtours: each city will have a
    # different sequential id in the planned route except the first one
    y = [model.add_var() for i in V]

    # objective function: minimize the distance
    model.objective = minimize(xsum(c[i][j]*x[i][j] for i in V for j in V))

    # constraint : leave each city only once
    for i in V:
        model += xsum(x[i][j] for j in V - {i}) == 1

    # constraint : enter each city only once
    for i in V:
        model += xsum(x[j][i] for j in V - {i}) == 1

    # subtour elimination
    for (i, j) in product(V - {0}, V - {0}):
        if i != j:
            model += y[i] - (n+1)*x[i][j] >= y[j]-n

    # optimizing
    model.optimize()

    # checking if a solution was found
    if model.num_solutions:
        out.write('route with total distance %g found: %s'
                  % (model.objective_value, places[0]))
        nc = 0
        while True:
            nc = [i for i in V if x[nc][i].x >= 0.99][0]
            out.write(' -> %s' % places[nc])
            if nc == 0:
                break
        out.write('\n')

def get_joint_nodes_dict(edges):
    nodes = {}
    ret = defaultdict(list)
    de_duplicate = defaultdict(set)
    for edge in edges:
        nodes[str(edge[0])] = edge[0]
        nodes[str(edge[1])] = edge[1]
        if str(edge[0])+str(edge[1]) not in de_duplicate[str(edge[0])]:
            ret[str(edge[0])].append(edge)
        else:
            de_duplicate[str(edge[0])].add(str(edge[0])+str(edge[1]))
        if str(edge[0])+str(edge[1]) not in de_duplicate[str(edge[1])]:
            ret[str(edge[1])].append(edge)
        else:
            de_duplicate[str(edge[1])].add(str(edge[0])+str(edge[1]))
    return ret, nodes


def test_smt():
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    # node0 = Node('g0|a0|v0')
    # node0.set_candidates(['1.1', '1.2'])
    # node1 = Node('g1|a1|v1')
    # node1.set_candidates(['1.1', '1.2', '1.3', '1.4', '1.5'])
    # node2 = Node('g2|a2|v2')
    # node2.set_candidates(['1.1', '1.2', '1.3'])
    # edges = [[node0, node1], [node2, node1]]


    node0 = Node('com.google.inject|guice|4.1.0')
    node0.set_candidates(['4.0', '4.1.0', '4.0-beta4', '4.2.0', '4.2.1', '4.2.2', '4.2.3'])
    node1 = Node('com.google.guava|guava|19.0')
    node1.set_candidates(['11.0.2', '12.0-rc1', '12.0', '13.0-rc1', '12.0.1', '13.0-rc2', '14.0.1', '16.0.1', '18.0-rc1', '19.0', '23.1-jre'])
    node2 = Node('com.alibaba.nacos|nacos-client|1.3.3')
    node2.set_candidates(['1.0.1', '1.1.0', '1.1.1', '1.1.3', '1.2.1', '1.3.0', '1.3.3'])
    edges = [[node0, node1], [node2, node1]]

    distance_smt(edges, c)
    a = 0

def calculate_all_dists(edges, c):
    maven_deps = c['library-crawler']['maven_deps']
    maven = c['library-crawler']['maven']
    dists = {}
    for edge in edges:

        g1, a1 = str(edge[0]).split('|')
        g2, a2 = str(edge[1]).split('|')

        # if g1+'|'+a1 == 'jakarta.validation|jakarta.validation-api' or g2+'|'+a2 == 'jakarta.validation|jakarta.validation-api':
        #     aa = 1
        versions2 = edge[1].get_all_versions(c)
        versions1 = edge[0].get_all_versions(c)
        cves_dict1 = get_cves_dict([edge[0].get_ga() + '|' + v for v in versions1])
        cves_dict2 = get_cves_dict([edge[1].get_ga() + '|' + v for v in versions2])
        compatible_versions = set(edge[1].get_candidates()).intersection(versions2)

        # for non central
        if edge[1].get_original_version() not in versions2:
            versions2.append(edge[1].get_original_version())
        versions2 = _sort(versions2)
        dists[str(edge[0])+'_'+str(edge[1])] = []
        for i, ver1 in enumerate(edge[0].get_all_versions(c)):
            default_version = get_default_version(parent_gav=g1+'|'+a1+'|'+ver1, dep_ga=g2+'|'+a2, c=c)
            # if default_version=='':

            tmp_list = []
            # its a range
            if ',' in default_version:
                ret = check_in_range(versions2, default_version)
                if len(ret) > 0:
                    default_version = ret[0]
            if default_version not in versions2:

                # raise DependencyVersionNotMatchError(g1+'|'+a1+'|'+ver1+"'s default version "+default_version+" is does not match for "+ g2+'|'+a2)
                # print(g1+'|'+a1+'|'+ver1+"'s default version "+ default_version +" does not match for "+ g2+'|'+a2)
                for j, candidate2 in enumerate(edge[1].get_all_versions(c)):
                    if candidate2 in compatible_versions:
                        score = abs(
                            versions2.index(candidate2) - versions2.index(edge[1].get_original_version()))
                        tmp_list.append(score)
                        score += len(cves_dict1.get(edge[0].get_ga()+ver1, []))*20
                        score += len(cves_dict2.get(edge[1].get_ga() + candidate2, [])) * 20
                    # tmp_list.append(0)
                    else:
                        tmp_list.append(1000)
                dists[str(edge[0]) + '_' + str(edge[1])].append(tmp_list)
            else:
                for j, candidate2 in enumerate(edge[1].get_all_versions(c)):
                    if candidate2 == edge[1].get_original_version():
                        dist = abs(
                            versions2.index(candidate2) - versions2.index(default_version))
                        dist += len(cves_dict1.get(edge[0].get_ga()+ver1, []))*20
                        dist += len(cves_dict2.get(edge[1].get_ga() + candidate2, [])) * 20
                        if dist !=0:
                            tmp_list.append(dist-0.5)
                        else:
                            tmp_list.append(dist)
                    if candidate2 in compatible_versions:
                        score = abs(
                            versions2.index(candidate2) - versions2.index(default_version))
                        tmp_list.append(score)
                        score += len(cves_dict1.get(edge[0].get_ga()+ver1, []))*20
                        score += len(cves_dict2.get(edge[1].get_ga() + candidate2, [])) * 20
                    else:
                        tmp_list.append(1000)

                dists[str(edge[0])+'_'+str(edge[1])].append(tmp_list)
    return dists

def calculate_dists(edges, c):
    maven_deps = c['library-crawler']['maven_deps']
    maven = c['library-crawler']['maven']
    dists = {}
    for edge in edges:

        g1, a1 = str(edge[0]).split('|')
        g2, a2 = str(edge[1]).split('|')

        # if g1+'|'+a1 == 'jakarta.validation|jakarta.validation-api' or g2+'|'+a2 == 'jakarta.validation|jakarta.validation-api':
        #     aa = 1
        versions2 = edge[1].get_candidates()#get_all_versions(g2 + '|' + a2, maven)
        # for non central
        if edge[1].get_original_version() not in versions2:
            versions2.append(edge[1].get_original_version())
        versions2 = _sort(versions2)
        dists[str(edge[0])+'_'+str(edge[1])] = []
        for i, ver1 in enumerate(edge[0].get_candidates()):
            default_version = get_default_version(parent_gav=g1+'|'+a1+'|'+ver1, dep_ga=g2+'|'+a2, c=c)
            # if default_version=='':

            tmp_list = []
            # its a range
            if ',' in default_version:
                ret = check_in_range(versions2, default_version)
                if len(ret) > 0:
                    default_version = ret[0]
            if default_version not in versions2:

                # raise DependencyVersionNotMatchError(g1+'|'+a1+'|'+ver1+"'s default version "+default_version+" is does not match for "+ g2+'|'+a2)
                # print(g1+'|'+a1+'|'+ver1+"'s default version "+ default_version +" does not match for "+ g2+'|'+a2)
                for j, candidate2 in enumerate(edge[1].get_candidates()):
                    tmp_list.append(abs(
                        versions2.index(candidate2) - versions2.index(edge[1].get_original_version())))
                    # tmp_list.append(0)
                dists[str(edge[0]) + '_' + str(edge[1])].append(tmp_list)
            else:
                for j, candidate2 in enumerate(edge[1].get_candidates()):
                    if candidate2 == edge[1].get_original_version():
                        dist = abs(
                            versions2.index(candidate2) - versions2.index(default_version))
                        if dist !=0:
                            tmp_list.append(dist-0.5)
                        else:
                            tmp_list.append(dist)
                    tmp_list.append(abs(
                        versions2.index(candidate2) - versions2.index(default_version)))

                dists[str(edge[0])+'_'+str(edge[1])].append(tmp_list)
    return dists


def all_smt(edges, c, depGraph):
    dists = calculate_all_dists(edges, c)
    joind_node_dict, nodes = get_joint_nodes_dict(edges)

    # lib1 = set(range(3))
    # lib2 = set(range(5))
    # lib3 = set(range(2))
    model = Model()
    variables = {}
    # add variables and constraints of one version chosen
    for edge in edges:
        lib1 = range(len(edge[0].get_candidates()))
        lib2 = range(len(edge[1].get_candidates()))
        ga1 = edge[0].get_ga()
        ga2 = edge[1].get_ga()
        x = [[model.add_var(name=ga1 + ':' + str(j) + '%' + ga2 + ':' + str(i), var_type=BINARY) for i in lib2] for j in
             lib1]
        variables[ga1 + '_' + ga2] = x
        model += xsum(x[j][i] for j in lib1 for i in lib2) == 1

    # Add multi edges -- one node constraint
    for node_name in joind_node_dict:
        node = nodes[node_name]
        if len(joind_node_dict[node_name]) > 1:
            first_edge = None
            first_range = None
            src_or_dst = ''
            for edge in joind_node_dict[node_name]:
                ga1 = edge[0].get_ga()
                ga2 = edge[1].get_ga()

                if edge[0] != node:
                    end_lib = range(len(edge[0].get_candidates()))
                    if not first_edge:
                        first_edge = variables[ga1 + '_' + ga2]
                        first_range = range(len(edge[0].get_candidates()))
                        src_or_dst = 'src'
                        continue
                    else:
                        for i in range(len(node.get_candidates())):
                            if src_or_dst == 'src':
                                model += xsum(first_edge[j][i] for j in first_range) == xsum(
                                    variables[ga1 + '_' + ga2][k][i] for k in end_lib)
                            elif src_or_dst == 'dst':
                                model += xsum(first_edge[i][j] for j in first_range) == xsum(
                                    variables[ga1 + '_' + ga2][k][i] for k in end_lib)
                    continue
                if edge[1] != node:
                    end_lib = range(len(edge[1].get_candidates()))
                    if not first_edge:
                        first_edge = variables[ga1 + '_' + ga2]
                        first_range = range(len(edge[1].get_candidates()))
                        src_or_dst = 'dst'
                        continue
                    else:
                        for i in range(len(node.get_candidates())):
                            if src_or_dst == 'src':
                                model += xsum(first_edge[j][i] for j in first_range) == xsum(
                                    variables[ga1 + '_' + ga2][i][k] for k in end_lib)
                            elif src_or_dst == 'dst':
                                model += xsum(first_edge[i][j] for j in first_range) == xsum(
                                    variables[ga1 + '_' + ga2][i][k] for k in end_lib)
                    continue

    # Calcualte objective
    objectives = []
    for edge in edges:
        ga1 = edge[0].get_ga()
        ga2 = edge[1].get_ga()
        lib1 = range(len(edge[0].get_candidates()))
        lib2 = range(len(edge[1].get_candidates()))
        objectives.append(
            xsum(dists[ga1 + '_' + ga2][i][j] * variables[ga1 + '_' + ga2][i][j] for i in lib1 for j in lib2))

    model.objective = minimize(xsum(
        objectives)
    )

    # binary variables indicating if arc (i,j) is used on the route or not
    # x = [[model.add_var(name='lib1_'+str(j)+'lib2_'+str(i), var_type=BINARY) for i in lib2]for j in lib1]
    # y = [[model.add_var(name='lib3_'+str(j)+'lib2_'+str(i), var_type=BINARY) for i in lib2]for j in lib3]
    # x = model.add_var(name='lib1', var_type=INTEGER, lb=0, ub=2)
    # y = model.add_var(name='lib2', var_type=INTEGER, lb=0, ub=4)

    # model.objective = minimize(xsum(
    #     dists1[i][j]*x[i][j] for i in lib1 for j in lib2) +xsum(dists0[k][j]*y[k][j] for j in lib2 for k in lib3)
    # )
    # model.objective = minimize(dists[x.][y])

    # model += xsum(x[j][i] for j in lib1 for i in lib2) == 1
    # model += xsum(y[j][i] for j in lib3 for i in lib2) == 1
    # for i in lib2:
    #     model += xsum(y[j][i]for j in lib3) == xsum(x[k][i] for k in lib1)
    status = model.optimize(max_seconds=300)
    if status == OptimizationStatus.OPTIMAL:
        print('optimal solution cost {} found'.format(model.objective_value))
    elif status == OptimizationStatus.FEASIBLE:
        print('sol.cost {} found, best possible: {}'.format(model.objective_value, model.objective_bound))
    elif status == OptimizationStatus.NO_SOLUTION_FOUND:
        print('no feasible solution found, lower bound is: {}'.format(model.objective_bound))
    if status == OptimizationStatus.OPTIMAL or status == OptimizationStatus.FEASIBLE:
        print('solution:')
        for v in model.vars:
            if abs(v.x) > 1e-6:  # only printing non-zeros
                print('{} : {}'.format(v.name, v.x))
    for v in model.vars:
        if abs(v.x) > 1e-6:  # only printing non-zeros
            gav1, gav2 = v.name.split('%')
            ga1, v1_index = gav1.split(':')
            ga2, v2_index = gav2.split(':')
            nodes[ga1].set_preferred(nodes[ga1].get_candidates()[int(v1_index)])
            nodes[ga2].set_preferred(nodes[ga2].get_candidates()[int(v2_index)])

    for node in nodes.values():
        if node.get_preferred() == None:
            node.set_preferred(node.get_original_version())
        new_nodes = depGraph.reset_sons_by_preferred(node, c)
        for n in new_nodes:
            depGraph.add_new_node_by_smt(n)


def distance_smt(edges, c, depGraph):

    # dists ={'g0|a0_g1|a1':
    #             [[1, 3, 3, 5, 7],
    #             [6, 1, 0,4,6]],
    #         'g2|a2_g1|a1':
    #             [[2, 2, 3, 5, 7],
    #             [3, 1, 1,7,9],
    #             [3,1,1,6,8]]}
    dists = calculate_dists(edges, c)
    joind_node_dict, nodes = get_joint_nodes_dict(edges)

    # lib1 = set(range(3))
    # lib2 = set(range(5))
    # lib3 = set(range(2))
    model = Model()
    variables = {}
    # add variables and constraints of one version chosen
    for edge in edges:
        lib1 = range(len(edge[0].get_candidates()))
        lib2 = range(len(edge[1].get_candidates()))
        ga1 = edge[0].get_ga()
        ga2 = edge[1].get_ga()
        x = [[model.add_var(name=ga1+':' + str(j) +'%'+ ga2 +':' + str(i), var_type=BINARY) for i in lib2] for j in lib1]
        variables[ga1+'_'+ga2] = x
        model += xsum(x[j][i] for j in lib1 for i in lib2) == 1

    # Add multi edges -- one node constraint
    for node_name in joind_node_dict:
        node = nodes[node_name]
        if len(joind_node_dict[node_name]) > 1:
            first_edge = None
            first_range = None
            src_or_dst = ''
            for edge in joind_node_dict[node_name]:
                ga1 = edge[0].get_ga()
                ga2 = edge[1].get_ga()

                if edge[0]!=node:
                    end_lib = range(len(edge[0].get_candidates()))
                    if not first_edge:
                        first_edge = variables[ga1+'_'+ga2]
                        first_range = range(len(edge[0].get_candidates()))
                        src_or_dst = 'src'
                        continue
                    else:
                        for i in range(len(node.get_candidates())):
                            if src_or_dst == 'src':
                                model += xsum(first_edge[j][i] for j in first_range) == xsum(
                                    variables[ga1+'_'+ga2][k][i] for k in end_lib)
                            elif src_or_dst == 'dst':
                                model += xsum(first_edge[i][j] for j in first_range) == xsum(
                                    variables[ga1 + '_' + ga2][k][i] for k in end_lib)
                    continue
                if edge[1] != node:
                    end_lib = range(len(edge[1].get_candidates()))
                    if not first_edge:
                        first_edge = variables[ga1 + '_' + ga2]
                        first_range = range(len(edge[1].get_candidates()))
                        src_or_dst = 'dst'
                        continue
                    else:
                        for i in range(len(node.get_candidates())):
                            if src_or_dst == 'src':
                                model += xsum(first_edge[j][i] for j in first_range) == xsum(
                                    variables[ga1 + '_' + ga2][i][k] for k in end_lib)
                            elif src_or_dst == 'dst':
                                model += xsum(first_edge[i][j] for j in first_range) == xsum(
                                    variables[ga1 + '_' + ga2][i][k] for k in end_lib)
                    continue

    # Calcualte objective
    objectives = []
    for edge in edges:
        ga1 = edge[0].get_ga()
        ga2 = edge[1].get_ga()
        lib1 = range(len(edge[0].get_candidates()))
        lib2 = range(len(edge[1].get_candidates()))
        objectives.append(xsum(dists[ga1+'_'+ga2][i][j]*variables[ga1+'_'+ga2][i][j] for i in lib1 for j in lib2))

    model.objective = minimize(xsum(
        objectives)
    )





    # binary variables indicating if arc (i,j) is used on the route or not
    # x = [[model.add_var(name='lib1_'+str(j)+'lib2_'+str(i), var_type=BINARY) for i in lib2]for j in lib1]
    # y = [[model.add_var(name='lib3_'+str(j)+'lib2_'+str(i), var_type=BINARY) for i in lib2]for j in lib3]
    # x = model.add_var(name='lib1', var_type=INTEGER, lb=0, ub=2)
    # y = model.add_var(name='lib2', var_type=INTEGER, lb=0, ub=4)

    # model.objective = minimize(xsum(
    #     dists1[i][j]*x[i][j] for i in lib1 for j in lib2) +xsum(dists0[k][j]*y[k][j] for j in lib2 for k in lib3)
    # )
    # model.objective = minimize(dists[x.][y])


    # model += xsum(x[j][i] for j in lib1 for i in lib2) == 1
    # model += xsum(y[j][i] for j in lib3 for i in lib2) == 1
    # for i in lib2:
    #     model += xsum(y[j][i]for j in lib3) == xsum(x[k][i] for k in lib1)
    status = model.optimize(max_seconds=300)
    if status == OptimizationStatus.OPTIMAL:
        print('optimal solution cost {} found'.format(model.objective_value))
    elif status == OptimizationStatus.FEASIBLE:
        print('sol.cost {} found, best possible: {}'.format(model.objective_value, model.objective_bound))
    elif status == OptimizationStatus.NO_SOLUTION_FOUND:
        print('no feasible solution found, lower bound is: {}'.format(model.objective_bound))
    if status == OptimizationStatus.OPTIMAL or status == OptimizationStatus.FEASIBLE:
        print('solution:')
        for v in model.vars:
            if abs(v.x) > 1e-6:  # only printing non-zeros
                print('{} : {}'.format(v.name, v.x))
    for v in model.vars:
        if abs(v.x) > 1e-6:  # only printing non-zeros
            gav1, gav2 = v.name.split('%')
            ga1, v1_index = gav1.split(':')
            ga2, v2_index = gav2.split(':')
            nodes[ga1].set_preferred(nodes[ga1].get_candidates()[int(v1_index)])
            nodes[ga2].set_preferred(nodes[ga2].get_candidates()[int(v2_index)])

    for node in nodes.values():
        if node.get_preferred()==None:
            node.set_preferred(node.get_original_version())
        new_nodes = depGraph.reset_sons_by_preferred(node, c)
        for n in new_nodes:

            depGraph.add_new_node_by_smt(n)

