import concurrent
import pymongo
import os
import csv
import signal
from collections import defaultdict
from jar_config import jar_path
from config import m2_path, MONGO_HOST, MONGO_PORT
from reachable_incompatibilities_no_entry import generate_csv
from download_all_jar import download_one_jar
def get_root_callees(root_jar):
    if not os.path.exists(root_jar):
        print('[WARNING] Root jar not exits:', root_jar)
        return set()
        # raise FileNotFoundError('Root jar not exits:', root_jar)
    edge_csv, namelist_csv, error = generate_csv(root_jar)
    callees = set()
    with open(edge_csv) as f:
        for i in csv.reader(f):
            callees.add(i[1])
    return callees

def get_callees(dep, parent_callers, callgraph_db_direct, callgraph_db_all):
    def handler(signum, frame):
        raise Exception("Timeout")
    if len(parent_callers)==0:
        return set()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(600)
    deps = dict()
    ret = set()
    try:
        g,a,v = dep.split('|')
        docs = None
        if callgraph_db_all is not None:
            try:
                coll = callgraph_db_all[g+'|'+a]
                coll.create_index('version')
                docs = coll.find_one({'version': v})
            except Exception:
                docs = None

        # if 'druid' in dep:
        #     print('')
        regen = False
        if docs:
            print('Retrieving from mongo:', dep, '\r', end='',flush=True)
            docs = coll.find({'version': v})
            deps = dict()
            for doc in docs:
                deps = {**deps, **doc['deps']}
            if len(deps) ==0 and doc.get('timeout', False)==False and doc.get('error', False)==False:
                regen =True
        else:
            regen = True
        if regen:
            if os.path.exists(m2_path+'/'+g.replace('.', '/')+'/'+a +'/'+v+'/'+a +'-' + v + '.jar'):
                edge_csv, namelist_csv, error = generate_csv(m2_path+'/'+g.replace('.', '/')+'/'+a +'/'+v+'/'+a +'-' + v + '.jar')
            elif os.path.exists(os.path.join(jar_path, a+'-'+v+'.jar')):
                edge_csv, namelist_csv, error = generate_csv(os.path.join(jar_path, a+'-'+v+'.jar'))
            else:
                download_one_jar(dep)
                edge_csv, namelist_csv, error = generate_csv(os.path.join(jar_path, a + '-' + v + '.jar'))

            direct_calls = defaultdict(list)
            edges = []
            for line in csv.reader(open(edge_csv)):
                edges.append(line)
                direct_calls[line[0]].append(line[1])
            if callgraph_db_direct is not None:
                try:
                    callgraph_db_direct[g+'|'+a].update_many({
                        'version': v},{'$set':{
                        'deps': direct_calls,
                        'error': error
                    }},upsert=True)
                except Exception:
                    pass
            indirect_calls = dict()
            for key in direct_calls:
                callees = set()
                next = {key}
                visited = set()
                while(len(next)>0):
                    tmp = {*next}
                    next = set()
                    for caller in tmp:
                        if caller not in visited:
                            next = next.union(direct_calls.get(caller,{}))
                            callees = callees.union(direct_calls.get(caller,{}))
                            visited.add(caller)
                indirect_calls[key] = list(callees)

            if callgraph_db_all is not None:
                try:
                    callgraph_db_all[g+'|'+a].update_many({
                    'version': v},{'$set':{
                    'deps': indirect_calls,
                    'error': error
                }},upsert=True)
                except:
                    batch = {}
                    try:
                        for key in indirect_calls:
                            batch[key] = indirect_calls[key]
                            if len(batch.keys()) == 10:
                                callgraph_db_all[g + '|' + a].update_many({
                                    'version': v},{'$set':{
                                    'deps': batch,
                                    'error': error
                                }},upsert=True)
                                batch = {}
                        callgraph_db_all[g + '|' + a].update_many({
                                    'version': v},{'$set':{
                                    'deps': batch,
                                    'error': error
                                }},upsert=True)
                        callgraph_db_all[g + '|' + a].create_index('version')
                    except:
                        for key in indirect_calls:
                            try:
                                callgraph_db_all[g + '|' + a].update_many({
                                    'version': v}, {'$set': {
                                    'deps': {key: indirect_calls[key]},
                                    'error': error
                                }}, upsert=True)
                            except Exception:
                                pass
                        try:
                            callgraph_db_all[g + '|' + a].create_index('version')
                        except Exception:
                            pass
            deps = indirect_calls


        for each in parent_callers:
            ret = ret.union(deps.get(each, set()))
        signal.alarm(0)
        return ret
    except Exception as exc:
        print('[ERROR] Callgraph timeout', exc)
        docs = coll.find({'version': v})
        if not docs:
            callgraph_db_all[g + '|' + a].insert_one({
                'version': v,
                'deps': [],
                'timeout': True
            })
        signal.alarm(0)
        return ret
    signal.alarm(0)
    return set()




def create_call_graph(edges, root, root_jar):
    try:
        c = pymongo.MongoClient(MONGO_HOST,
                                port=int(MONGO_PORT),
                                serverSelectionTimeoutMS=1000)
        callgraph_db_direct = c['call_graphs_direct']
        callgraph_db_all = c['call_graphs_all']
    except Exception:
        c = None
        callgraph_db_direct = None
        callgraph_db_all = None
    visisted = set()
    graph = {}
    graph[root] = get_root_callees(root_jar)
    next = {root}

    # Dictionarize edges
    dependency_edges = defaultdict(list)
    for edge in edges:
        dependency_edges[edge[0]].append(edge[1])
    count = 1
    while(len(next)>0):
        tmp = {*next}
        next = set()
        for single_dep in tmp:
            visisted.add(single_dep)
            deps = dependency_edges.get(single_dep, set())
            for dep in deps:
                if len(graph[single_dep]) ==0:
                    graph[dep] = set()
                else:
                    graph[dep] = get_callees(dep, graph[single_dep], callgraph_db_direct, callgraph_db_all)
                count+=1
                print('Graph derived: ', count, '\r', end='', flush=True)
                if dep not in visisted:
                    next.add(dep)
    ret = set()
    for key in graph:
        ret|=graph[key]
    if c is not None:
        c.close()
    return ret

def create_call_graph_dict(edges, root, root_jar):
    try:
        c = pymongo.MongoClient(MONGO_HOST,
                                port=int(MONGO_PORT),
                                serverSelectionTimeoutMS=1000)
        callgraph_db_direct = c['call_graphs_direct']
        callgraph_db_all = c['call_graphs_all']
    except Exception:
        c = None
        callgraph_db_direct = None
        callgraph_db_all = None
    visisted = set()
    graph =defaultdict(set)
    graph[root] = get_root_callees(root_jar)
    next = {root}

    # Dictionarize edges
    dependency_edges = defaultdict(list)
    for edge in edges:
        dependency_edges[edge[0]].append(edge[1])
    count = 1
    while(len(next)>0):
        tmp = {*next}
        next = set()
        for single_dep in tmp:
            visisted.add(single_dep)
            deps = dependency_edges.get(single_dep, set())
            # with concurrent.futures.ProcessPoolExecutor() as executor:
            #     future_name = {executor.submit(get_callees, dep, graph[single_dep], callgraph_db_direct, callgraph_db_all): dep for dep in
            #                    deps}
            #     for future in concurrent.futures.as_completed(future_name):
            #         dep = future.result()[1]
            #         graph[dep] = future.result()[0]
            #         count += 1
            #         print('Graph derived: ', count, '\r', end='', flush=True)
            #         if dep not in visisted:
            #             next.add(dep)

            for dep in deps:
                # if dep == 'org.elasticsearch|elasticsearch|7.3.0':
                #     ccc = 1
                if len(graph[single_dep])!=0:
                    graph[dep] = graph[dep].union(get_callees(dep, graph[single_dep], callgraph_db_direct, callgraph_db_all))
                else:
                    graph[dep] = graph[dep].union(set())
                count+=1
                print('Graph derived: ', count, '\r', end='', flush=True)
                if dep not in visisted:
                    next.add(dep)
    if c is not None:
        c.close()

    # remove version from keys
    ret = {}
    for key in graph:
        if key.count('|') == 3:
            gavsp = key.split('|')
            g,a,v= gavsp[0], gavsp[1], gavsp[3]
        else:
            g, a, v = key.split('|')
        # g,a,v = key.split('|')
        ret[g+'|'+a] = list(graph[key])
    return ret


def generate_call_graph2DB():
    c = pymongo.MongoClient(MONGO_HOST,
                            port=MONGO_PORT)
    callgraph_db_direct = c['call_graphs_direct']
    callgraph_db_all = c['call_graphs_all']
    maven = c['library-crawler']['maven']
    gav = 'org.eclipse.jetty|jetty-servlet|8.0.1.v20110908'
    g,a,v = gav.split('|')
    gavs = []
    for doc in maven.find({
        'group': g,
        'artifact': a
    }):
        gavs.append([g,a,doc['version']])
    for each in gavs:
        g,a,v = each
        if os.path.exists(m2_path + '/' + g.replace('.', '/') + '/' + a + '/' + v + '/' + a + '-' + v + '.jar'):
            edge_csv, namelist_csv, error = generate_csv(
                m2_path + '/' + g.replace('.', '/') + '/' + a + '/' + v + '/' + a + '-' + v + '.jar')
        elif os.path.exists(os.path.join(jar_path, a + '-' + v + '.jar')):
            edge_csv, namelist_csv, error = generate_csv(os.path.join(jar_path, a + '-' + v + '.jar'))
        else:
            download_one_jar(gav)
            edge_csv, namelist_csv, error = generate_csv(os.path.join(jar_path, a + '-' + v + '.jar'))

        direct_calls = defaultdict(list)
        edges = []
        for line in csv.reader(open(edge_csv)):
            edges.append(line)
            direct_calls[line[0]].append(line[1])
        callgraph_db_direct[g + '|' + a].insert_one({
            'version': v,
            'deps': direct_calls
        })
        indirect_calls = {}
        for key in direct_calls:
            callees = set()
            next = {key}
            visited = set()
            while (len(next) > 0):
                tmp = {*next}
                next = set()
                for caller in tmp:
                    if caller not in visited:
                        next = next.union(direct_calls.get(caller, {}))
                        callees = callees.union(direct_calls.get(caller, {}))
                        visited.add(caller)
            indirect_calls[key] = list(callees)
        callgraph_db_all[g + '|' + a].insert_one({
            'version': v,
            'deps': indirect_calls
        })
        callgraph_db_all[g + '|' + a].create_index('version')
    if c is not None:
        c.close()

