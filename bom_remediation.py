from moo import solver
from bom_evaluation import pre_compute_subgraphs, evaluate, pre_evaluate
from evaluation.get_dep_tree import serialize_subgraph
from jar_config import jar, user_ga
import pymongo
from config import mongodb_port, mongodb_host


def symbolize_subgraph(subgraph, c):
    moo_mapping = c['remediation']['moo_mapping']
    mapping = {'key': 'mapping'}
    maven = c['library-crawler']['maven']
    upperbounds = []
    for node in serialize_subgraph(subgraph):
        if user_ga in node:
            continue
        g,a,v = node.split('|')
        docs = maven.find({'group': g, 'artifact': a})
        if docs:
            mapping[node] = {}
            count = 0
            for doc in docs:
                mapping[node][str(count)] = doc['version']
                count+=1
            upperbounds.append([node, count])

    # moo_mapping only has one doc
    moo_mapping.delete_many({})
    moo_mapping.insert_one({'key': 'order', 'order': [each[0] for each in upperbounds]}, bypass_document_validation=True)
    moo_mapping.insert_one(mapping, bypass_document_validation=True)
    return upperbounds






def remediation(original_path, original_jar, test_path=None):
    # name = jar.split("/")[-1].replace('-jar-with-dependencies.jar', '')
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    subgraphs = pre_compute_subgraphs(c, original_path)

    for subgraph in subgraphs:
        if len(subgraph['cves'])==0:
            continue
        pre_evaluate(c, subgraph, original_jar, '0')
        upperbounds = symbolize_subgraph(subgraph, c)
        solver(c, upperbounds)
        break
    c.close()