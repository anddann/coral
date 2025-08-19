import csv
import json
import os
import subprocess
import random
from pprint import pprint

import pymongo

from benchmark.benchmark import clear_placeHolder
from bom_evaluation import pre_compute_subgraphs
from config import project_path, mongodb_port, mongodb_host, working_dir
import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt

from evaluation.get_dep_tree import get_mvn_dep_tree
from utils.version_utils import is_major, is_dev


def get_size_of_deps():
    depset = set()
    for project in project_path:
        print(project)
        print(len(depset))

        deps, edges, root = get_mvn_dep_tree(clear_placeHolder(project_path, project)[project]['original'])
        keys = set()
        for k in deps.keys():
            g,a,v = k.split('|')
            keys.add(g+'|'+a)

        depset = depset.union(keys)
    with open(working_dir+'data/all_deps_ga.json', 'w') as f:
        f.write(json.dumps(list(depset)))

def get_unfixed_cve():
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    benchmark_coll = c['remediation']['benchmark_metrics']
    for doc in benchmark_coll.find({'order':'Tool'}):
        doc['library']

def get_overlapping_steady_cve():
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)

    steady_cve = set()
    for l in csv.reader(open('steady_res/cve list.csv')):
        steady_cve.add(l[0])

    benchmark_coll = c['remediation']['benchmark_metrics']
    unsure = 0
    unreach = 0
    reach = 0
    dyed = set(['CVE-2016-9878',
'CVE-2019-0231',
'CVE-2014-0054',
'CVE-2020-13692',
'CVE-2020-7238',
'CVE-2018-8088',
'CVE-2020-11612',
'CVE-2016-4970',
'CVE-2019-10086',
'CVE-2021-44832',
'CVE-2021-29425',
'CVE-2018-10936',
'CVE-2018-17196',
'CVE-2020-5421',
'CVE-2018-10237',
'CVE-2015-3192'
               ])
    # for d in dyed:
    #     if d not in steady_cve:
    #         print(d)
    # exit()
    for doc in benchmark_coll.find({'order':'steady'}):
        if 'unsure_cves' not in doc:
            continue
        # print(doc['project'])
        unsure += len(steady_cve.intersection(doc['unsure_cves']))
        unreach +=len(steady_cve.intersection(doc['unreachable_cves']))

        reach += len(steady_cve.intersection(doc['reachable_cves']))

    print(unsure)
    print(reach)
    print(unreach)
    c.close()
    # print(len(unreach.intersection(steady_cve)))
    # print(len(reach))
    # print(len(reach.intersection(steady_cve)))

def count_reasons_4_unreach_unsure_vuls(large_scale=False):
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    if large_scale:
        benchmark_coll = c['remediation']['large_scale_metrics']
    else:
        benchmark_coll = c['remediation']['benchmark_metrics']
    # reasons count:
    is_major_reason = []
    no_clean = []
    not_compatible = []

    fixable = {'major':0,
               'minor':0,
               'patch': 0,
               'unknown': 0,
               'pre': 0,
               'removed':0,
               'direct':0,
               'indirect': 0
               }
    is_dev_reason = []
    for doc in benchmark_coll.find({'order': 'Tool'}):
        print(doc['project'])
        if 'maven_' in doc['project']:
            break
        for gav in doc['cve_dict']:
            g,a,v = gav.split('|')
            if doc['cve_dict'][gav]['cleanvers'] == []:
                no_clean.extend(doc['cve_dict'][gav]['cves'])
            else:
                not_com = False
                for clean_ver in doc['cve_dict'][gav]['cleanvers']:
                    if (not is_major(clean_ver, v)) and (not is_dev(clean_ver)):
                        not_compatible.extend(doc['cve_dict'][gav]['cves'])
                        not_com =True
                        break
                if not not_com:
                    is_major_reason.extend(doc['cve_dict'][gav]['cves'])
        if 'fixable' not in doc:
            continue
        fixable['major'] += doc['fixable']['major']
        fixable['minor'] += doc['fixable']['minor']
        fixable['patch'] += doc['fixable']['patch']
        fixable['pre'] += doc['fixable']['prerelease']
        fixable['unknown'] += doc['fixable']['unknown_upgrades']
        fixable['removed'] += doc['fixable'].get('removed_old_ver', 0)
        fixable['direct'] += doc['fixable']['direct_dep']
        fixable['indirect'] += doc['fixable']['indirect_dep']
    print(len(is_major_reason))
    print(len(no_clean))
    print(len(not_compatible))
    pprint(fixable)

