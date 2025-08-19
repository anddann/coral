import json
import os
import pickle
from collections import defaultdict

import pymongo

from benchmark.benchmark import clear_placeHolder, testing_compilation_test
from bom_evaluation import get_libvers
from utils.pom_modifier import update_pom
from config import project_path, working_dir, mongodb_host, mongodb_port


def parse():
    project = 'hutool_system'
    if '/' in project:
        project  = project.replace('/', '-')
    with open('../remediation_results/'+project+'_snyk.json', 'w') as fw, open('../snyk/tmp') as f:
        out = []
        for lin in f.readlines():
            one = {}
            line = lin.strip()
            _,old,_,new = line.split(' ')


            one['old'] = old.replace(':', '|').replace('@', '|')

            one['new'] = new.replace(':', '|').replace('@', '|')
            out.append(one)

        fw.write(json.dumps(out))
    print(out)
def apply():
    # projects = ['activemq', 'apollo', 'canal', 'druid', 'guava', 'hutool', 'log4j', 'mall', 'netty', 'seata', 'spring-boot-demo']
    # project_address = ['activemq', 'apollo', 'canal', 'druid', 'guava', 'hutool', 'logging-log4j2', 'mall', 'netty', 'seata', 'spring-boot-demo']
    start = False
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    benchmark = c['remediation']['benchmark_metrics']
    for project in project_path:
        if project == 'seata_server':
            start = True
        if not project.startswith('seata'):
            start = False
        if not start:
            continue
        doc = benchmark.find_one({'order': 'Tool', 'project': project})
        if doc['compilation'] == True and doc['unit_test'] == True:
            continue
        print(project)
        if not os.path.exists(working_dir + 'remediation_results/' + project.replace('/', '_')):
            # print(project)
            continue
        # else:
        #     continue
        with open(working_dir + 'remediation_results/' + project.replace('/', '_'), 'rb') as handle:
            depGraph = pickle.load(handle)

        depGraph.check_preferred()
        new_libvers = get_libvers(depGraph.get_edges())
        # for ga in new_libvers:
        #     # ga+'|'+depGraph.get_node().get_original_version()
        res = new_libvers
        test_path = clear_placeHolder(project_path, project)[project]['test']

        # print(test_path)
        if '_test' not in test_path:
            exit()
        os.chdir(test_path)
        os.system('git stash push pom.xml')
        for k, ver in res.items():
            # ga = k.replace('|', ':')
            # g, a = k.split('|')
            # os.system('mvn versions:use-dep-version -Dincludes=' + ga + ' -DdepVersion=' + list(v)[
            #     0] + ' -DforceVersion=true')
            # os.system('mvn versions:update-property -DnewVersion=' + list(v)[
            #     0] + ' -Dproperty=' + a + '.version  -DallowDowngrade=true')
            if k == 'org.springframework.boot|spring-boot-starter-web':
                ver = '2.3.3.RELEASE'
            update_pom(os.path.join(test_path, 'pom.xml'), [k+'|'+ver], {k: ver})
            # os.chdir('/Users/lyuye/workspace/remediation/' + project_address[i] + '_snyk/')
        print('[INFO] ~~ Finish apply remediation:', project)
        testing_compilation_test(project)
def apply_one(project):
    if not os.path.exists(working_dir + 'remediation_results/' + project.replace('/', '_')):
        # print(project)
        return
    # else:
    #     continue
    with open(working_dir + 'remediation_results/' + project.replace('/', '_'), 'rb') as handle:
        depGraph = pickle.load(handle)

    depGraph.check_preferred()
    new_libvers = get_libvers(depGraph.get_edges())
    # for ga in new_libvers:
    #     # ga+'|'+depGraph.get_node().get_original_version()
    res = new_libvers
    test_path = clear_placeHolder(project_path, project)[project]['test']

    # print(test_path)
    if '_test' not in test_path:
        exit()
    os.chdir(test_path)
    os.system('git stash push pom.xml')
    for k, ver in res.items():
        # ga = k.replace('|', ':')
        # g, a = k.split('|')
        # os.system('mvn versions:use-dep-version -Dincludes=' + ga + ' -DdepVersion=' + list(v)[
        #     0] + ' -DforceVersion=true')
        # os.system('mvn versions:update-property -DnewVersion=' + list(v)[
        #     0] + ' -Dproperty=' + a + '.version  -DallowDowngrade=true')
        if k == 'org.springframework.boot|spring-boot-starter-web':
            ver = '2.3.3.RELEASE'
        update_pom(os.path.join(test_path, 'pom.xml'), [k + '|' + ver], {k: ver})
    # print('[INFO] ~~ Finish apply remediation:', project)
    # testing_compilation_test(project)
# apply()
# parse()