import json
import os
import pickle
from collections import defaultdict

from benchmark.benchmark import clear_placeHolder
from bom_evaluation import get_libvers
from utils.pom_modifier import update_pom
from config import project_path, working_dir


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
    start = False
    for project in project_path:
        if project == 'maven_apache':
            start = True

        if not start:
            continue
        print(project)
        with open(working_dir + 'remediation_results/' + project.replace('/', '_')+'_baseline', 'rb') as handle:
            edges = pickle.load(handle)
        # for ga in new_libvers:
        #     # ga+'|'+depGraph.get_node().get_original_version()
        new_libvers = get_libvers(edges)
        res = new_libvers
        test_path = clear_placeHolder(project_path, project)[project]['baseline']

        print(test_path)
        if '_baseline' not in test_path:
            exit()
        os.chdir(test_path)
        for k, ver in res.items():
            # ga = k.replace('|', ':')
            # g, a = k.split('|')
            # os.system('mvn versions:use-dep-version -Dincludes=' + ga + ' -DdepVersion=' + list(v)[
            #     0] + ' -DforceVersion=true')
            # os.system('mvn versions:update-property -DnewVersion=' + list(v)[
            #     0] + ' -Dproperty=' + a + '.version  -DallowDowngrade=true')
            update_pom(os.path.join(test_path, 'pom.xml'), [k + '|' + ver], {k: ver})
            # os.chdir('/Users/lyuye/workspace/remediation/' + project_address[i] + '_snyk/')
# parse()