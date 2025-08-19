import json
import os
from collections import defaultdict
from benchmark.benchmark import clear_placeHolder
from utils.pom_modifier import update_pom
from config import project_path, working_dir, testcases_dir

# def parse():
#     project = 'hutool_system'
#     if '/' in project:
#         project  = project.replace('/', '-')
#     with open('../remediation_results/'+project+'_snyk.json', 'w') as fw, open('../snyk/tmp') as f:
#         out = []
#         for lin in f.readlines():
#             one = {}
#             line = lin.strip()
#             _,old,_,new = line.split(' ')
#
#
#             one['old'] = old.replace(':', '|').replace('@', '|')
#
#             one['new'] = new.replace(':', '|').replace('@', '|')
#             out.append(one)
#
#         fw.write(json.dumps(out))
#     print(out)
def apply():

    projects = ['activemq', 'apollo', 'canal', 'druid', 'guava', 'hutool', 'log4j', 'mall', 'netty', 'seata', 'spring-boot-demo']
    project_address = ['activemq', 'apollo', 'canal', 'druid', 'guava', 'hutool', 'logging-log4j2', 'mall', 'netty', 'seata', 'spring-boot-demo']
    start = False
    for project in project_path:
        if project == 'maven_apache':
            start = True

        if not start:
            continue
        print(project)
        with open(working_dir + 'remediation_results/' + project.replace('/', '-')+'_scantist.json', 'r') as handle:
            res = json.load(handle)

        new_libvers = {}
        for each in res:
            g, a, v = each['new'].split('|')
            new_libvers[g+'|'+a] = v
        # for ga in new_libvers:
        #     # ga+'|'+depGraph.get_node().get_original_version()
        res = new_libvers
        test_path = clear_placeHolder(project_path, project)[project]['snyk'].replace('_snyk', '_scantist')

        print(test_path)
        if '_scantist' not in test_path:
            exit()
        os.chdir(test_path)
        for k, ver in res.items():
            # ga = k.replace('|', ':')
            # g, a = k.split('|')
            # os.system('mvn versions:use-dep-version -Dincludes=' + ga + ' -DdepVersion=' + list(v)[
            #     0] + ' -DforceVersion=true')
            # os.system('mvn versions:update-property -DnewVersion=' + list(v)[
            #     0] + ' -Dproperty=' + a + '.version  -DallowDowngrade=true')
            update_pom(os.path.join(test_path, 'pom.xml'), [k+'|'+ver], {k: ver})
            # os.chdir('/Users/lyuye/workspace/remediation/' + project_address[i] + '_snyk/')


    # for i, project in enumerate(projects):
    #     res = defaultdict(set)
    #     project_paths = {}
    #     for f in os.listdir(working_dir+'remediation_results'):
    #         if 'scantist' in f and f.startswith(project):
    #             with open(working_dir+'remediation_results/'+f) as p:
    #                 rem = json.load(p)
    #                 for each in rem:
    #                     if 'new' in each:
    #                         new = each['new']
    #                         g,a,v = new.split('|')
    #                         submodule = f.replace('_scantist.json', '').split('_')[-1]
    #                         # if the project contains '/', this path derivation would fail
    #                         project_paths[new] = project_path[f.replace('_scantist.json', '')]['snyk'].replace('PLACEHOLDER', submodule).replace('_snyk', '_scantist')
    #                         res[g+'|'+a].add(v)
    #     manual = []
    #     deps = list()
    #     os.chdir(testcases_dir+project_address[i]+'_scantist/')
    #     for k, v in res.items():
    #         print(len(v), k)
    #         g, a = k.split('|')
    #         ga = k.replace('|', ':')
    #         if len(v) >1:
    #             for i, ver in enumerate(v):
    #                 if i == 0:
    #                     continue
    #                 os.chdir(project_paths[k+'|'+ver])
    #                 print(k+'|'+ver, project_paths[k+'|'+ver])
    #                 os.system('mvn versions:use-dep-version -Dincludes=' + ga + ' -DdepVersion=' + list(v)[
    #                     0] + ' -DforceVersion=true')
    #                 os.system('mvn versions:update-property -DnewVersion=' + list(v)[
    #                     0] + ' -Dproperty=' + a + '.version  -DallowDowngrade=true')
    #                 update_pom(project_paths[k+'|'+ver]+'pom.xml', [k+'|'+ver], {k: ver})
    #                 os.chdir(testcases_dir + project_address[i] + '_scantist/')
    #         deps.append(k+'|'+list(v)[0])
    #         os.system('mvn versions:use-dep-version -Dincludes='+ga+' -DdepVersion='+list(v)[0] +' -DforceVersion=true')
    #         os.system('mvn versions:update-property -DnewVersion='+list(v)[0]+' -Dproperty='+a+'.version  -DallowDowngrade=true')
    #     update_pom(testcases_dir + project_address[i] + '_scantist/pom.xml', deps, res)
    #     for m in manual:
    #         print(m)
# apply()
# parse()