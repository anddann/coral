import json
import os
from collections import defaultdict

from utils.pom_modifier import update_pom
from config import project_path

def parse():
    project = 'nacos_sys'
    if '/' in project:
        project  = project.replace('/', '-')
    with open('remediation_results/'+project+'_snyk.json', 'w') as fw, open('snyk/tmp') as f:
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
    projects = ['activemq', 'apollo', 'canal', 'druid', 'guava', 'hutool', 'log4j', 'mall', 'netty', 'seata', 'spring-boot-demo', 'maven', 'nacos']
    project_address = ['activemq', 'apollo', 'canal', 'druid', 'guava', 'hutool', 'logging-log4j2', 'mall', 'netty', 'seata', 'spring-boot-demo', 'maven', 'nacos']
    for i, project in enumerate(projects):
        res = defaultdict(set)
        project_versions = {}
        if not project.startswith('nacos'):
            continue
        for f in os.listdir('remediation_results'):
            if 'snyk' in f and f.startswith(project):
                with open('remediation_results/'+f) as p:
                    rem = json.load(p)
                    for each in rem:
                        if 'new' in each:
                            new = each['new']
                            g,a,v = new.split('|')
                            submodule = f.replace('_snyk.json', '').split('_')[-1]
                            project_versions[new] = project_path[f.replace('_snyk.json', '')]['snyk'].replace('PLACEHOLDER', submodule)
                            res[g+'|'+a].add(v)
        manual = []
        deps = list()
        os.chdir('/Users/lyuye/workspace/remediation/'+project_address[i]+'_snyk/')
        for k, v in res.items():
            print(len(v), k)
            if len(v) >1:
                for i, ver in enumerate(v):
                    if i == 0:
                        continue
                    ga = k.replace('|', ':')
                    g, a = k.split('|')
                    os.chdir(project_versions[k+'|'+ver])
                    print(k+'|'+ver, project_versions[k+'|'+ver])
                    os.system('mvn versions:use-dep-version -Dincludes=' + ga + ' -DdepVersion=' + list(v)[
                        0] + ' -DforceVersion=true')
                    os.system('mvn versions:update-property -DnewVersion=' + list(v)[
                        0] + ' -Dproperty=' + a + '.version  -DallowDowngrade=true')
                    update_pom(project_versions[k+'|'+ver]+'pom.xml', [k+'|'+ver], {k: ver})
                    os.chdir('/Users/lyuye/workspace/remediation/' + project_address[i] + '_snyk/')
            g, a = k.split('|')
            ga = k.replace('|', ':')
            deps.append(k+'|'+list(v)[0])
            os.system('mvn versions:use-dep-version -Dincludes='+ga+' -DdepVersion='+list(v)[0] +' -DforceVersion=true')
            os.system('mvn versions:update-property -DnewVersion='+list(v)[0]+' -Dproperty='+a+'.version  -DallowDowngrade=true')
        update_pom('/Users/lyuye/workspace/remediation/' + project_address[i] + '_snyk/pom.xml', deps, res)
        for m in manual:
            print(m)
# apply()
# parse()