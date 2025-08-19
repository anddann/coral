import json
import os
from collections import defaultdict

from utils.pom_modifier import update_pom
from config import project_path

def parse():
    project = 'maven_slf4j-provider'
    scopes = ['compile', 'runtime', 'provided', 'test', 'system']
    if '/' in project:
        project  = project.replace('/', '-')
    with open('remediation_results/'+project+'_steady.json', 'w') as fw, open('steady_res/tmp') as f:
        out = []
        g = 'GROUP'
        a = 'ARTIFACT'
        one = {}
        for lin in f.readlines():

            line = lin.strip()
            print(line)
            if line.lower() in scopes:
                if one != {}:
                    out.append(one)
                    one = {}
                one['scope']= line.lower()
                continue
            if 'Artifact ID' in line:
                old = line.replace('Artifact ID: ', '')
                g,a,v = old.split(' ')[0].split(':')
                one['old'] = g+'|'+a+'|'+v
                continue
            if g+':'+a in line:
                one['new'] = line.split(' ')[0].replace(':', '|')
                continue
        if one != {}:
            out.append(one)
        print(out)
        fw.write(json.dumps(out))

def apply():
    project = 'nacos'
    project_address = 'nacos'
    project_versions = {}
    res = defaultdict(set)
    for f in os.listdir('remediation_results'):
        if 'steady' in f and f.startswith(project):
            with open('remediation_results/'+f) as p:
                rem = json.load(p)
                for each in rem:
                    if 'new' in each:
                        new = each['new']
                        g,a,v = new.split('|')
                        submodule = f.replace('_steady.json', '').split('_')[-1]
                        project_versions[new] = project_path[f.replace('_steady.json', '')]['snyk'].replace('PLACEHOLDER', submodule).replace('snyk', 'steady')
                        res[g+'|'+a].add(v)

    os.chdir('/Users/lyuye/workspace/remediation/'+project_address+'_steady/')
    deps = list()
    manual = []

    for k, v in res.items():
        print(len(v), k)
        if len(v) >1:
            for i, ver in enumerate(v):
                if i == 0:
                    continue
                os.chdir(project_versions[k+'|'+ver])
                print(k+'|'+ver, project_versions[k+'|'+ver])
                ga = k.replace('|', ':')
                g, a = k.split('|')
                try:
                    os.system('mvn versions:use-dep-version -Dincludes=' + ga + ' -DdepVersion=' + list(v)[
                        0] + ' -DforceVersion=true')
                    os.system('mvn versions:update-property -DnewVersion=' + list(v)[
                        0] + ' -Dproperty=' + a + '.version  -DallowDowngrade=true')
                except:
                    pass
                update_pom(project_versions[k+'|'+ver]+'pom.xml', [k+'|'+ver], {k: ver})
                os.chdir('/Users/lyuye/workspace/remediation/' + project_address + '_steady/')
        g, a = k.split('|')
        deps.append(k+'|'+list(v)[0])
        ga = k.replace('|', ':')

        try:
            os.system('mvn versions:use-dep-version -Dincludes='+ga+' -DdepVersion='+list(v)[0])
        except Exception as e:
            print(e)

    update_pom('/Users/lyuye/workspace/remediation/' + project_address + '_steady/pom.xml', deps, res)
    for m in manual:
        print(m)
# apply()
# parse()

