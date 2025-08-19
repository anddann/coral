import csv
import json
import re
import pymongo
import json

import requests

from compatibility.get_break import compatibility_check
from utils.version_utils import _sort

g = 'com.google.guava'
a = 'guava'
def test_successsive():
    c = pymongo.MongoClient('localhost',
                            port=27017)
    maven = c['library-crawler']['maven']


    version_list = []
    last_version = ''
    direct = set()
    successive = set()
    for doc in maven.find({'group': g, 'artifact': a}):
        version_list.append(doc['version'])
    with requests.Session() as session:
        version_list = _sort(version_list, session)
    # for ver in version_list:
    #     if last_version!='':
    #         successive = successive.union(compatibility_check(g, a, last_version, ver))
    #     last_version = ver
    direct = compatibility_check(g, a, version_list[0], version_list[-1])
    print(version_list)
    print(len(direct))
    print(len(successive))
    open(f'compatibility/results/{a}_direct.json', 'w').write(json.dumps(list(direct)))
    # open(f'compatibility/results/{a}_successive.json', 'w').write(json.dumps(list(successive)))

def remove_non_existent_APIs():
    names = []
    for line in csv.reader(open('/Users/lyuye/workspace/java-compatibility/sootCallGraph/graph/guava-r03_NameList.csv')):
        names.append(re.sub('\(.*$', '', line[0]))
    ret = []
    dir = json.load(open(f'compatibility/results/{a}_direct.json'))
    suc = json.load(open(f'compatibility/results/{a}_successive.json'))
    # print(len(set(dir)-set(suc)))
    # exit()
    for i in suc:
        if ':' not in i:
            continue
        if re.sub('\(.*$', '', i)  in names:
            ret.append(i)
    print(len(ret))
    open('compatibility/successive_rm.json', 'w').write(json.dumps(ret))
    ret = []
    for i in dir:
        if ':' not in i:
            continue

        if re.sub('\(.*$', '', i)  in names:
            ret.append(i)
    print(len(ret))
    open('compatibility/direct_rm.json', 'w').write(json.dumps(ret))

def calculate_combinations():
    c = pymongo.MongoClient('localhost',
                            port=27017)
    maven = c['library-crawler']['maven']
    vul_libs = set()
    for i in json.load(open('compatibility/directVulLibs.json')):
        vul_libs.add(i['vendor']+':'+i['library'])
    total = 0
    for vul_lib in vul_libs:
        g, a = vul_lib.split(':')
        version_count = 0
        for doc in maven.find({'group': g, 'artifact': a}):
            epoch = int(re.sub('000$', '', doc['time']))
            if epoch>1262304000:
                version_count+=1
        if version_count>1000:
            print(g, a)
            print(version_count)
            total += (version_count* version_count - version_count)/2

    print(total)
