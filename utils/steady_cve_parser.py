import csv
import json
from collections import defaultdict

import requests


def get_steady_cve_func():
    with requests.Session() as session, open('cve_func_steady.csv','w')as fw:
        steady = csv.writer(fw, lineterminator='\n')
        for l in csv.reader(open('data/unsure_cves.csv')):
            cve = l[0]

            res = session.get('http://119.8.160.106:8033/backend/bugs/'+cve)
            if res.status_code != 200:
                print(cve)
                continue
            a = res.json()

            # a = json.loads(a)

            ret = defaultdict(list)
            if 'constructChanges' in a:
                for change in a['constructChanges']:
                    if change['constructChangeType'] =='ADD':
                        continue
                    if change['constructId']['type']== 'CLAS' or change['constructId']['type']== 'ENUM' or change['constructId']['type']== 'PACK':
                        continue
                    if 'test' in change['repoPath'].lower():
                        continue
                    sig = change['constructId']['qname']
                    method = sig.split('.')[-1]
                    clss = sig.split('.')[-2]
                    pkg = sig.replace('.'+clss+'.'+method, '')
                    deleted = change['constructChangeType']=='DEL'

                    method_name = method[:method.index('(')]
                    args = method[method.index('('):].strip('()')
                    args_ = [e.strip() for e in args.split(',')]
                    signature = pkg+'.'+clss+':'+method.replace(' ', '')
                    if deleted:
                        steady.writerow([cve, '', change['repoPath'], pkg, clss, '', method, method,'', '', method_name, str(args_), '', '', change['commit'], '', change['repo'], signature])
                    else:
                        steady.writerow([cve, '', change['repoPath'], pkg, clss, '', method, '', '', '', method_name, str(args_), '', '', change['commit'], '', change['repo'], signature])

            if a['constructChanges'] == {}:
                print(cve)
