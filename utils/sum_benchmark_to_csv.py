import csv
import os

import pymongo

from config import mongodb_host, mongodb_port, project_path


def sum_benchmark_to_csv():
    read_benchmark()
    write_sum()
    read_large_scale()


def read_benchmark():
    print('Number of all projects:', len(project_path))
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    benchmark = c['remediation']['benchmark_metrics']
    os.makedirs('data', exist_ok=True)
    with open('data/ori.csv', 'w') as f1, open('data/tool.csv', 'w') as f2, open('data/snyk.csv', 'w') as f3,\
            open('data/dpb.csv', 'w') as f4, open('data/baseline.csv', 'w') as f5, open('data/scantist.csv', 'w') as f6,\
                open('data/steady.csv', 'w') as f7, open('data/allsmt.csv', 'w') as f8,open('data/large.csv', 'w') as f9:
        tool = csv.writer(f2, lineterminator='\n')
        tool.writerow(['project', 'size', 'cve_reach', 'cve_unreach', 'cve_unsure', 'cve_fixes',
                       '#breaking API', 'efforts', 'spans', 'dev', 'major', 'compilation', 'has_unit_test', 'unit_test'])
        ori = csv.writer(f1, lineterminator='\n')
        ori.writerow(
            ['project', 'size', 'cve_reach', 'cve_unreach', 'cve_unsure', 'cve_fixes',
             '#breaking API', 'efforts', 'spans', 'dev', 'major', 'compilation', 'has_unit_test', 'unit_test'])
        snyk = csv.writer(f3, lineterminator='\n')
        snyk.writerow(
            ['project', 'size', 'cve_reach', 'cve_unreach', 'cve_unsure', 'cve_fixes',
             '#breaking API', 'efforts', 'spans', 'dev', 'major', 'compilation', 'has_unit_test', 'unit_test'])
        dpb = csv.writer(f4, lineterminator='\n')
        dpb.writerow(
            ['project', 'size', 'cve_reach', 'cve_unreach', 'cve_unsure', 'cve_fixes',
             '#breaking API', 'efforts', 'spans', 'dev', 'major', 'compilation', 'has_unit_test', 'unit_test'])
        baseline = csv.writer(f5, lineterminator='\n')
        baseline.writerow(
            ['project', 'size', 'cve_reach', 'cve_unreach', 'cve_unsure', 'cve_fixes',
             '#breaking API', 'efforts', 'spans', 'dev', 'major', 'compilation', 'has_unit_test', 'unit_test'])
        scantist = csv.writer(f6, lineterminator='\n')
        scantist.writerow(
            ['project', 'size', 'cve_reach', 'cve_unreach', 'cve_unsure', 'cve_fixes',
             '#breaking API', 'efforts', 'spans', 'dev', 'major', 'compilation', 'has_unit_test', 'unit_test'])
        steady = csv.writer(f7, lineterminator='\n')
        steady.writerow(
            ['project', 'size', 'cve_reach', 'cve_unreach', 'cve_unsure', 'cve_fixes',
             '#breaking API', 'efforts', 'spans', 'dev', 'major', 'compilation', 'has_unit_test', 'unit_test'])
        allsmt = csv.writer(f8, lineterminator='\n')
        allsmt.writerow(
            ['project', 'size', 'cve_reach', 'cve_unreach', 'cve_unsure', 'cve_fixes',
             '#breaking API', 'efforts', 'spans', 'dev', 'major', 'compilation', 'has_unit_test', 'unit_test'])
        large = csv.writer(f9, lineterminator='\n')
        large.writerow(
            ['project', 'size', 'cve_reach', 'cve_unreach', 'cve_unsure', 'cve_fixes',
             '#breaking API', 'efforts', 'spans', 'dev', 'major', 'compilation', 'has_unit_test', 'unit_test'])
        count = 0
        for project in project_path:
            count+=1
            print(count, project,)# '\r', end='', flush=True)
            if benchmark.count_documents({'project': project})==0:
                continue
            docs = benchmark.find({'project': project})
            order_list = set()
            
            for d in docs:
                if d['project'].startswith('maven'):
                    break
                if d['order'] == '0':
                    # if 'size' not in d:
                    #     break
                    ori.writerow([project, d['size'], len(d['reachable_cves']), len(d['unreachable_cves'])+ len(d['unsure_cves']),
                                  0, 0, 0, 0, 0, 0, 0, str(d.get('compilation', 'true')).lower(), str(d.get('has_unit_test', 'true')).lower(), str(d.get('unit_test', 'true')).lower()])
                    order_list.add('0')
                if d['order'] == 'Tool':

                    if 'size' in d:
                        tool.writerow([project, d['size'], len(d['reachable_cves']),
                                      len(d['unreachable_cves']), len(d['unsure_cves']),
                                      d['unreachable_fix'] + d['reachable_fix'], d['incom_apis'], d['efforts'], d['spans'],
                                       d['dev_upgrades'], d['major_upgrades'], str(d.get('compilation', 'true')).lower(), str(d.get('has_unit_test', 'true')).lower(), str(d.get('unit_test', 'true')).lower()])
                        order_list.add('Tool')
                if d['order'] == 'snyk':
                    # size not in means failure
                    if 'size' in d:
                        snyk.writerow([project, d['size'], len(d['reachable_cves']),
                                      len(d['unreachable_cves']), len(d['unsure_cves']),
                                      d['unreachable_fix'] + d['reachable_fix'], d['incom_apis'], d['efforts'], d['spans'],
                                       d['dev_upgrades'], d['major_upgrades'], str(d.get('compilation', 'true')).lower(), str(d.get('has_unit_test', 'true')).lower(), str(d.get('unit_test', 'true')).lower()])
                        order_list.add('snyk')
                if d['order'] == 'dpb':
                    if 'size' in d:
                        dpb.writerow([project, d['size'], len(d['reachable_cves']),
                                      len(d['unreachable_cves']), len(d['unsure_cves']),
                                      d['unreachable_fix'] + d['reachable_fix'], d['incom_apis'], d['efforts'], d['spans'],
                                      d['dev_upgrades'], d['major_upgrades'], str(d.get('compilation', 'true')).lower(), str(d.get('has_unit_test', 'true')).lower(), str(d.get('unit_test', 'true')).lower()])
                        order_list.add('dpb')
                if d['order'] == 'baseline':
                    if 'size' in d:
                        baseline.writerow([project, d['size'], len(d['reachable_cves']),
                                      len(d['unreachable_cves']), len(d['unsure_cves']),
                                      d['unreachable_fix'] + d['reachable_fix'], d['incom_apis'], d['efforts'], d['spans'],
                                           d['dev_upgrades'], d['major_upgrades'], str(d.get('compilation', 'true')).lower(), str(d.get('has_unit_test', 'true')).lower(), str(d.get('unit_test', 'true')).lower()])
                        order_list.add('baseline')
                if d['order'] == 'scantist':
                    if 'size' in d:
                        scantist.writerow([project, d['size'], len(d['reachable_cves']),
                                      len(d['unreachable_cves']), len(d['unsure_cves']),
                                      d['unreachable_fix'] + d['reachable_fix'], d['incom_apis'], d['efforts'], d['spans'],
                                           d['dev_upgrades'], d['major_upgrades'], str(d.get('compilation', 'true')).lower(), str(d.get('has_unit_test', 'true')).lower(), str(d.get('unit_test', 'true')).lower()])
                        order_list.add('scantist')
                if d['order'] == 'steady':
                    if 'size' in d:
                        steady.writerow([project, d['size'], len(d['reachable_cves']),
                                           len(d['unreachable_cves']), len(d['unsure_cves']),
                                           d['unreachable_fix'] + d['reachable_fix'], d['incom_apis'], d['efforts'],
                                           d['spans'], d['dev_upgrades'], d['major_upgrades'], str(d.get('compilation', 'true')).lower(), str(d.get('has_unit_test', 'true')).lower(), str(d.get('unit_test', 'true')).lower()])
                        order_list.add('steady')
                if d['order'] == 'all_smt':
                    if 'size' in d:
                        allsmt.writerow([project, d['size'], len(d['reachable_cves']),
                                      len(d['unreachable_cves']), len(d['unsure_cves']),
                                      d['unreachable_fix'] + d['reachable_fix'], d['incom_apis'], d['efforts'], d['spans'],
                                      d['dev_upgrades'], d['major_upgrades'], str(d.get('compilation', 'true')).lower(), str(d.get('has_unit_test', 'true')).lower(), str(d.get('unit_test', 'true')).lower()])
                        order_list.add('all_smt')
            if '0' not in order_list:
                break
                # raise RuntimeError("Original not evaluated for", project)
            if 'Tool' not in order_list:
                raise RuntimeError("Tool failed to generate benchmark for", project)
            if 'snyk' not in order_list:
                snyk.writerow([project, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'false', 'true', 'false', 'fail'])
            if 'dpb' not in order_list:
                dpb.writerow([project, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'false', 'true', 'false', 'fail'])
            if 'baseline' not in order_list:
                baseline.writerow([project, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'false', 'true', 'false', 'fail'])
            if 'scantist' not in order_list:
                scantist.writerow([project, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'false', 'true', 'false', 'fail'])
            if 'steady' not in order_list:
                steady.writerow([project, 0, 0, 0, 0,0,  0, 0, 0, 0, 0, 'false', 'true', 'false', 'fail'])
            if 'all_smt' not in order_list:
                allsmt.writerow([project, 0, 0, 0, 0,0,  0, 0, 0, 0, 0, 'false', 'true', 'false', 'fail'])

def write_sum():
    with open('data/ori.csv', 'r') as f1, open('data/tool.csv', 'r') as f2, open('data/snyk.csv', 'r') as f3, \
            open('data/dpb.csv', 'r') as f4, open('data/baseline.csv', 'r') as f5, open('data/sum.csv', 'w') as f6, \
            open('data/scantist.csv', 'r') as f7, open('data/steady.csv', 'r') as f8, open('data/allsmt.csv', 'r') as f9:
        # calculate original failed tests
        test_fail_list = set()


        sum = csv.writer(f6, lineterminator='\n')
        sum.writerow(['name', 'size', 'cve_reach', 'cve_unreach', 'cve_unsure', 'cve_fixes',
             '#breaking API', 'efforts', 'spans', 'dev', 'major', 'compilation', 'unit_test', 'failure', 'new test failure'])
        total = ['ori', 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0]
        for l in csv.reader(f1):
            if l[0]=='project':
                continue
            for i, col in enumerate(l):
                if i==0:
                    continue
                elif i == 11:
                    if col == 'false':
                        total[i] += 1
                elif i == 13:
                    if col == 'false':
                        total[i-1] += 1
                        test_fail_list.add(l[0])
                elif i == 12:
                    pass

                else:
                    total[i]+=int(col)
        sum.writerow(total)

        total = ['tool', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        for l in csv.reader(f2):
            if l[0]=='project':
                continue
            for i, col in enumerate(l):
                if i==0:
                    continue
                elif i == 11:
                    if col == 'false':
                        total[11] += 1
                elif i == 13:
                    if col == 'false':
                        total[12] += 1
                        if l[0] not in test_fail_list:
                            total[i+1] += 1
                elif i == 12:
                    pass
                else:
                    total[i]+=int(col)

        sum.writerow(total)

        total = ['snyk', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        for l in csv.reader(f3):
            if l[0]=='project':
                continue
            for i, col in enumerate(l):
                if i==0:
                    continue
                if col != 'fail' and col != 'true' and col != 'false' :
                    total[i]+=int(col)
                if i == 11 and col=='false':
                    total[11]+= 1
                if i == 13 and col == 'false':
                    total[12]+= 1
                    if l[0] not in test_fail_list:
                        total[i + 1] += 1
            if l[-1] =='fail':
                total[-1]+=1
        sum.writerow(total)

        total = ['dependabot', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        for l in csv.reader(f4):
            if l[0]=='project':
                continue
            for i, col in enumerate(l):
                if i==0:
                    continue
                if col != 'fail' and col != 'true' and col != 'false' :
                    total[i] += int(col)
                if i == 11 and col=='false':
                    total[11]+= 1
                if i == 13 and col == 'false':
                    total[12]+= 1
                    if l[0] not in test_fail_list:
                        total[i + 1] += 1
            if l[-1] =='fail':
                total[-1]+=1
        sum.writerow(total)

        total = ['baseline', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        for l in csv.reader(f5):
            if l[0]=='project':
                continue
            for i, col in enumerate(l):
                if i==0:
                    continue
                if col != 'fail' and col != 'true' and col != 'false' :
                    total[i] += int(col)
                if i == 11 and col=='false':
                    total[11]+= 1
                if i == 13 and col == 'false':
                    total[12]+= 1
                    if l[0] not in test_fail_list:
                        total[i + 1] += 1
            if l[-1] =='fail':
                total[-1]+=1
        sum.writerow(total)

        total = ['scantist', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        for l in csv.reader(f7):
            if l[0]=='project':
                continue
            for i, col in enumerate(l):
                if i==0:
                    continue
                if col != 'fail' and col != 'true' and col != 'false' :
                    total[i] += int(col)
                if i == 11 and col=='false':
                    total[11]+= 1
                if i == 13 and col == 'false':
                    total[12]+= 1
                    if l[0] not in test_fail_list:
                        total[i + 1] += 1
            if l[-1] =='fail':
                total[-1]+=1
        sum.writerow(total)

        total = ['steady', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        for l in csv.reader(f8):
            if l[0]=='project':
                continue
            for i, col in enumerate(l):
                if i==0:
                    continue
                if col != 'fail' and col != 'true' and col != 'false':
                    total[i]+=int(col)
                if i == 11 and col=='false':
                    total[11]+= 1
                if i == 13 and col == 'false':
                    total[12]+= 1
                    if l[0] not in test_fail_list:
                        total[i + 1] += 1
            if l[-1] =='fail':
                total[-1]+=1
        sum.writerow(total)

        total = ['allsmt', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        for l in csv.reader(f9):
            if l[0]=='project':
                continue
            for i, col in enumerate(l):
                if i==0:
                    continue
                elif i == 11:
                    if col == 'false':
                        total[11] += 1
                elif i == 13:
                    if col == 'false':
                        total[12] += 1
                        if l[0] not in test_fail_list:
                            total[i+1] += 1
                elif i == 12:
                    pass
                elif col == 'fail' :
                    continue
                else:
                    try:
                        total[i]+=int(col)
                    except:
                        print(l)
                        exit()
        sum.writerow(total)
def get_unsure_cves_4_triage():
    print('Number of all projects:', len(project_path))
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    benchmark = c['remediation']['benchmark_metrics']
    os.makedirs('data', exist_ok=True)
    cves = set()
    for doc in benchmark.find():
        tmp = []
        for e in doc['unsure_cves']:
            if 'CNVD' not in e and 'CNNVD' not in e:
                tmp.append(e)
        cves = cves.union(tmp)
    with open('data/unsure_cves.csv', 'w') as f:
        a = csv.writer(f, lineterminator='\n')
        a.writerows([[cve] for cve in cves])

def sum_large_to_csv():
    read_large_scale()
    write_large_sum()

def read_large_scale():
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    benchmark = c['remediation']['large_scale_metrics']
    os.makedirs('data', exist_ok=True)
    with open('data/large_ori.csv', 'w') as f1, open('data/large_tool.csv', 'w') as f2:
        tool = csv.writer(f2, lineterminator='\n')
        tool.writerow(['project', 'size', 'cve_reach', 'cve_unreach', 'cve_unsure', 'cve_fixes',
                       '#breaking API', 'efforts', 'spans', 'dev', 'major', ])
        ori = csv.writer(f1, lineterminator='\n')
        ori.writerow(
            ['project', 'size', 'cve_reach', 'cve_unreach', 'cve_unsure', 'cve_fixes',
             '#breaking API', 'efforts', 'spans', 'dev', 'major'])

        count = 0
        for doc in benchmark.find({'order': 'Tool'}):
            count += 1
            project = doc['project']
            print(count, doc['project'])  # '\r', end='', flush=True)
            ori_doc = benchmark.find_one({'project': project, 'order':'0'})
            order_list = set()
            # if 'size' not in d:
            #     break
            d = ori_doc
            ori.writerow([project, d['size'], len(d['reachable_cves']),
                          len(d['unreachable_cves']), len(d['unsure_cves']),
                           0, 0, 0, 0, 0, 0])

            d = doc

            tool.writerow([project, d['size'], len(d['reachable_cves']),
                           len(d['unreachable_cves']), len(d['unsure_cves']),
                           d['unreachable_fix'] + d['reachable_fix'], d['incom_apis'], d['efforts'],
                           d['spans'],
                           d['dev_upgrades'], d['major_upgrades']])



def write_large_sum():

    with open('data/large_ori.csv', 'r') as f1, open('data/large_tool.csv', 'r') as f2, open('data/large_sum.csv', 'w') as f3:
        sum = csv.writer(f3, lineterminator='\n')
        sum.writerow(['name', 'size', 'cve_reach', 'cve_unreach', 'cve_unsure', 'cve_fixes',
                      '#breaking API', 'efforts', 'spans', 'dev', 'major'])
        total = ['ori', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        for l in csv.reader(f1):
            if l[0] == 'project':
                continue
            for i, col in enumerate(l):
                if i == 0:
                    continue
                else:
                    total[i] += int(col)
        sum.writerow(total)

        total = ['tool', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        for l in csv.reader(f2):
            if l[0] == 'project':
                continue
            for i, col in enumerate(l):
                if i == 0:
                    continue
                else:
                    total[i] += int(col)

        sum.writerow(total)




