import csv
import os
import subprocess
from config import japicmp_path, japicmp_mod_path, mongodb_port, mongodb_host, m2_path
from download_all_jar import download_one_jar
from jar_config import jar_path
# Borrowed for SemB detection study
from utils.miscellaneous import get_jar_path


def get_precomputed(gav1, gav2, connection):
    g, a, v1 = gav1.split('|')
    g, a, v2 = gav2.split('|')
    com = connection['incom_apis'][g+'|'+a]
    doc = com.find_one({'v': v1+'|'+v2})
    if doc:
        return doc['a']
    else:
        out = run_original_japicmp(gav1, gav2)
        com.insert_one({
            'v': v1+'|'+v2,
            'a': list(out)
        }, bypass_document_validation=True)
        return list(out)


def get_japicmp(gav1, gav2, connection):
    return get_precomputed(gav1, gav2, connection)

    # process = subprocess.Popen(
    #     ['java', '-jar', japicmp_mod_path, 'get', gav1.replace('|', ':'), gav2.replace('|', ':'), mongodb_host, str(mongodb_port)],
    #     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # out, err = process.communicate()
    #
    # if 'NotFoundInMongoDBException' in err.decode():
    #     out = run_original_japicmp(gav1, gav2)
    # return parse_output(out)


def run_original_japicmp(jar1, jar2):
    a = japicmp_jar(jar1, jar2)
    # save_compa_features(gav1, jar1, gav2, jar2)
    return a


def japicmp_jar(jar1, jar2):
    process = subprocess.Popen(
        ['java', '-jar', japicmp_path, '-o' , jar1, '-n', jar2, '--ignore-missing-classes'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    return parse_output(out)

def save_compa_features(gav1, jar1, gav2, jar2):
    try:
        process = subprocess.Popen(
            ['java', '-jar', japicmp_mod_path, 'set', jar1, gav1.replace('|', ':'), mongodb_host, str(mongodb_port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
    except:
        pass

    try:
        process = subprocess.Popen(
            ['java', '-jar', japicmp_mod_path, 'set', jar2, gav2.replace('|', ':'), mongodb_host, str(mongodb_port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
    except:
        pass

def parse_output(out):
    apis = set()
    old_clazz = ''
    clazz = ''
    for line in out.decode("utf-8").split('\n'):
        if line.startswith('****') or line.startswith('---'):
            clazz = line.split(' ')[-4]
            continue
        if clazz!='' and line.startswith('\t'):
            if 'REMOVED METHOD' in line:
                elements = line.split(' ')
                if '(' in elements[-1]:
                    apis.add(clazz+':'+elements[-1])
                else:
                    method = ''
                    elements.reverse()
                    for ele in elements:
                        method = ele + ' ' + method
                        if '(' in ele:
                            break
                    apis.add(clazz+':'+method)
        else:
            old_clazz = clazz
    # print(apis)
    return apis


def semb_study():
    with open(config.workspace+'/java-compatibility/scripts_py/RQ4 new large scale - ma.csv') as f, open(config.workspace+'/java-compatibility/scripts_py/minor_japicmp.csv', 'w') as fw:
        names = []
        for l in csv.reader((f)):
            if l[0]=='name':
                continue
            names.append(l[0])
        out = csv.writer(fw, lineterminator='\n')
        for name in names:
            print(name)
            a,v1, v2 = name.split('_')
            count = len(japicmp_jar(os.path.join(jar_path, a + '-' + v1 + '.jar'), os.path.join(jar_path, a + '-' + v2 + '.jar')))
            out.writerow([name, count])
