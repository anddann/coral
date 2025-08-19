import csv
import os
import re
from unidiff import PatchSet
from collections import defaultdict
from shutil import copyfile
def get_methods(object, spacing=20):
  methodList = []
  for method_name in dir(object):
    try:
        if callable(getattr(object, method_name)):
            methodList.append(str(method_name))
    except:
        methodList.append(str(method_name))
  processFunc = (lambda s: ' '.join(s.split())) or (lambda s: s)
  for method in methodList:
    try:
        print(str(method.ljust(spacing)) + ' ' +
              processFunc(str(getattr(object, method).__doc__)[0:90]))
    except:
        print(method.ljust(spacing) + ' ' + ' getattr() failed')

def parse_diff(input, is_file=False):
    output = []
    incomplete = []
    commit = ''
    try:
        if is_file:
            patches = PatchSet.from_filename(input, encoding='utf-8')
        else:
            patches = PatchSet.from_string(input, encoding='utf-8')
    except:
        return output, incomplete, commit
    for patch in patches:
        if commit == '' and patch.patch_info and patch.patch_info[0].startswith('From'):
            commit = re.search('From (\w+) ', patch.patch_info[0]).group(1)
        if patch.source_file.endswith('.java'):
            # print(patch.path)
            package = re.sub('^.*/java/', '', patch.path)
            package = re.sub('^java/', '', package)
            package = re.sub('^.*/testcases/', '', package)
            package = re.sub('^.*test/', '', package)
            package = re.sub('.java$', '', package).replace('/', '.')
            for hunk in patch:
                header = hunk.section_header
                res = re.search("(.*) (\w+\(.*\))", header)
                if res:
                    method = res.group(2)
                    type_ = res.group(1) 
                else:
                    res = re.search("(.*) (\w+\(.*)", header)
                    if res:
                        method = res.group(2)
                        type_ = res.group(1)
                        incomplete.append(type_+'|'+ package + ':' + method)
                    else:
                        print('patch.path', header)
                        continue
                output.append(type_+'|'+ package + ':' + method)

    return list(set(output)), list(set(incomplete)), commit
# parse_diff('/home/cc/workspace/java-call-graph-remediation/java_patch/org.apache.tomcat__tomcat__CVE-2019-0221__0.patch')
if __name__=="__main__":
    files = os.listdir('lyuye_java_patch')
    mapping = defaultdict(list)
    incomplete_funcs = defaultdict(list)
    cve_commits = defaultdict(list)
    count = 0
    all = 0
    for file in files:
        if not file.endswith('patch'):
            continue
        all+=1
        out, incomplete, commit = parse_diff('lyuye_java_patch/'+file, is_file=True)
        cve = file.split('__')[0]
        if commit:
            cve_commits[cve].append(commit)
        if out:
            count+=1
            incomplete_funcs[cve].append({'funcs': incomplete, 'commit': commit, 'file':file})

            mapping[cve].append({'funcs': out, 'commit': commit})
        # else:
        #     copyfile('lyuye_java_patch/'+file, 'pending_java_patch/'+file)
    print (count, all)
    print(len(mapping))
    visited = set()
    with open('java_cve_func.csv', 'w') as f:
        w = csv.writer(f, delimiter=',', lineterminator='\n')
        for cve, out_list in mapping.items():
            for o in out_list:
                for func in o['funcs']:
                    if func in visited:
                        continue
                    w.writerow([cve, func, o['commit']])
                    visited.add(func)
    visited = set()
    with open('java_cve_func_incomplete.csv', 'w') as f:
        w = csv.writer(f, delimiter=',', lineterminator='\n', quotechar = "\"")
        for cve, out_list in incomplete_funcs.items():
            for o in out_list:
                for func in o['funcs']:
                    if func in visited:
                        continue
                    w.writerow([cve, func, o['commit'], o['file']])
                    visited.add(func)

