import subprocess,re
import csv
from collections import defaultdict

from config import working_dir
from utils.miscellaneous import timer, get_jar_path


def revapi_jar(jar1, jar2):
    ret = []
    # try:
    # print('/Users/lyuye/workspace/java-compatibility/otherTools/revapi-0.11.2/revapi.sh', '-n', jar2, '-o', jar1,
    #      '--extensions=org.revapi:revapi-java:0.24.4,org.revapi:revapi-reporter-text:0.14.2 -D revapi.reporter.text.minSeverity=BREAKING')
    # out = subprocess.run(f'/Users/lyuye/workspace/java-compatibility/otherTools/revapi-0.11.2/revapi.sh -n {jar2} -o {jar1} --extensions=org.revapi:revapi-java:0.24.4,org.revapi:revapi-reporter-text:0.14.2 -D revapi.reporter.text.minSeverity=BREAKING |grep -v "old: <none>"',capture_output=True)
    process = subprocess.Popen(
        [working_dir+'revapi-0.11.2/revapi.sh', '-n', jar2, '-o', jar1,
         '--extensions=org.revapi:revapi-java:0.24.4,org.revapi:revapi-reporter-text:0.14.2 -D revapi.reporter.text.minSeverity=BREAKING'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    outs = out.decode("utf-8").split("\n\n")
    # print(len(outs))


    for o in outs:
        if 'old: <none>' in o:
            continue
        if 'BINARY: BREAKING' in o or 'SOURCE: BREAKING' in o:
            result = re.search('^(old:.*?)\n', o)
            if result and ' enum ' not in result.group(1):
                a = result.group(1)
                if 'method' in a:
                    result = re.search("old: method \S+ (.*\))", a)
                else:
                    result = re.search("old: \S+ (\S+)", a)
                if result:
                    a = result.group(1).replace("::", ":").replace(" ", "")
                    if ':' in a:

                        ret.append(a)
    # except Exception as e:
    #     print('[ERROR] revapi error', e)
    #     return ret
    return ret

@timer
def revapi(g, a, v1, v2):
    ret = []
    # print(g, a, v1, v2)
    lib = a
    ver1 = v1
    ver2 = v2

    jar1 ='/Users/lyuye/workspace/java-compatibility/jars/' + lib + '-' + ver1 + '.jar'
    jar2 = '/Users/lyuye/workspace/java-compatibility/jars/' + lib + '-' + ver2 + '.jar'
    # print(jar1)
    # print(jar2)
    # out = subprocess.run(f'/Users/lyuye/workspace/java-compatibility/otherTools/revapi-0.11.2/revapi.sh -n {jar2} -o {jar1} --extensions=org.revapi:revapi-java:0.24.4,org.revapi:revapi-reporter-text:0.14.2 -D revapi.reporter.text.minSeverity=BREAKING |grep -v "old: <none>"',capture_output=True)
    process = subprocess.Popen(
        ['/Users/lyuye/workspace/java-compatibility/otherTools/revapi-0.11.2/revapi.sh', '-n', jar2, '-o', jar1,
         '--extensions=org.revapi:revapi-java:0.24.4,org.revapi:revapi-reporter-text:0.14.2 -D revapi.reporter.text.minSeverity=BREAKING'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    outs = out.decode("utf-8").split("\n\n")
    # print(len(outs))

    for o in outs:
        if 'old: <none>' in o:
            continue
        if 'BINARY: BREAKING' in o or 'SOURCE: BREAKING' in o:
            result = re.search('^(old:.*?)\n', o)
            if result and ' enum ' not in result.group(1):
                a = result.group(1)
                if 'method' in a:
                    result = re.search("old: method \S+ (.*\))", a)
                else:
                    result = re.search("old: \S+ (\S+)", a)
                if result:
                    a = result.group(1).replace("::", ":").replace(" ", "")
                    if ':' in a:
                        ret.append(a)
    return ret
def compatibility_check(g, a, v1, v2):
    rev = revapi_jar(get_jar_path(g+'|'+a+'|'+v1), get_jar_path(g+'|'+a+'|'+v2))
    return rev


if __name__=='__main__':
    compatibility_check('org.apache.httpcomponents', 'httpclient', '4.0', '4.5.13')

