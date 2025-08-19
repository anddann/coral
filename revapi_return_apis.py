import json
import subprocess,re
import csv, sys
from collections import defaultdict
from jar_config import revapi



def get_incompatible_apis(jar1, jar2):
    process = subprocess.Popen(
        [revapi, '-n', jar2, '-o', jar1,
         '--extensions=org.revapi:revapi-java:0.24.4,org.revapi:revapi-reporter-text:0.14.2 -Drevapi.reporter.text.minSeverity=BREAKING '],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()

    outs = out.decode("utf-8").split("\n\n")
    # print('Incompatible APIs:', len(outs))
    # print(revapi, '-n', jar2, '-o', jar1,
    #      '--extensions=org.revapi:revapi-java:0.24.4,org.revapi:revapi-reporter-text:0.14.2 -Drevapi.reporter.text.minSeverity=BREAKING ')
    incomp_apis = set()
    for o in outs:
        if 'old: <none>' in o:
            continue
        result = re.search('^(old:.*?)\n', o)
        if result and ' enum ' not in result.group(1):
            a = result.group(1)
            if 'method' in a:
                result = re.search("old: method .* (.*::.*\))", a)
            else:
                result = re.search("old: .* (.*::.*\))", a)
            if result:
                a = result.group(1).replace("::", ":").replace(" ", "")
                a = a.replace('===', '')
                # print(a)
                incomp_apis.add(a)
    # print(incomp_apis)
    return incomp_apis

if __name__=='__main__':
    jar1 = '/Users/lyuye/workspace/java-compatibility/jars/httpcore-4.1.jar'
    jar2 = '/Users/lyuye/workspace/java-compatibility/jars/httpcore-4.2.jar'
    get_incompatible_apis(jar1, jar2)



