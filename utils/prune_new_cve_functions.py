import csv, re
import json


def check_path(s):
    if 'src/main/java/' in s:
        path = s.split('src/main/java/')[-1]
    elif 'src/share/classes/' in s:
        path = s.split('src/share/classes/')[-1]
    elif 'src/java/main/' in s:
        path = s.split('src/java/main/')[-1]
    elif 'java/' in s:
        path = s.split('java/')[-1]
    elif 'src/' in s:
        path = s.split('src/')[-1]
    else:
        return s.replace('.java', '').replace('/', '.')
    return path.replace('.java', '').replace('/', '.')

def check_visibility(s):
    if s.startswith('private'):
        return 'private'
    elif s.startswith('public'):
        return 'public'
    elif s.startswith('protected'):
        return 'protected'
    else:
        return ''
def prune_csv(file):
    with open(file) as f, open('../cve_func_10_22_processed.csv', 'w') as fw:
        b = csv.writer(fw, lineterminator = '\n', delimiter = ',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        a = csv.reader(f)
        start = False
        for l in a:
            if True: #l[0] == 'CVE-2017-9735':
                start = True
            if start:
                l2 = l
                path = check_path(l[2])
                if not path:
                    print(l[0])
                    b.writerow(l2)
                    continue
                clazz = l[2].split('/')[-1].replace('.java', '')
                l[4] = clazz
                l[3] = path

                visibility = check_visibility(l[6])
                l2[8] = visibility
                res = re.search('\S+\(.*\)', l[6])
                if res:
                    method = res.group(0)
                    method_name = re.sub('\(.*\)', '', method)
                    l2[17] = path+':'+method

                    l2[9] = l[6].replace(visibility+' ','').replace(method, '').strip()
                    l2[10] = re.sub('\(.*\)', '', method)
                    args = re.search('\((.*)\)', method)
                    argstring = []
                    type_list = []
                    args = re.sub('<.*>', '', args.group(1))
                    for each in args.split(','):
                        tmp = re.sub('@.*\) ', '', each.strip().strip("\""))
                        tmp = re.sub('@\S+ ', '', tmp)
                        tmp = re.sub('final ', '', tmp)
                        tmp = re.sub('<.*>', '', tmp)
                        if tmp == '':
                            continue
                        argstring.append(tmp)
                        type_list.append(tmp.split(' ')[-2])
                    l2[17] = path + ':' + method_name+'('+','.join(type_list)+')'
                    print(l2[17])
                    l2[11] = str(argstring)

                    b.writerow(l2)
                else:
                    b.writerow(l2)
            else:
                b.writerow(l)

if __name__=='__main__':
    prune_csv('../cve_func_10_22.csv')