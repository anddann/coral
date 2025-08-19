import csv, ast, re

def sig_translation(s):
    import re
    args = re.search('\((.*)\)', s)
    if args:
        args = args.group(1)
        if args =='':
            return s
        else:
            new_args = ''
            for arg in args.split(','):
                element = arg.split('.')[-1].split('$')[-1].strip()
                new_args = new_args+element+','
            return s.replace(args, new_args.strip(' ,'))
    return s
def prune_args(l):
    o = []
    for arg in l:
        if arg.count(' ') == 1:
            o.append(arg.split(' ')[0])
        elif arg.count(' ') == 2:
            o.append(arg.split(' ')[1])
        else:
            print(arg)
    return '('+','.join(o)+')'
def sigtrans():
    cg = []
    with open('soot4.2.0.csv') as f:
        a =csv.reader(f)
        for i, j in enumerate(a):
            print(sig_translation(j[1]))
            print(sig_translation(j[0]))
def formalize_cve_func():
    sigs = []
    with open('cve_func.csv') as f, open('new_cve_func.csv', 'w') as f2:
        b = csv.reader(f)
        writer = csv.writer(f2, lineterminator='\n', quoting=csv.QUOTE_ALL)
        for i, j in enumerate(b):
            clss = j[3]
            clss = re.sub('^src\.solaris\.classes\.', '', clss)
            clss = re.sub('^src\.share\.classes\.', '', clss)
            clss = re.sub('^src\.main\.', '', clss)
            clss = re.sub('^netx\.', '', clss)
            clss = re.sub('^examples\.', '', clss)
            clss = re.sub('^main\.', '', clss)
            clss = re.sub('^.*src\.', '', clss)
            clss = re.sub('^.*src\.', '', clss)
            print(clss)
            if i==0:
                writer.writerow(j+['signature'])
                continue
            #if j[4] ==1:
            #    continue
            if not j[6]:
                j[3] = clss
                writer.writerow(j+[''])
                continue
            args='()'
            if j[11]:
                args =prune_args(ast.literal_eval(j[11]))
            if clss.split('.')[-1]==j[10]:
                sig = clss+':'+'clinit'+args
            else:
                sig = clss+':'+j[10]+args
            sig.replace(' ', '').replace('\n', '')
            j[3] = clss
            writer.writerow(j+[sig])
            # sigs.append(j[4]+':'+j[10]+args)
            # sig_translation()
if __name__=='__main__':
    formalize_cve_func()
