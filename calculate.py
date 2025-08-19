import csv,os

o = {}
cve_set = set()
zx = csv.reader(open('zhanxian_cve.csv', 'r'))
zx_list = []
for line in zx:
    if line:
        zx_list.append(line[0])
for f in os.listdir('lvye_patch'):
    cve, ga, num = f.split('__')
    cve_set.add(cve)
print(len(set(zx_list)-cve_set))
with open ('have_patch_cve.csv','w') as f:
    w = csv.writer(f)
    for each in cve_set:
        w.writerow([each])
exit()