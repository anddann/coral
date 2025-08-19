import csv
import pymongo

if __name__=='__main__':
    c = pymongo.MongoClient('155.69.151.221',
                            port=27016)
    cve_func_coll = c['remediation']['cve_funcs']
    cve_func_coll.create_index('cve')
    with open('../cve_func_10_22_processed.csv') as f:
        cve_dict = {}
        classes = {}
        methods = {}
        cveset = set()

        for index, line in enumerate(csv.reader(f)):
            if index == 0:
                 continue
            if not line[0] in cve_dict.keys():
                cve_dict[line[0]] = {
                    'cve': line[0],
                    'methods': [],
                    'classes': []
                }
            if line[17]:
                cve_dict[line[0]]['methods'].append(line[17])
                cve_dict[line[0]]['methods'] = list(set(cve_dict[line[0]]['methods']))
            cve_dict[line[0]]['classes'].append(line[3])
            cve_dict[line[0]]['classes'] = list(set(cve_dict[line[0]]['classes']))
        for cve in cve_dict.keys():
            cve_func_coll.update_one({'cve': cve}, {'$set':cve_dict[cve]}, upsert=True)
            # if not doc:
            #     cve_func_coll.insert_one(cve_dict[cve])

    c.close()