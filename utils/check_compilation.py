import csv
import os
import subprocess

from benchmark.benchmark import clear_placeHolder
from config import project_path

def check_compilation():
    with open('data/compilation_check.py', 'w') as f:
        out = csv.writer(f, delimiter=',',lineterminator='\n')
        snyk = 0
        dpb = 0
        steady = 0
    count =0
    for project in project_path:
        count +=1
        print(count)
        os.chdir(clear_placeHolder(project_path, project)[project]['snyk'])
        try:
            output = subprocess.check_output('mvn compile', stderr=subprocess.STDOUT,
                                             shell=True).decode()
        except Exception as e:
            snyk+=1
            print(clear_placeHolder(project_path, project)[project]['snyk'])


        os.chdir(clear_placeHolder(project_path, project)[project]['dpb'])
        try:
            output = subprocess.check_output('mvn compile', stderr=subprocess.STDOUT,
                                             shell=True).decode()
        except Exception as e:
            dpb+=1
            print(clear_placeHolder(project_path, project)[project]['dpb'])

        os.chdir(clear_placeHolder(project_path, project)[project]['snyk'].replace('_snyk', '_steady'))
        try:
            output = subprocess.check_output('mvn compile', stderr=subprocess.STDOUT,
                                             shell=True).decode()
        except Exception as e:
            steady += 1
            print(clear_placeHolder(project_path, project)[project]['snyk'].replace('_snyk', '_steady'))

    out.writerow(['name', 'error'])
    out.writerow(['snyk', snyk])
    out.writerow(['Dependabot', dpb])
    out.writerow(['steady', steady])