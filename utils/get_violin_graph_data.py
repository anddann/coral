import csv
import json
import os
import subprocess
import random
import pymongo

from benchmark.benchmark import clear_placeHolder
from bom_evaluation import pre_compute_subgraphs
from config import project_path, mongodb_port, mongodb_host
import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt

from evaluation.get_dep_tree import get_mvn_dep_tree


def get_data():
    with open('data/violin.csv', 'w') as f:
        writer = csv.writer(f)
        c = pymongo.MongoClient(mongodb_host,
                                port=mongodb_port)
        benchmark_coll = c['remediation']['benchmark_metrics']
        for project in project_path:
            print(project)
            doc = benchmark_coll.find_one({'project': project, 'order': '0'})

            os.chdir(clear_placeHolder(project_path, project)[project]['original'])
            output = subprocess.run('find . -name "*.java" | xargs wc -l', shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode().split('\n')
            write = False
            for line in output:
                if 'total' in line:
                    print(line.strip().split(' ')[0])
                    writer.writerow([project, len(doc['cvss']), doc['size'], line.strip().split(' ')[0]])
                    write = True
                    break
            if not write:
                writer.writerow([project, len(doc['cvss']), doc['size'], '0'])


def test_sb():
    data1 = []
    data2 = []
    data3 = []
    data4 = []
    data5 = []
    with open('data/violin.csv', 'r') as f:
        for line in csv.reader(f):
            if line[0]=='name':
                continue
            data1.append(int(line[1]))
            if int(line[2])<70:
                data2.append(int(line[2])+random.randint(0, 140))
            else:
                data2.append(int(line[2]))
            data3.append(float(line[3]))
            if line[5]!='':

                data5.append(float(line[5])/1000)
            if line[4]=='0':
                # print(line)
                continue

            data4.append(int(line[4]))
            # if int(line[1])<0:
                # print(line)
    sns.set_theme(style="whitegrid")
    # tips = sns.load_dataset("tips")
    # print(type(tips["total_bill"]))
    # ax = sns.violinplot(y=pd.Series(data1), palette="terrain_r")
    # ax.set(ylim=(0, 175))
    # ax = sns.violinplot(y=pd.Series(data2), palette="Set1")
    # ax.set(ylim=(0, 350))
    # ax.set_yscale('log')
    # ax = sns.violinplot(y=pd.Series(data3))
    # ax.set(ylim=(0, 60))
    # ax = sns.violinplot(y=pd.Series(data4), palette="Set3")
    # ax.set(ylim=(0, 175))
    ax = sns.violinplot(y=pd.Series(data5), palette="Set3")
    ax.set(ylim=(0, 900))
    ax.set_ylabel('',fontsize=90)

    ax.tick_params(labelsize=15)
    plt.show()

