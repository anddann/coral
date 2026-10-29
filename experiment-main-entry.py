import logging
import sys
import subprocess
import json

from algorithm import product_remediation
from evaluation.get_dep_tree import get_mvn_dep_tree
import os

print(sys.argv)
logging.basicConfig(level=logging.INFO)

"""
Adapt the field names to match the expectation
"""


def adapt_mvn_dep_tree(dep_tree):
  dep_tree['libraryVendor'] = dep_tree.pop('groupId')
  dep_tree['libraryName'] = dep_tree.pop('artifactId')
  dep_tree['extrasList'] = None
  if 'children' in dep_tree:
    dep_tree['dependenciesList'] = dep_tree.pop('children')
    for child in dep_tree['dependenciesList']:
      adapt_mvn_dep_tree(child)
  else:
    dep_tree['dependenciesList'] = []



def generate_graph_for_input(project_path):
  cwd = os.getcwd()
  os.chdir(project_path)
  run = subprocess.run(["mvn", "dependency:tree", "-DoutputType=json",
                        "-DoutputFile=deptree.json"], stderr=subprocess.STDOUT)
  run.check_returncode()
  mvn_deptree = None
  with open('deptree.json') as f:
    mvn_deptree = json.load(f)
    os.chdir(cwd)
  adapt_mvn_dep_tree(mvn_deptree)
  return {'root': mvn_deptree}


if __name__ == '__main__':
  print("Experiment Main EntryPoint")
  print(sys.argv)
  project_path = sys.argv[1]
  jar_path = sys.argv[2]

  adaptedgraph = generate_graph_for_input(project_path)
  projectname = "{}:{}:{}".format(adaptedgraph["root"]["libraryVendor"], adaptedgraph["root"]["libraryName"], adaptedgraph["root"]["version"])
  product_remediation(graph_api_std_deptree=adaptedgraph,
                      user_clss_file_path=jar_path, project_name=projectname)
