import logging
import os
logging.getLogger("root").setLevel(logging.WARNING)
logging.basicConfig(level=logging.ERROR)
total_jobs = 80

MONGO_HOST = os.getenv('MONGO_HOST',"localhost")
MONGO_PORT = 27017

mongodb_host = MONGO_HOST
mongodb_port = MONGO_PORT
joern_cli_path = ''
repo_dir = ''
# Reachability flag
check_reachabiliity = False
current_project = 'log4j_samples-loggerProperties'
# Project Path for benchmark
project_path = '../maven_repos/'
# Soot
soot_path = "./soot-parser-1.0.0-jar-with-dependencies.jar "
japicmp_path = ''
japicmp_mod_path = ''
repos_string = ''
# Working Dir
working_dir = './'
testcases_dir = './'


refactoringMiner_path = './libs/RefactoringMiner/build/distributions/RefactoringMiner-3.0.9/bin/RefactoringMiner'

# semantic version
semver_host = os.getenv('SEMSERVER_HOST',"localhost")#'155.69.151.221'
semver_port = 8080

# Graph API
graph_api_host = os.getenv('GRAPH_API_HOST',"localhost")#'155.69.145.245'#'155.69.151.221'##'ec2-13-250-81-217.ap-southeast-1.compute.amazonaws.com'
graph_api_port = '8090'#'8085'

# deps.dev & OSV integration toggle (replaces proprietary Scantist Graph API)
USE_DEPS_DEV = os.getenv('USE_DEPS_DEV', 'True').lower() in ('true', '1')

jar_timeout_default = 600
jar_timeout_short = 120
timeout_flag = "subprocess.TimeoutExpired"

time_difference_in_seconds = 60*60*12


task_total = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
task_local = "8"
task_default = False

regenerate = True
from_pom = False
small_task = True
pom_path = 'pom_dep_extractor/'
download_path = "jars/"
m2_path = '/Users/adann/.m2/repository/'
gav_info_json = "./maven_info_filter.json"
workspace='/Users/adann/Desktop/tool_coral/workspace'