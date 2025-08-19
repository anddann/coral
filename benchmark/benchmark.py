import os
import pymongo
import pickle
from config import working_dir, project_path as paths, mongodb_host, mongodb_port
from bom_evaluation import evaluate_other_tools, evaluate_original_for_benchmark, evaluate_algo, evaluate_baseline, \
    eval_scantist, testing_compilation_n_unit_tests_for_one, evaluate_all_smt, evaluate_large_scale
from algorithm import remediation, baseline as bl_algo, all_smt_remediation


def tool(project, real_pr_flag=False):
    project_path = clear_placeHolder(paths, project, real_pr_flag)
    original_path = project_path[project]['original']
    jar_path = project_path[project]['jar']
    # if os.path.exists(working_dir+'remediation_results/' + project.replace('/', '_')):
    #     return
    return remediation(project, original_path, jar_path)

def tool_large_scale(name, path, jar_path):
    original_path = path
    if os.path.exists(working_dir+'remediation_results_large_scale/' + name):
        return None
    return remediation(name, original_path, jar_path, large_scale=True)


def all_smt_baseline(project):
    project_path = clear_placeHolder(paths, project)
    original_path = project_path[project]['original']
    jar_path = project_path[project]['jar']
    if os.path.exists(working_dir+'remediation_results/' + project.replace('/', '_')+'_all_smt'):
        return
    return all_smt_remediation(project, original_path, jar_path)

# old baseline (pick latest)
def baseline(project):
    project_path = clear_placeHolder(paths, project)
    original_path = project_path[project]['original']
    if os.path.exists(working_dir+'remediation_results/' + project.replace('/', '_')+'_baseline'):
        return
    bl_algo(project, original_path)

def all_solver(project):
    project_path = clear_placeHolder(paths, project)
    original_path = project_path[project]['original']
    if os.path.exists(working_dir+'remediation_results/' + project.replace('/', '_')+'_allSolver'):
        return


def benchmark_baseline(project, project_path, old_edges, root):
    print('[INFO] Evaluating Baseline')
    with open(working_dir+'remediation_results/' + project.replace('/', '_')+'_baseline', 'rb') as handle:
        edges = pickle.load(handle)

    evaluate_baseline(project, edges, project_path[project]['jar'], old_edges, root)

def benchmark_all_smt(project, project_path, old_edges):
    print('[INFO] Evaluating all smt')
    if not os.path.exists(working_dir + 'remediation_results/' + project.replace('/', '_')+'_all_smt'):
        return
    with open(working_dir + 'remediation_results/' + project.replace('/', '_')+'_all_smt', 'rb') as handle:
        depGraph = pickle.load(handle)

    depGraph.check_preferred()
    evaluate_all_smt(project, depGraph, project_path[project]['jar'], old_edges, project_path[project]['test'])

def  benchmark_tool(project, project_path, old_edges):
    print('[INFO] Evaluating tool')
    if not os.path.exists(working_dir+'remediation_results/' + project.replace('/', '_')):
        connection = pymongo.MongoClient(mongodb_host, port=mongodb_port)
        # unset 'size' to mark the doc is invalid
        connection['remediation']['benchmark_metrics'].update_one({'order': 'Tool', 'project': project}, {'$unset': {
            'size':1
        }})
    with open(working_dir+'remediation_results/' + project.replace('/', '_'), 'rb') as handle:
        depGraph = pickle.load(handle)

    depGraph.check_preferred()
    project_path[project] = normalize_test_path(project_path[project])
    evaluate_algo(project, depGraph, project_path[project]['jar'], old_edges, project_path[project]['test'])

def normalize_test_path(paths):
    import re
    if paths['test'] == paths['original']:
        # Regex pattern to match `/remediation/` and `seata/`
        pattern = r"(/Users/lyuye/workspace/java-remediation/)(remediation)(/)(seata)(/.*)"

        # Replacement string
        replacement = r"\1tool\3seata_test\5"
        paths['test'] = re.sub(pattern, replacement, paths['test'])
    return paths

def benchmark_large_scale(project, jar, old_edges):
    print('[INFO] Evaluating tool')
    # if not os.path.exists(working_dir+'remediation_results_large_scale/' + project.replace('/', '_')):
    #     connection = pymongo.MongoClient(mongodb_host, port=mongodb_port)
    #     # unset 'size' to mark the doc is invalid
    #     connection['remediation']['benchmark_metrics'].update_one({'order': 'Tool', 'project': project}, {'$unset': {
    #         'size':1
    #     }})
    with open(working_dir+'remediation_results_large_scale/' + project, 'rb') as handle:
        depGraph = pickle.load(handle)

    depGraph.check_preferred()
    evaluate_large_scale(project, depGraph, jar, old_edges,)

def clear_placeHolder(project_path, project, real_pr_flag =False):
#     if real_pr_flag:
#         sub_project = project.split('_')[-1]
#         for key in real_pr[project]:
#             if 'PLACEHOLDER' in real_pr[project][key]:
#                 real_pr[project][key] = real_pr[project][key].replace('PLACEHOLDER', sub_project)
#         return real_pr
    sub_project = project.split('_')[-1]
    for key in project_path[project]:
        if 'PLACEHOLDER' in project_path[project][key]:
            project_path[project][key] = project_path[project][key].replace('PLACEHOLDER', sub_project)
    return project_path

def switch_to_new_mac_path(project_path, project):
    sub_project = project.split('_')[-1]
    for key in project_path[project]:
        project_path[project][key] = project_path[project][key].replace('/Users/lyuye/workspace/remediation/', '/Users/lyuye/workspace/java-remediation/remediation/')
    return project_path

def testing_compilation_test(project):
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    project_path = clear_placeHolder(paths, project)
    # testing_compilation_n_unit_tests_for_one(project, project_path[project], '0', c)
    # testing_compilation_n_unit_tests_for_one(project, project_path[project], 'Tool', c)
    # testing_compilation_n_unit_tests_for_one(project, project_path[project], 'baseline', c)
    # testing_compilation_n_unit_tests_for_one(project, project_path[project], 'snyk', c)
    # testing_compilation_n_unit_tests_for_one(project, project_path[project], 'steady', c)
    # testing_compilation_n_unit_tests_for_one(project, project_path[project], 'scantist', c)
    # testing_compilation_n_unit_tests_for_one(project, project_path[project], 'dpb', c)
    testing_compilation_n_unit_tests_for_one(project, project_path[project], 'all', c)
    # print('[INFO] ~~~ Finish test compilation:', project)


def benchmark(project):
    project_path = clear_placeHolder(paths, project)
    project_path = switch_to_new_mac_path(project_path, project)
    edges, root = evaluate_original_for_benchmark(project, project_path, project_path[project]['original'])
    if edges == None:
        return
    benchmark_tool(project, project_path, edges)
    return

def steady(project, project_path, edges):
    print('[INFO] Evaluating Steady')
    path = (project_path[project]['snyk']).replace('snyk', 'steady')
    evaluate_other_tools(project, path, edges, 'steady', project_path[project]['jar'])

def snyk(project, project_path, edges):
    print('[INFO] Evaluating Snyk')
    path = project_path[project]['snyk']
    evaluate_other_tools(project, path, edges, 'snyk', project_path[project]['jar'])

def dpb(project, project_path, edges):
    print('[INFO] Evaluating DPB')
    path = project_path[project]['dpb']
    evaluate_other_tools(project, path, edges, 'dpb', project_path[project]['jar'])
# def baseline(project, project_path, edges):
#     print('Evaluating Baseline')
#     path = project_path[project]['baseline']
#     evaluate_other_tools(project, path, edges, 'baseline', project_path[project]['jar'])

