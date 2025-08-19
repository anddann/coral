import numpy as np
from time import time
from pymoo.factory import get_algorithm, get_crossover, get_mutation, get_sampling, get_termination
from pymoo.optimize import minimize
from pymoo.core.problem import ElementwiseProblem
from bom_evaluation import evaluate

class MyProblem(ElementwiseProblem):
    c = None
    count= 1
    def __init__(self, n_var=2, n_obj=1, n_constr=1, xl=0, xu=10, type_var=int, subgraph={}):
        super().__init__(n_var=n_var, n_obj=n_obj, n_constr=n_constr, xl=xl, xu=xu, type_var=type_var)
        self.subgraph = subgraph
    def _evaluate(self, x, out, *args, **kwargs):
        start = time()
        current_reachable_cve_count, remaining_unreachable_cves, AI, efforts = evaluate(x, self.count, self.subgraph)
        out["F"] = [remaining_unreachable_cves, AI, efforts]
        out["G"] = [current_reachable_cve_count]
        print('#### Evaluation took', "%.2f" % (time()-start), 's ####')
        self.count +=1


def solver(upperbounds, subgraph):
    # Skip non vulnerable subgraph
    if len(subgraph['cves'])==0:
        return




    start_time = time()
    method = get_algorithm("nsga2",
                           pop_size=20,
                           sampling=get_sampling("int_random"),
                           crossover=get_crossover("int_sbx", prob=1.0, eta=3.0),
                           mutation=get_mutation("int_pm", eta=3.0),
                           eliminate_duplicates=True,
                           )

    myproblem = MyProblem(n_var=len(upperbounds), n_obj=3, n_constr=1, xl=np.array([0 for a in upperbounds]), xu=np.array([a[1]-1 for a in upperbounds]), type_var=int, subgraph=subgraph)
    res = minimize(myproblem,
                   method,
                   get_termination('n_eval', 3),
                   seed=1,
                   save_history=True,
                   verbose=True
                   )

    print("Best solution found: %s" % res.X)
    print("Function value: %s" % res.F)
    print("Constraint violation: %s" % res.CV)
    print('MOO took:', "%.2f" % (time() - start_time), 's')
    # print(res.opt)
    # print(res.pop.get('X'))