import graphviz
from evaluation.get_dep_tree import get_cves_dict

def visualize(edges, deps):
    dot = graphviz.Digraph()
    visited = set()
    cve_dict = get_cves_dict(deps)
    for edge in edges:
        print(edge)
        src = edge[0]
        dst = edge[1]
        src = src
        dst = dst
        if src not in visited:
            if src in cve_dict:
                dot.node(src, src, color = 'red')
            else:
                dot.node(src, src)
            visited.add(src)
        if dst not in visited:
            if dst in cve_dict:
                dot.node(dst, dst, color='red')
            else:
                dot.node(dst, dst)
            visited.add(dst)
        dot.edge(src, dst)
    dot.view()
    exit()
if __name__=='__main__':
    dot = graphviz.Digraph(comment='The Round Table')


    dot.node('A', 'King Arthur')
    dot.node('B', 'Sir Bedevere the Wise')
    dot.node('L', 'Sir Lancelot the Brave')
    dot.edges(['AB', 'AL'])
    dot.edge('B', 'L', constraint='false')
    dot.render(directory='doctest-output').replace('\\', '/')