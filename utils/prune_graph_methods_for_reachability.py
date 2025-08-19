import re
def prune_graph(graph):
    ret =set()
    for methods in list(graph.values()):
        for node in methods:
            res = re.search('\(.*\)', node)
            if res:
                first_half = node.replace(res.group(0), '')
                args = []
                for arg in res.group(0).strip('()').replace(' ', '').split(','):
                    args.append(arg.split('.')[-1])
                ret.add(first_half+'('+','.join(args)+')')
            else:
                ret.add(node)
    ret2 = set()
    for methods in list(graph.values()):
        for node in methods:
            tmp = re.sub('\:.*$', '', node)
            ret2.add(re.sub('\$.*$', '', tmp))
    return ret, ret2