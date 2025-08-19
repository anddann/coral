import re

def get_class(methods):
    ret = set()
    for method in methods:
        ret.add(method.split(':')[0])
    return ret

def clean_args_for_cve_mappings(methods):
    ret = set()
    for method in methods:
        pack_class_method_name = re.sub('\(.*\)', '', method)
        ret.add(pack_class_method_name)
    return ret

