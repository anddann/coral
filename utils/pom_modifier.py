# import xml.etree.ElementTree as ET

import re
import subprocess
import xml.dom.minidom as minidom
from lxml import etree as ET

def update_pom(pom_path, new_deps, dep_dict):
    tree = ET.parse(pom_path)
    root = tree.getroot()
    insert = True
    root_tag = re.search('\{(.*)\}', root.tag).group(1)

    for neighbor in root:
        if type(neighbor.tag) is str and 'dependencyManagement' in neighbor.tag:
            insert = False
            for deps in neighbor:
                for dep in deps:
                    g = ''
                    a = ''
                    for tag in dep:
                        if tag.tag == 'groupId':
                            g = tag.text
                        if tag.tag == 'artifactId':
                            a = tag.text
                    if g+'|'+a in dep_dict:
                        ET.SubElement(dep, 'version').text = list(dep_dict[g+'|'+a])[0]

                for gav in new_deps:
                    g, a, v = gav.split('|')
                    dependency = ET.SubElement(deps, 'dependency')
                    ET.SubElement(dependency, 'groupId').text = g
                    ET.SubElement(dependency, 'artifactId').text = a
                    ET.SubElement(dependency, 'version').text = v


    if insert:
        dependencyManagement = ET.SubElement(root, 'dependencyManagement')
        dependencies = ET.SubElement(dependencyManagement, 'dependencies')
        for gav in new_deps:
            g, a, v = gav.split('|')
            dependency = ET.SubElement(dependencies, 'dependency')
            ET.SubElement(dependency, 'groupId').text = g
            ET.SubElement(dependency, 'artifactId').text = a
            ET.SubElement(dependency, 'version').text = v

    # ET.register_namespace('', root_tag)

    # print(ET.tostring(tree, pretty_print=True).decode())
    with open(pom_path, 'w') as f:
        # xmlstr = minidom.parseString(ET.tostring(root, 'utf-8')).toprettyxml(indent="\t")
        xmlstr = ET.tostring(tree, pretty_print=True,encoding='unicode')
        f.write(xmlstr)
    subprocess.run(f'xmllint --format {pom_path} --output {pom_path}', shell=True, check=False,
                   stdout=subprocess.PIPE,
                   stderr=subprocess.DEVNULL)


