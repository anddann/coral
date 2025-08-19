from bs4 import BeautifulSoup


html_doc = open('/compat_report/9.4.41.v20210516_to_11.0.7/compat_report.html').read()
soup = BeautifulSoup(html_doc, 'html.parser')
class_set = set()
methods = set()
for each in soup.find_all('h2'):

    if 'Problems with Data Types, High Severity' in each.text:
        print(each)
        for e in each.next_siblings:

            if 'class="section"' in str(e):
                for desc in e.descendants:
                    if 'class="ttype"' in str(desc):
                        class_set.add(str(desc.next_sibling).strip())
    if 'Problems with Methods, High Severity' in each.text:
        print(each)
        for e in each.next_siblings:

            if 'class="section"' in str(e):
                for desc in e.descendants:
                    if 'class="ext"' in str(desc):
                        methods.add(str(desc.next_sibling).strip())
print(methods)