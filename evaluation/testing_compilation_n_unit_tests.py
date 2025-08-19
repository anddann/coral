import os
import re
import subprocess

from config import working_dir


def test_compilation(tool, project, path):
    os.chdir(path)
    if tool !='0':
        subprocess.run('xmllint --format pom.xml --output pom.xml', shell=True, check=False,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL)
    try:
        subprocess.run('mvn compile -Dmaven.test.skip=true -Dcheckstyle.skip=true -Dlicense.skipAddThirdParty=true -Drat.skip=true', shell=True, check=False, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL)
        # proc = subprocess.Popen(['mvn', 'compile', '-Dmaven.test.skip=true'])
        # output, errs = proc.communicate()
        # output = subprocess.check_output('mvn compile -Dmaven.test.skip=true', stderr=subprocess.STDOUT,
        #                              shell=True).decode()
        output = subprocess.run('mvn compile -Dmaven.test.skip=true -Dcheckstyle.skip=true -Dlicense.skipAddThirdParty=true -Drat.skip=true | tee comp_log.txt', shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode()
    except Exception as e:
        print('[INFO] ('+tool+') Compilation Exception for', path+'comp_log.txt', 'of', project)
        # print(e)
        return False
    if 'BUILD SUCCESS' in output:
        return True
    elif 'Could not resolve dependencies for project' in output:
        print('[INFO] ~~~~Dependency Failure for', path+'comp_log.txt', 'of', project)
        return False
    elif '[INFO] BUILD FAILURE' in output:
        print('[INFO] Compilation Failure for', path+'comp_log.txt', 'of', project)
        return False
    else:
        print('[ERROR] Compilation Test Exception for', path+'comp_log.txt', 'of', project)
        return False

def test_unit_test(tool, project, path):
    try:
        os.chdir(path)
        # subprocess.run('mvn test', check=False, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        # output = subprocess.check_output('mvn test', stderr=subprocess.STDOUT,
        #                              shell=True).decode()
        output = subprocess.run('mvn test | tee test_log.txt', check=False, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode()
    except Exception as e:
        print('[INFO] ('+tool+') Unit Test Exception for', path+'test_log.txt', 'of', project)
        # print(e)
        return False, False
    if 'BUILD SUCCESS' in output:
        if '[INFO] No sources to compile' in output:
            # test pass, no test
            return True, False
        else:
            # test pass, have test
            return True, True
    elif '[INFO] BUILD FAILURE' in output:
        if re.search('[INFO] Tests run: \d+, Failures: 0, Errors: 0, Skipped: \d+', output):
            return True, True
        else:
            print('[INFO] Test Failure for', path+'test_log.txt', 'of', project)
            return False, True
    else:
        print('[ERROR] Test Exception for', path+'test_log.txt', 'of', project)
        return False, True
