"""
    This snippet of code executes web requests in parallel using rotating IPs
    and fake request headers. Configurable params:
    REFRESH_TIMEOUT - number of seconds to refresh the free IP pool after
    NUM_WORKERS - number of workers to execute in parallel
    request_urls - list of urls to request where each item is a tuple of
                   (url, filename)
    Reference:
    https://www.scrapehero.com/how-to-prevent-getting-blacklisted-while-scraping/
    https://www.scrapehero.com/how-to-fake-and-rotate-user-agents-using-python-3/
"""
import csv
import json
import logging
import subprocess
import threading
import traceback

from requests.exceptions import ConnectionError, ChunkedEncodingError
from itertools import cycle
import concurrent.futures
import os
import random
import requests
import time
from timeloop import Timeloop
from datetime import timedelta, datetime
import logging
from config import download_path, gav_info_json, total_jobs, repos_string
logging.getLogger("root").setLevel(logging.WARNING)
logging.basicConfig(level=logging.DEBUG)
start_time = datetime.now().strftime('%Y%m%d%H%M%S')
PROXIES = []
PROXY_POOL = None
NUM_WORKERS = 30
REFRESH_TIMEOUT = 300  # In seconds
counter = 0
error_counter = 0
new_counter = 0
error_json = []
error_reason_json = []
USER_AGENTS = [
    # Chrome
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
    'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
    # Firefox
    'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)',
    'Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 6.2; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)',
    'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
    'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)'
]
def refresh_proxies():
    def get_new_proxies_list():
        url = "http://list.didsoft.com/get?email=jiahui@scantist.com&pass=9n354k&pid=http3000&showcountry=no"
        response = requests.get(url)
        proxies = response.text.split("\n")
        return proxies

    # Get new proxies
    proxies = get_new_proxies_list()
    counter = 10
    # Retry after 1 second, for a maximum of 10 times
    while not len(proxies) and counter:
        counter -= 1
        time.sleep(1)
        proxies = get_new_proxies_list()

    # Update global variables if successfully obtained new list
    if len(proxies):
        global PROXIES, PROXY_POOL
        PROXIES = proxies
        PROXY_POOL = cycle(PROXIES)


def get_url_default(process_number=100000):
    all_jar_infos = json.load(open("./data/jar_info_jackson-core.json"))

    urls = []

    for document in all_jar_infos:
        urls.append((all_jar_infos[document], all_jar_infos[document].split("/")[-1]))

    return urls


def download(info, m2_repo, total_amount, request_timout=10):
    try:
        global PROXY_POOL
        global USER_AGENTS
        url, filename = info
        download_complete = False
        global counter
        global error_counter

        # check if exists
        if os.path.exists(os.path.join(m2_repo, filename)):
            counter += 1
            print(f'Downloaded pom {counter}/{total_amount}, error: {error_counter}', '\r', end='', flush=True)
            return

        while not download_complete:
            try:

                proxy = next(PROXY_POOL)
                user_agent = random.choice(USER_AGENTS)
                headers = {'User-Agent': user_agent}
                response = requests.get(url,
                                        headers=headers,
                                        proxies={ 'http': proxy},
                                        timeout=request_timout)

                download_complete = True


            except ConnectionError:
                # Bad IP address, retry
                logging.debug(f'Connection error using proxy {proxy}, retrying.')
            except ChunkedEncodingError:
                logging.debug(f'ConnectionResetError error using proxy {proxy}, retrying.')
            except Exception as e:
                if isinstance(e, requests.exceptions.ReadTimeout):
                    logging.debug(f'retry downloading {filename} for {e}')
                    download(info, m2_repo, total_amount, request_timout=request_timout * 4)
                else:
                    error_json.append(info)
                    error_reason_json.append({filename: e.__str__()})
                    logging.debug(f'Error downloading type:{e.__class__.__name__},{filename}: {e}')
                    error_counter += 1
                    logging.debug(f'Downloaded pom {counter}/{total_amount}, error : {error_counter}', '\r',
                          end='', flush=True)

                break

        if download_complete:
            try:
                os.makedirs(m2_repo, exist_ok=True)
                with open(m2_repo + '/' + filename, 'wb+') as f:
                    f.write(response.content)
                    response.close()
                    f.close()
                    counter += 1
                    logging.debug(f'Downloaded pom {counter}/{total_amount}, error : {error_counter}', '\r',
                          end='', flush=True)

            except Exception as e:
                logging.debug(f'Error saving {filename}: {e}')
                error_json.append(info)
                error_reason_json.append({filename: e.__str__()})
                error_counter += 1
                logging.debug(f'Downloaded pom {counter}/{total_amount}, error : {error_counter}', '\r',
                      end='', flush=True)
    except Exception as e:
        logging.debug(f'Unexpected Exception: {filename}: {e}')
        error_json.append(info)
        error_reason_json.append({filename: e.__str__()})
        error_counter += 1
        logging.debug(f'Downloaded pom {counter}/{total_amount}, error : {error_counter}', '\r',
              end='', flush=True)


# Set up scheduled IP refresh
# tl = Timeloop()
# tl.start()

# @tl.job(interval=timedelta(seconds=REFRESH_TIMEOUT))
# def scheduled_ip_refresh():
#     refresh_proxies()
#     logging.debug('IP List refreshed')


def chunk_it(seq, num):
    out = []
    last = 0.0

    if num == 0:
        return out

    avg = len(seq) / float(num)
    while last < len(seq):
        out.append(seq[int(last):int(last + avg)])
        last += avg

    return out


def download_jar_maven(document):
    group_id = document["group_id"]
    artifact_id = document["artifact_id"]
    version_name = document["version_name"]
    try:
        result = subprocess.check_output(f'mvn org.apache.maven.plugins:maven-dependency-plugin:2.8:get \
                                         -DgroupId=%s \
                                         -DartifactId=%s \
                                         -Dversion=%s \
                                         -Dtransitive=false \
                                         -DremoteRepositories={repos_string} \
                                         -Dpackaging=jar' % (group_id,
                                                             artifact_id,
                                                             version_name), shell=True)
        logging.debug("download jar successed: %s" % document)
        return True
    except Exception as e:
        logging.debug("download jar failed: %s" % str(e))
        return False


# def download_parallel_task(jar_infos, total_amount):
#
#     for jar_info in jar_infos:
#         try:
#             filename = jar_info["library_name"] + "-" + jar_info["version_name"] + ".jar"
#             url = "http://insecure.repo1.maven.org/maven2/" + "/".join(jar_info["group_id"].split(".")) \
#                   + "/" +jar_info["library_name"] + "/" +jar_info["version_name"]+ "/" + filename
#
#             info = (url, filename)
#             print(url)
#             m2_repo = os.path.join(download_path, jar_info["group_id"], jar_info["library_name"], jar_info["version_name"] )
#             download(info, m2_repo, total_amount, request_timout=10)
#         except:
#             print(f" {url} - {traceback.format_exc()}")

def download_one_jar(gav):
    with open('download_failure_jar.json', 'r') as f:
        failures = set(json.load(f))
        if gav in failures:
            return
    group_id, artifact_id, version_name = gav.split('|')
    local_path = download_path  # os.path.join(download_path, group_id, artifact_id, version_name)
    os.makedirs(local_path, exist_ok=True)

    if os.path.exists(os.path.join(local_path, artifact_id + '-' + version_name + '.jar')):
        return
    try:
        logging.debug(os.path.join(local_path, artifact_id + '-' + version_name + '.jar'))
        result = subprocess.check_output(f'mvn dependency:get \
                    -DgroupId=%s \
                    -DartifactId=%s \
                    -Dversion=%s \
                    -Dtransitive=false \
                    -Ddest={local_path} \
                    -DremoteRepositories=https://repo1.maven.org/maven2/ \
                    -Dpackaging=jar' % (group_id,
                                        artifact_id,
                                        version_name), shell=True)
    except:
        logging.error('Download Jar Failed: '+ gav)
        with open('download_failure_jar.json', 'w') as f:
            failures.add(gav)
            f.write(json.dumps(list(failures)))
def download_parallel_task(jar_infos, total_amount):
    global counter
    global error_counter

    for jar_info in jar_infos:
        group_id = jar_info["group_id"]
        artifact_id = jar_info["library_name"]
        version_name = jar_info["version_name"]
        # group_id = jar_info["group"]
        # artifact_id = jar_info["artifact"]
        # version_name = jar_info["version"]
        local_path = download_path#os.path.join(download_path, group_id, artifact_id, version_name)
        os.makedirs(local_path, exist_ok=True)

        if os.path.exists(os.path.join(local_path, artifact_id+'-'+version_name+'.jar')):
            continue
        try:
            logging.debug(os.path.join(local_path, artifact_id + '-' + version_name + '.jar'))
            result = subprocess.check_output(f'mvn dependency:get \
                -DgroupId=%s \
                -DartifactId=%s \
                -Dversion=%s \
                -Dtransitive=false \
                -Ddest={local_path} \
                -DremoteRepositories=https://repo1.maven.org/maven2/ \
                -Dpackaging=jar' % (group_id,
                                                                     artifact_id,
                                                                     version_name), shell=True)
            logging.debug(result)
            counter += 1
            logging.debug(f'Downloaded pom {counter}/{total_amount}, error : {error_counter}')
            logging.debug(download_path  +artifact_id+'-'+version_name+'.jar')
        except:
            error_json.append(jar_info)
            error_reason_json.append({"log": traceback.format_exc() })
            error_counter += 1
            logging.debug(f'Downloaded pom {counter}/{total_amount}, error : {error_counter}')




def download_jar():
    global total_jobs

    jar_infos = json.load(open(gav_info_json))

    # refresh_proxies()
    # tl.start()

    if total_jobs > len(jar_infos):
        total_jobs = len(jar_infos)

    if total_jobs > 0:

        jar_infos_list = chunk_it(jar_infos, total_jobs)

        jobs = []
        for x in range(total_jobs):
            thread = threading.Thread(
                target=download_parallel_task, args=(jar_infos_list[x], len(jar_infos)))
            jobs.append(thread)
            thread.start()

        for proc in jobs:
            proc.join()

    # tl.stop()
    logging.debug("download finished!")
    logging.debug(f"downloaded finished, need downloaded: {str(len(jar_infos))}")
    logging.debug(f"downloaded finished, new downloaded: {str(counter)}")
    logging.debug(f"downloaded finished, error downloaded: {str(error_counter)}")


if __name__ == '__main__':
    start_time = datetime.now().strftime('%Y%m%d%H%M%S')

    # before_error_json = json.loads(open(os.path.join("../tmp/", "error_file.json")).read())
    # create the temp folder
    os.makedirs(download_path, exist_ok=True)

    download_jar()

    os.makedirs('./tmp', exist_ok=True)

    error_file = open(os.path.join("./tmp/", "error_file_" + start_time + ".json"), 'w')
    json.dump(error_json, error_file)

    error_reason_file = open(os.path.join("./tmp/", "error_reason_file_" + start_time + ".json"), 'w')
    json.dump(error_reason_json, error_reason_file)
