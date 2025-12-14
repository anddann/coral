import json
import shutil
import subprocess

from requests.exceptions import ConnectionError
from lxml.html import fromstring
from itertools import cycle
import concurrent.futures
import pymongo
import os
import random
import requests
import time
from timeloop import Timeloop
from datetime import timedelta

import config
from config import m2_path, pom_path

PROXIES = []
PROXY_POOL = None
NUM_WORKERS = 16
REFRESH_TIMEOUT = 300  # In seconds
counter = 0
new_counter = 0
error_json = []
error_reason_json = []
download_poms = []
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
        url = 'https://free-proxy-list.net/'
        response = requests.get(url)
        parser = fromstring(response.text)
        proxies = set()
        for i in parser.xpath('//tbody/tr')[:300]:
            if i.xpath('.//td[7][contains(text(),"yes")]'):
                proxy = 'https://' + ':'.join([i.xpath('.//td[1]/text()')[0], i.xpath('.//td[2]/text()')[0]])
                proxies.add(proxy)
            else:
                proxy = 'http://' + ':'.join([i.xpath('.//td[1]/text()')[0], i.xpath('.//td[2]/text()')[0]])
                proxies.add(proxy)
        print(proxies)
        return list(proxies)

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


def _refresh_proxies():
    import csv
    in_ = csv.reader(open('proxy.csv'))
    proxies = []
    for r in in_:
        proxies.append(r[2].lower() + '://' + r[0] + ':' + r[1])
    global PROXIES, PROXY_POOL
    PROXIES = proxies
    PROXY_POOL = cycle(PROXIES)


def get_urls(gavs=None):
    """
        Example Maven pom file download. Change the implementation of
        this method to supply a list of urls to request, along with
        the filenames to use to save the response.
    """

    base_url = 'https://repo1.maven.org/maven2'
    urls = []
    for a in gavs:
        group, artifact, version = a.split('|')
        url = f'{base_url}/{group.replace(".", "/")}/{artifact}/{version}/{artifact}-{version}.pom'
        filename = f'{group.replace(".", "/")}/{artifact}/{version}/{artifact}-{version}.pom'
        urls.append((url, filename))
    return urls


def download(info, m2_repo, total_amount, curl=True):
    try:
        global PROXY_POOL
        global USER_AGENTS
        url, filename = info
        download_complete = False
        global counter
        global new_counter
        # check if exists
        if os.path.exists(os.path.join(m2_repo, filename)):
            print(os.path.join(m2_repo, filename))
            counter += 1
            print(f'Downloaded pom {counter}/{total_amount}, new downloaded: {new_counter}', '\r', end='', flush=True)
            return
        while not download_complete:
            try:
                print(url)
                proxy = next(PROXY_POOL)
                # proxy = "118.174.65.170:52436"
                user_agent = random.choice(USER_AGENTS)
                headers = {'User-Agent': user_agent}
                if not curl:
                    if 'https' in proxy:
                        response = requests.get(url,
                                                headers=headers,
                                                proxies={'https': proxy},
                                                timeout=3)
                    else:
                        response = requests.get(url,
                                                headers=headers,
                                                proxies={'http': proxy},
                                                timeout=3)
                    # decoding to appropriate string
                    response.encoding = 'utf-8'
                # if response.status_code!=200:
                print(response.status_code)
                download_complete = True
                print(f'New downloaded: {new_counter}', '\r', end='', flush=True)

            except ConnectionError:
                # Bad IP address, retry
                print(f'Connection error using proxy {proxy}, retrying.')
            except Exception as e:
                print(f'Error downloading {filename}: {e}')
                error_json.append(filename)
                error_reason_json.append({filename: e.__str__()})
                break
        new_counter += 1
        counter += 1
        # Make dirs
        paths = [m2_repo]
        dirs = filename.split('/')
        for index, dir in enumerate(dirs):
            if index == len(dirs) - 1:
                break
            paths.append(dir)
            dir_to_make = '/'.join(paths)
            os.mkdir(dir_to_make) if not os.path.exists(dir_to_make) else ''
        # Save the response
        if download_complete:
            try:
                with open(m2_repo + '/' + filename, 'w+') as f:
                    f.write(response.text)
                    f.close()
            except Exception as e:
                print(f'Error saving {filename}: {e}')
                error_json.append(filename)
                error_reason_json.append({filename: e.__str__()})
    except Exception as e:
        print(f'Unexpected Exception: {filename}: {e}')
        error_json.append(filename)
        error_reason_json.append({filename: e.__str__()})


# Set up scheduled IP refresh
tl = Timeloop()


@tl.job(interval=timedelta(seconds=REFRESH_TIMEOUT))
def scheduled_ip_refresh():
    refresh_proxies()
    print('IP List refreshed. List length', len(PROXIES))


def download_pom(m2_repo, gavs=None, get_url_fn=None, download_fn=None, curl_flag=False):
    if not get_url_fn:
        get_url_fn = get_urls
    if not download_fn:
        download_fn = download
    # Get the URLs to download
    request_urls = get_url_fn(gavs)

    refresh_proxies()
    tl.start()
    # Download in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
        future_names = [executor.submit(download_fn, url, m2_repo, len(gavs), curl_flag) for url in request_urls]
        for future in concurrent.futures.as_completed(future_names):
            # Wait for all threads to complete
            pass

    tl.stop()


def download_all_poms(gav):
    gavs = [gav]
    download_pom(m2_repo=config.m2_path, gavs=gavs)
    print("downloaded finised, new downloaded: ", new_counter)

def download_pom_one(jar_info):
    print('Downloading', jar_info)

    group_id, artifact_id, version_name = jar_info.split('|')
    local_path = pom_path#os.path.join(download_path, group_id, artifact_id, version_name)
    # os.makedirs(local_path, exist_ok=True)

    # if os.path.exists(os.path.join(local_path, artifact_id+'-'+version_name+'.jar')):
    #     return
    try:
        result = subprocess.check_output(f'mvn dependency:get \
            -DgroupId=%s \
            -DartifactId=%s \
            -Dversion=%s \
            -Dtransitive=false \
            -Ddest={local_path} \
            -DremoteRepositories=https://repo1.maven.org/maven2/ \
            -Dpackaging=pom' % (group_id,
                                 artifact_id,
                                 version_name), shell=True)

        # print(result)
        if not os.path.exists(os.path.join(local_path, artifact_id+'-'+version_name+'.pom')):
            shutil.copyfile(m2_path+group_id.replace('.', '/')+'/'+artifact_id+'/'+version_name+ '/'+ artifact_id+'-'+version_name+'.pom', local_path+artifact_id+'-'+version_name+'.pom')
    except Exception as e:
        print(e)



if __name__=='__main__':
    download_all_poms()