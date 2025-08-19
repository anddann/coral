import functools
import os
import time

from config import m2_path
from download_all_jar import download_one_jar
from jar_config import jar_path


def timer(func):
    """Print the runtime of the decorated function"""

    @functools.wraps(func)
    def wrapper_timer(*args, **kwargs):
        start_time = time.perf_counter()  # 1
        print(f"Running {func.__name__!r}")
        value = func(*args, **kwargs)
        end_time = time.perf_counter()  # 2
        run_time = end_time - start_time  # 3
        print(f"Finished {func.__name__!r} in {run_time:.4f} secs")
        return value

    return wrapper_timer

def get_jar_path(gav1):
    g, a, v = gav1.split('|')
    if os.path.exists(m2_path + '/' + g.replace('.', '/') + '/' + a + '/' + v + '/' + a + '-' + v + '.jar'):
        jar1 = m2_path + '/' + g.replace('.', '/') + '/' + a + '/' + v + '/' + a + '-' + v + '.jar'
    elif os.path.exists(os.path.join(jar_path, a + '-' + v + '.jar')):
        jar1 = os.path.join(jar_path, a + '-' + v + '.jar')
    else:
        print('Downloading ' + gav1, '\r', end='', flush=True)
        download_one_jar(gav1)
        jar1 = os.path.join(jar_path, a + '-' + v + '.jar')
    return jar1