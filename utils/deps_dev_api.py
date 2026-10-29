import json
import logging
import os
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.deps_cache')
os.makedirs(CACHE_DIR, exist_ok=True)

# In-memory caches to speed up repeated lookups during traversal
_MEM_CACHE_VERSIONS: Dict[str, List[str]] = {}
_MEM_CACHE_CLEAN_VERSIONS: Dict[str, Set[str]] = {}
_MEM_CACHE_CVES: Dict[str, Set[str]] = {}
_MEM_CACHE_DIRECT_DEPS: Dict[str, Dict[str, str]] = {}


def _get_cache_path(category: str, key: str) -> str:
    safe_key = key.replace('/', '_').replace(':', '_').replace('|', '_')
    return os.path.join(CACHE_DIR, f"{category}_{safe_key}.json")


def _read_disk_cache(category: str, key: str):
    path = _get_cache_path(category, key)
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return None


def _write_disk_cache(category: str, key: str, data):
    path = _get_cache_path(category, key)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f)
    except Exception:
        pass


def _http_get(url: str, timeout: int = 15) -> Optional[dict]:
    req = urllib.request.Request(
        url,
        headers={'User-Agent': 'coral-reproduction-deps-dev/1.0'}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        logger.debug(f"[DEPS_DEV] GET error for {url}: {e}")
    return None


def _http_post(url: str, payload: dict, timeout: int = 20) -> Optional[dict]:
    body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'coral-reproduction-deps-dev/1.0'
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        logger.debug(f"[OSV] POST error for {url}: {e}")
    return None


def get_all_versions_deps_dev(group: str, artifact: str) -> List[str]:
    """Retrieve all available versions for a Maven package from deps.dev."""
    ga = f"{group}:{artifact}"
    if ga in _MEM_CACHE_VERSIONS:
        return _MEM_CACHE_VERSIONS[ga]

    cached = _read_disk_cache("versions", ga)
    if cached is not None:
        _MEM_CACHE_VERSIONS[ga] = cached
        return cached

    pkg = urllib.parse.quote(ga, safe='')
    url = f"https://api.deps.dev/v3/systems/maven/packages/{pkg}"
    data = _http_get(url)
    versions = []
    if data and 'versions' in data:
        versions = [v['versionKey']['version'] for v in data['versions'] if 'versionKey' in v and 'version' in v['versionKey']]

    if versions:
        _MEM_CACHE_VERSIONS[ga] = versions
        _write_disk_cache("versions", ga, versions)
    return versions


def is_in_central_deps_dev(group: str, artifact: str) -> bool:
    """Check if the given artifact exists on Maven Central via deps.dev."""
    vers = get_all_versions_deps_dev(group, artifact)
    return len(vers) > 0


def get_cves_osv(group: str, artifact: str, version: str) -> Set[str]:
    """Query OSV for CVEs / GHSAs affecting a specific version."""
    gav = f"{group}:{artifact}:{version}"
    if gav in _MEM_CACHE_CVES:
        return _MEM_CACHE_CVES[gav]

    cached = _read_disk_cache("cves", gav)
    if cached is not None:
        res_set = set(cached)
        _MEM_CACHE_CVES[gav] = res_set
        return res_set

    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": f"{group}:{artifact}",
            "ecosystem": "Maven"
        },
        "version": version
    }
    data = _http_post(url, payload)
    cves: Set[str] = set()
    if data and 'vulns' in data:
        for vuln in data['vulns']:
            # Prefer CVE aliases if present
            aliases = vuln.get('aliases', [])
            cve_aliases = [a for a in aliases if a.startswith('CVE-')]
            if cve_aliases:
                cves.update(cve_aliases)
            else:
                cves.add(vuln.get('id', ''))

    cves.discard('')
    _MEM_CACHE_CVES[gav] = cves
    _write_disk_cache("cves", gav, list(cves))
    return cves


def get_clean_versions_deps_dev(group: str, artifact: str) -> Set[str]:
    """
    Finds all clean (non-vulnerable) versions of an artifact using OSV querybatch.
    """
    ga = f"{group}:{artifact}"
    if ga in _MEM_CACHE_CLEAN_VERSIONS:
        return _MEM_CACHE_CLEAN_VERSIONS[ga]

    cached = _read_disk_cache("clean_vers", ga)
    if cached is not None:
        res_set = set(cached)
        _MEM_CACHE_CLEAN_VERSIONS[ga] = res_set
        return res_set

    all_vers = get_all_versions_deps_dev(group, artifact)
    if not all_vers:
        return set()

    clean_versions = set()
    url = "https://api.osv.dev/v1/querybatch"

    # Batch query OSV in chunks of 50 to avoid timeout/payload limits
    chunk_size = 50
    for i in range(0, len(all_vers), chunk_size):
        chunk = all_vers[i:i + chunk_size]
        queries = [
            {
                "package": {"name": ga, "ecosystem": "Maven"},
                "version": v
            }
            for v in chunk
        ]
        data = _http_post(url, {"queries": queries})
        if data and 'results' in data:
            for ver, res in zip(chunk, data['results']):
                vulns = res.get('vulns', [])
                if len(vulns) == 0:
                    clean_versions.add(ver)
                else:
                    # Cache CVEs found for this version as well
                    cves = set()
                    for vuln in vulns:
                        cve_aliases = [a for a in vuln.get('aliases', []) if a.startswith('CVE-')]
                        if cve_aliases:
                            cves.update(cve_aliases)
                        else:
                            cves.add(vuln.get('id', ''))
                    cves.discard('')
                    _MEM_CACHE_CVES[f"{group}:{artifact}:{ver}"] = cves
                    _write_disk_cache("cves", f"{group}:{artifact}:{ver}", list(cves))
        else:
            # If batch fails, assume versions without known issues
            pass

    _MEM_CACHE_CLEAN_VERSIONS[ga] = clean_versions
    _write_disk_cache("clean_vers", ga, list(clean_versions))
    return clean_versions


def get_direct_deps_deps_dev(group: str, artifact: str, version: str) -> Dict[str, str]:
    """
    Returns direct dependencies declared by parent GAV:
    { "dep_group|dep_artifact": "dep_version" }
    """
    parent_gav = f"{group}:{artifact}:{version}"
    if parent_gav in _MEM_CACHE_DIRECT_DEPS:
        return _MEM_CACHE_DIRECT_DEPS[parent_gav]

    cached = _read_disk_cache("direct_deps", parent_gav)
    if cached is not None:
        _MEM_CACHE_DIRECT_DEPS[parent_gav] = cached
        return cached

    pkg = urllib.parse.quote(f"{group}:{artifact}", safe='')
    ver = urllib.parse.quote(version, safe='')
    url = f"https://api.deps.dev/v3/systems/maven/packages/{pkg}/versions/{ver}:dependencies"
    data = _http_get(url)

    direct_deps: Dict[str, str] = {}
    if data and 'nodes' in data and 'edges' in data:
        nodes = data['nodes']
        edges = data['edges']
        # Node index 0 is the root node
        for edge in edges:
            if edge.get('fromNode') == 0:
                to_idx = edge.get('toNode')
                if to_idx is not None and to_idx < len(nodes):
                    vkey = nodes[to_idx].get('versionKey', {})
                    name = vkey.get('name', '')
                    dep_v = vkey.get('version', '')
                    if ':' in name and dep_v:
                        dg, da = name.split(':', 1)
                        direct_deps[f"{dg}|{da}"] = dep_v

    _MEM_CACHE_DIRECT_DEPS[parent_gav] = direct_deps
    _write_disk_cache("direct_deps", parent_gav, direct_deps)
    return direct_deps


def get_default_version_deps_dev(parent_gav: str, dep_ga: str) -> str:
    """
    Finds the version of dep_ga pulled in by parent_gav.
    parent_gav can be 'g|a|v' or 'g:a:v'
    dep_ga can be 'dg|da' or 'dg:da'
    """
    p_parts = parent_gav.replace(':', '|').split('|')
    if len(p_parts) < 3:
        return ""
    pg, pa, pv = p_parts[0], p_parts[1], p_parts[2]
    d_ga_key = dep_ga.replace(':', '|')

    directs = get_direct_deps_deps_dev(pg, pa, pv)
    return directs.get(d_ga_key, "")
