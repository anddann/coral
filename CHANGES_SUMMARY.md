# Summary of Changes: Decoupling Proprietary Services via deps.dev & OSV

This document provides a detailed trace of all code modifications made on the branch **`deps-dev-integration`**. It documents **what** changed in each file, **why** it changed, and **how** it enables Coral to run on arbitrary new Java projects without private Scantist Graph API servers or an internal MongoDB database.

---

## 1. Overview of Motivation

Coral originally relied on two proprietary backend services developed for research benchmarks:
1. **Scantist Graph API (`GRAPH_API_HOST:8090`)**: Handled package version retrieval, non-vulnerable ("clean") version identification, and CVE lookups. Because this was an internal service (or hosted on lab servers like `155.69.151.221`), it was unavailable for general external use.
2. **MongoDB (`MONGO_HOST:27017`)**: Held internal collections (`library-crawler.maven`, `library-crawler.maven_deps`, `remediation.cve_funcs`, `call_graphs_all`). If MongoDB was missing or unpopulated, candidate discovery stopped completely (`check_central()` returned `False`).

### Core Solution
* Implemented open replacements using Google's **`deps.dev`** API (for versions, direct dependencies, and Central verification) and **`OSV`** API (for batch and single vulnerability lookups).
* Made MongoDB **optional and fail-safe**: MongoDB is now treated strictly as a local cache. If offline or empty, execution falls back automatically to `deps.dev` and local files.

---

## 2. File-by-File Trace of Modifications

### 1. `utils/deps_dev_api.py` (New File)
* **What changed**: Created a unified client for Google's `deps.dev` API (`v3`) and Google's `OSV` API (`v1`).
* **Why it changed**: Serves as the drop-in open replacement for the Scantist Graph API and MongoDB `maven` collection.
* **Key Functions**:
  * `get_all_versions_deps_dev(group, artifact)`: Fetches all published versions from `https://api.deps.dev/v3/systems/maven/packages/...`.
  * `get_clean_versions_deps_dev(group, artifact)`: Uses OSV batch queries (`https://api.osv.dev/v1/querybatch`) in chunks of 50 to find versions with zero reported vulnerabilities.
  * `get_cves_osv(group, artifact, version)`: Queries `https://api.osv.dev/v1/query` for CVEs and GHSAs affecting a specific package version.
  * `get_direct_deps_deps_dev(group, artifact, version)`: Queries deps.dev `:dependencies` to get direct dependency mappings (`group|artifact -> version`).
  * `get_default_version_deps_dev(parent_gav, dep_ga)`: Resolves which version of `dep_ga` is pulled in by `parent_gav`.
  * `is_in_central_deps_dev(group, artifact)`: Checks if an artifact exists in Maven Central.
  * **Caching Layer**: Implements memory caching plus persistent JSON caching in `.deps_cache/` to ensure lookups are fast and minimize external network requests.

---

### 2. `utils/graph_api.py`
* **What changed**:
  * Added import of `USE_DEPS_DEV` from `config` and helper functions from `utils.deps_dev_api`.
  * **`get_clean_versions(gav, c=None)`**: When `USE_DEPS_DEV` is `True` (or if Graph API connection fails), calls `get_clean_versions_deps_dev()` instead of making HTTP POST requests to `http://{graph_api_host}:{graph_api_port}/cleanVers`.
  * **`get_vul_versions(gav, c, clean_versions)`**: Wrapped MongoDB `maven` access in `try/except` and safely falls back to `get_all_versions()`.
  * **`get_dependency_tree(directs, c=None)`**: Added timeout and error handling so failing to reach Scantist's `/allDependencies` fails gracefully rather than halting execution.
* **Why it changed**: Previously, any call to `get_clean_versions` sent HTTP POST requests to unavailable Scantist endpoints, preventing the selection of safe upgrade candidate versions.

---

### 3. `evaluation/get_dep_tree.py`
* **What changed**:
  * **`get_cve(gav)`**: Replaced HTTP POST to `http://{graph_api_host}:{graph_api_port}/issue4one` with `get_cves_osv(g, a, clean_v)` from the OSV API. Added fallback to local `get_cve_from_file(gav)` if network is unavailable.
  * **`get_cves_dict(deps)`**: Updated to call `get_cve(gav)` directly so newly analyzed packages receive live CVE mappings instead of relying solely on the static historical CSV snapshot.
  * **`supplement_edges(c, deps, edges)`**: Added null check (`if c is None: return edges`) and wrapped MongoDB operations in `try/except`.
* **Why it changed**: Enables accurate vulnerability detection for new dependency coordinates while preventing crashes when MongoDB is not running.

---

### 4. `structures/Node.py`
* **What changed**:
  * **`check_central(self, c)`**: Originally queried `c['library-crawler']['maven'].find_one(...)`. If MongoDB was empty or offline, this returned `False`, causing Coral to abort candidate discovery and keep the original (vulnerable) version. Updated to check MongoDB if available, and otherwise verify existence via `is_in_central_deps_dev(g, a)`.
  * **`calculate_candidates_safer(self, c, depGraph)`**: Replaced direct assignment `maven = c['library-crawler']['maven']` with a safe check (`maven = None` if `c is None` or on connection error).
* **Why it changed**: Allows candidate generation and search traversal to proceed normally without requiring pre-loaded MongoDB collections.

---

### 5. `structures/dependencyGraph.py`
* **What changed**:
  * **`exclude_reachable_vulnerable_versions(self, node_ga, cves_dict, c)`**: Wrapped `c['remediation']['cve_funcs']` access in a safety check. If MongoDB is unavailable or a CVE has no method mapping, it logs `CVE func_missing: <cve>` and continues gracefully rather than throwing connection errors.
  * **`reset_sons_by_preferred(self, node, c)`**: If `doc` is not found in MongoDB `maven_deps`, it now queries `get_direct_deps_deps_dev(ng, na, new_version)` from `deps.dev` to reconstruct the dependency tree for the newly selected version.
* **Why it changed**: When Coral switches a node to a new version, it needs to update the child dependency edges. Falling back to `deps.dev` allows child dependency updates to succeed without pre-populated database records.

---

### 6. `utils/db_utils.py`
* **What changed**:
  * Added `serverSelectionTimeoutMS=1000` to `pymongo.MongoClient()` initialization, wrapped in `try/except` so `c`, `maven_deps`, and `maven` degrade to `None` if MongoDB is down.
  * **`get_all_versions(ga, maven)`**: If `maven` collection is `None` or yields no versions, falls back to `get_all_versions_deps_dev(g, a)`.
  * **`get_default_version(parent_gav, dep_ga, c)`**: If MongoDB `maven_deps` has no entry, falls back to `get_default_version_deps_dev(parent_gav, dep_ga)`.
* **Why it changed**: Avoids 30-second connection timeout hangs and guarantees that version enumeration and parent-child version resolution continue working offline or without a database.

---

### 7. `algorithm.py`
* **What changed**:
  * In `all_solver()`, `baseline()`, and `product_remediation()`: Configured `pymongo.MongoClient(MONGO_HOST, port=MONGO_PORT, serverSelectionTimeoutMS=1000)` inside `try/except`, setting `c = None` on failure.
* **Why it changed**: Prevents unhandled driver exceptions when launching the remediation algorithm without a running MongoDB daemon.

---

### 8. `call_graph/construct_call_graphs.py`
* **What changed**:
  * In `get_callees()`: Added null checks for `callgraph_db_all` and `callgraph_db_direct`. Wrapped database index creation and update operations in `try/except`.
  * In `create_call_graph()`: Initialized MongoClient with `serverSelectionTimeoutMS=1000` inside `try/except`. Protected `c.close()` with `if c is not None:`.
* **Why it changed**: MongoDB was used here as a call-graph cache. When Mongo is absent, Soot automatically regenerates the call graph from JAR files on disk (`regen = True`). Safeguarding database writes ensures this fallback operates cleanly.

---

### 9. `pom_dep_extractor/extract_pom_dep.py`
* **What changed**:
  * In `populate_dep(gav, c=None)`: Added safe initialization of MongoClient with a 1-second timeout. Checked `if maven_deps is not None:` before checking or inserting POM records.
* **Why it changed**: Prevents crashes during POM extraction when database caching is inactive.

---

### 10. `config.py` & `config.local.py`
* **What changed**:
  * Added configuration flag:
    ```python
    # deps.dev & OSV integration toggle (replaces proprietary Scantist Graph API)
    USE_DEPS_DEV = os.getenv('USE_DEPS_DEV', 'True').lower() in ('true', '1')
    ```
* **Why it changed**: Provides an explicit toggle. When `True` (default), all Graph API requests are routed through `deps.dev` and `OSV`. Setting it to `False` allows switching back to Scantist Graph API if an endpoint is provided.

---

### 11. `.gitignore` (New File)
* **What changed**:
  * Added `.deps_cache/`, `__pycache__/`, `*.pyc`, `.DS_Store`, and `venv-py39/`.
* **Why it changed**: Prevents cached API query JSON files and Python compilation artifacts from polluting git history.

---

## 3. Verification and Testing

The adaptations were verified using the project's virtual environment:
1. **Module Imports**: Verified that all adapted modules (`config`, `utils.deps_dev_api`, `utils.db_utils`, `utils.graph_api`, `evaluation.get_dep_tree`, `structures.Node`, `structures.dependencyGraph`, `algorithm`) import without syntax or runtime dependency errors.
2. **Live OSV Lookup**: Verified lookup of `io.netty:netty-codec:4.1.67.Final`, successfully retrieving known CVEs (`CVE-2021-37136`, `CVE-2021-37137`, etc.).
3. **Clean Version Detection**: Verified batch query against `io.netty:netty-codec`, correctly identifying non-vulnerable versions.
4. **Central Verification**: Tested `Node('io.netty|netty-codec|4.1.67.Final').check_central(None)` returning `True` without any running MongoDB instance.
