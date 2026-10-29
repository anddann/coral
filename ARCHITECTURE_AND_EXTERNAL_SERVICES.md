# Coral: External Services Analysis & Minimal Architecture Guide

This document details the external service dependencies of **Coral** (ICSE 2023), analyzes which services are strictly required when running Coral on **new user input** (rather than historical reproduction), and specifies how proprietary dependencies (Scantist Graph API and MongoDB) are replaced with open public services (**deps.dev** and **OSV**).

---

## 1. Part 1: External Sources Breakdown

When analyzing an arbitrary new Java project, Coral performs four core phases:
1. **Dependency tree resolution** (discovering root, direct, and transitive dependencies).
2. **Version candidate selection & ordering** (identifying existing versions on Maven Central and ordering them according to Maven Semantic Versioning rules).
3. **Vulnerability & compatibility assessment** (detecting known CVEs and filtering out versions with breaking API changes via bytecode analysis).
4. **Constraint solving & remediation** (finding an optimal, conflict-free dependency graph that minimizes CVEs without introducing breaking API changes).

Below is the status of every external dependency in the original codebase:

| External Dependency | Endpoint / Port | Where Used in Code | Required for New Input? | How Handled |
| :--- | :--- | :--- | :--- | :--- |
| **Maven Semver API** | `localhost:8080` | `utils/version_utils.py` (`/sort`, `/checkinrange`) | **Yes (Keep Local)** | Required for Maven version comparison/sorting and range evaluations (`[1.0, 2.0)`). Fully self-hosted locally via Docker or `java -jar` from `maven_semver/`. |
| **Maven Central** | `https://repo1.maven.org` | `download_all_jar.py`, `download_pom.py` | **Yes (Network)** | Required to download candidate dependency JARs/POMs so Soot and Revapi can inspect their bytecode. |
| **Java & Maven CLI** | `mvn` | `evaluation/get_dep_tree.py`, `pom_dep_extractor/extract_pom_dep.py` | **Yes (Local CLI)** | Used to extract local project dependency trees (`mvn dependency:tree`) and parse effective POMs. |
| **Soot Parser** | Local JAR (`soot-parser-1.0.0...`) | `call_graph/construct_call_graphs.py`, `reachable_incompatibilities_no_entry.py` | **Yes (Local JAR)** | Constructs whole-program call graphs from the target project JAR. |
| **Revapi** | Local CLI (`revapi-0.11.2/`) | `revapi_return_apis.py`, `structures/Node.py` | **Yes (Local CLI)** | Compares old vs. new candidate JARs to detect breaking API changes. |
| **Graph API** | `localhost:8090` (originally `155.69.151.221`) | `utils/graph_api.py`, `evaluation/get_dep_tree.py` | **No (Replaced)** | Proprietary internal Scantist service. **Replaced with deps.dev and OSV**. |
| **MongoDB** | `localhost:27017` | `Node.py`, `dependencyGraph.py`, `db_utils.py`, `construct_call_graphs.py` | **Optional / Decoupled** | Originally held crawled Maven metadata and cached call graphs. Now decoupled: queries fall back to deps.dev / OSV and local files if MongoDB is down or unpopulated. |
| **PostgreSQL** | `119.8.168.13:5432` (`cvetriage`) | `utils/db_utils.py` (`update_cvss`) | **No (Unused)** | Offline internal Scantist database for CVSS scores. Not invoked at runtime. |

---

## 2. Part 2: Replacing Graph API & MongoDB with deps.dev & OSV

The proprietary Graph API and crawled MongoDB database are replaced using Google's **Open Source Insights API (`deps.dev`)** and **Open Source Vulnerabilities API (`osv.dev`)**.

### Endpoint Mapping Table

| Original Graph API / Mongo Call | Purpose | Open Replacement | Replacement Implementation |
| :--- | :--- | :--- | :--- |
| `POST /cleanVers` | Find versions of an artifact that have 0 vulnerabilities | **OSV Batch Query API**<br>`POST https://api.osv.dev/v1/querybatch` | Queries candidate versions in batches. Any version where `len(vulns) == 0` is classified as clean. (`get_clean_versions_deps_dev`) |
| `POST /issues` & `POST /issue4one` | Find CVE/GHSA IDs affecting a package version | **OSV Single Query API**<br>`POST https://api.osv.dev/v1/query` | Returns all vulnerability records for `pkg:maven/{group}:{artifact}@{version}`. Extracts CVE aliases and GHSA IDs. (`get_cves_osv`) |
| `c['library-crawler']['maven']` | Enumerate all published versions of a package | **deps.dev Package API**<br>`GET https://api.deps.dev/v3/systems/maven/packages/{group}%3A{artifact}` | Returns all known versions on Maven Central. (`get_all_versions_deps_dev`) |
| `POST /allDependencies` & `c['library-crawler']['maven_deps']` | Get resolved transitive dependency tree | **Local Maven CLI** + **deps.dev**<br>`mvn dependency:tree -DoutputType=json`<br>`GET .../versions/{version}:dependencies` | Root project tree is generated directly via local Maven CLI. Transitive dependencies for upgraded candidates are queried via deps.dev `:dependencies`. |
| `POST /fix` & `POST /remediation` | Baseline tool suggestions | **Not needed** | These were only used in the paper as baseline comparisons against Coral's algorithm. Coral's own constraint solver produces the optimal solution. |

### Vulnerability Reachability: Package-level vs. Method-level

* **Package-level (Default & Sound)**: By default, `deps.dev` + `OSV` provide accurate package- and version-level advisories. Versions with reported CVEs are discarded in favor of verified clean versions.
* **Method-level Call Graph Reachability**: When evaluating whether a project actually invokes vulnerable bytecode methods, Coral checks `cve_func_10_22.csv`. If a newly encountered CVE is not present in that CSV, Coral falls back gracefully without crashing, logging `CVE func_missing: <cve>`.

---

## 3. Recommended Minimal Architecture for New Inputs

To run Coral on new projects without private lab servers or commercial credentials, use the following minimal standalone architecture:

```
+-------------------------------------------------------------------------+
|                              New Java Project                            |
|                 (pom.xml + compiled JAR / bytecode classes)             |
+-------------------------------------------------------------------------+
                                     |
                                     | 1. mvn dependency:tree -DoutputType=json
                                     v
+-------------------------------------------------------------------------+
|                            Coral Engine                                  |
|                                                                         |
|  +--------------------+   2. Sort & Range Check   +-------------------+ |
|  |   algorithm.py     | ------------------------> |   maven_semver    | |
|  | (Constraint Solver)| <------------------------ | (localhost:8080)  | |
|  +--------------------+                           +-------------------+ |
|       |          |                                                      |
|       |          | 3. Versions & Vulnerabilities                        |
|       |          v                                                      |
|       |   +---------------------------------------+                     |
|       |   |          utils/deps_dev_api.py        |                     |
|       |   |  - deps.dev (package versions & deps) |                     |
|       |   |  - api.osv.dev (CVE & clean versions) |                     |
|       |   |  - .deps_cache/ (local disk cache)    |                     |
|       |   +---------------------------------------+                     |
|       |                                                                 |
|       | 4. Compatibility & Call Graph Analysis                          |
|       v                                                                 |
|  +--------------------------+    +------------------------------------+ |
|  |     Revapi (CLI)         |    |      Soot Bytecode Parser          | |
|  | (API breaking changes)   |    | (soot-parser-1.0.0-jar...jar)      | |
|  +--------------------------+    +------------------------------------+ |
+-------------------------------------------------------------------------+
                                     |
                                     | 5. Solved conflict-free BOM
                                     v
+-------------------------------------------------------------------------+
|                  Remediation Results (pickle / JSON)                    |
+-------------------------------------------------------------------------+
```

---

## 4. Setup and Execution Steps

### Step 1: Start `maven_semver`
Run the semantic versioning helper microservice on port 8080:
```bash
# Option A: via Docker
cd maven_semver
docker build -t maven-semver .
docker run -d -p 8080:8080 maven-semver

# Option B: directly via Java 8+
java -jar maven_semver/target/maven.semver-1.1-jar-with-dependencies.jar
```

### Step 2: (Optional) Local MongoDB Container
MongoDB is no longer mandatory; Coral will use `deps.dev` / `osv.dev` and local files if MongoDB is not present. If you want Coral to optionally cache query results in a local database:
```bash
docker run -d -p 27017:27017 --name coral-mongo mongo:latest
```

### Step 3: Run Coral on a New Maven Project
Use `experiment-main-entry.py` (which runs `mvn dependency:tree` on your project, adapts the format, and triggers remediation):
```bash
python experiment-main-entry.py /path/to/my-maven-project /path/to/my-maven-project/target/project.jar
```
Or run `production_entry.py` with custom project coordinates and JAR path.

### Step 4: Output
Coral outputs the remediation plan (the recommended dependency version tuple for each direct and transitive dependency) into `remediation_results/<project_name>`.

