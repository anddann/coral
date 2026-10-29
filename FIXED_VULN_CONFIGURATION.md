# Fixed / Custom Vulnerability Configuration Guide

This guide explains how to define a **fixed/custom set of vulnerabilities, vulnerable versions, and non-vulnerable (clean) versions** when running Coral, instead of querying the complete data from OSV.dev.

---

## 1. Overview & Use Case

When testing or benchmarking Coral on a specific dependency update scenario, you often want to:
1. **Target only a specific dependency** (e.g. remediate only `io.netty:netty-codec` while ignoring vulnerabilities in unrelated transitive dependencies).
2. **Control the exact CVEs reported** (e.g. return only `CVE-2021-37136` rather than all 5+ CVEs reported by public feeds).
3. **Control which versions are considered vulnerable vs. clean** (e.g. specify version `X` as vulnerable and versions `Y, Z` as the allowed clean target versions).

---

## 2. Configuration File (`vuln_config.json`)

By default, Coral looks for a file named `vuln_config.json` in the project root directory (or at the path specified by the environment variable `VULN_CONFIG_PATH`).

### Configuration Format Example

```json
{
  "mode": "fixed_only",
  "dependencies": {
    "io.netty:netty-codec": {
      "vulnerable_versions": [
        "4.1.67.Final"
      ],
      "clean_versions": [
        "4.1.68.Final",
        "4.1.69.Final",
        "4.1.70.Final"
      ],
      "cves": {
        "4.1.67.Final": [
          "CVE-2021-37136"
        ]
      }
    }
  }
}
```

### Schema & Fields

* **`mode`**:
  * `"fixed_only"` *(default)*: Only the dependencies explicitly declared under `dependencies` have vulnerabilities. Any other dependency in the project tree is automatically considered **clean** (returns `0` CVEs, all versions safe). This allows you to isolate and test remediation on a single dependency.
  * `"fallback"`: For dependencies defined in this configuration, use the fixed definitions; for any unlisted dependencies, fall back to querying live data from `deps.dev` / `OSV`.

* **`dependencies`**: A dictionary where keys are dependency identifiers in either `groupId:artifactId` or `groupId|artifactId` format:
  * **`vulnerable_versions`**: List of version strings that are marked as vulnerable.
  * **`clean_versions`**: List of version strings that Coral can consider as non-vulnerable upgrade targets.
    * *Tip*: If you omit `clean_versions` but provide `vulnerable_versions`, Coral automatically treats all other versions on Maven Central as clean (`all_versions - vulnerable_versions`).
  * **`cves`**: A mapping from version string to a list of CVE IDs:
    ```json
    "cves": {
      "4.1.67.Final": ["CVE-2021-37136"]
    }
    ```
  * **`default_cves`** *(optional)*: A default list of CVE IDs to assign to any version in `vulnerable_versions` if not explicitly specified in `cves`.

---

## 3. Environment Variables & Settings

In `config.py` / `config.local.py`:

```python
# Enable/disable fixed vulnerability definitions (default: True)
USE_FIXED_VULN = os.getenv('USE_FIXED_VULN', 'True').lower() in ('true', '1')

# Path to the JSON configuration file (default: 'vuln_config.json')
VULN_CONFIG_PATH = os.getenv('VULN_CONFIG_PATH', 'vuln_config.json')
```

To switch back to live OSV.dev querying at any time without modifying files:
```bash
export USE_FIXED_VULN=False
```

---

## 4. Programmatic API (Python)

You can also dynamically define or override vulnerabilities directly in Python code (e.g. inside a test script or harness) using `utils.vuln_config`:

```python
from utils.vuln_config import set_fixed_vulnerabilities

set_fixed_vulnerabilities({
    "mode": "fixed_only",
    "dependencies": {
        "org.apache.logging.log4j:log4j-core": {
            "vulnerable_versions": ["2.14.1"],
            "clean_versions": ["2.15.0", "2.16.0", "2.17.1"],
            "cves": {
                "2.14.1": ["CVE-2021-44228"]
            }
        }
    }
})

# To reset back to loading from file:
set_fixed_vulnerabilities(None)
```
