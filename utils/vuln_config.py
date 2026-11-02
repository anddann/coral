import json
import logging
import os
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Global state for in-memory or file-loaded configuration
_ACTIVE_CONFIG: Optional[dict] = None


def normalize_ga(name: str) -> str:
    """Normalize 'group:artifact' or 'group|artifact' to 'group:artifact'."""
    return name.replace('|', ':').strip()


def normalize_gav(name: str) -> str:
    """Normalize GAV to 'group:artifact:version'."""
    parts = name.replace('|', ':').split(':')
    if len(parts) >= 3:
        return f"{parts[0]}:{parts[1]}:{parts[2]}"
    return name


def load_vuln_config(file_path: Optional[str] = None) -> Optional[dict]:
    """Load configuration from a JSON file."""
    global _ACTIVE_CONFIG
    if file_path is None:
        from config import VULN_CONFIG_PATH
        file_path = VULN_CONFIG_PATH

    if file_path and os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                _ACTIVE_CONFIG = data
                logger.info(f"[VULN_CONFIG] Loaded fixed vulnerability config from {file_path}")
                return data
        except Exception as e:
            logger.error(f"[VULN_CONFIG] Failed to load config from {file_path}: {e}")
    return None


def set_fixed_vulnerabilities(config_dict: Optional[dict]):
    """Programmatically set or clear the active fixed vulnerability configuration."""
    global _ACTIVE_CONFIG
    _ACTIVE_CONFIG = config_dict


def get_active_config() -> Optional[dict]:
    """Return the currently active configuration, loading from file if not yet loaded."""
    global _ACTIVE_CONFIG
    if _ACTIVE_CONFIG is None:
        load_vuln_config()
    return _ACTIVE_CONFIG


def is_fixed_vuln_enabled() -> bool:
    """Check if fixed vulnerability configuration is enabled and active."""
    from config import USE_FIXED_VULN
    if not USE_FIXED_VULN:
        return False
    cfg = get_active_config()
    return cfg is not None and isinstance(cfg, dict) and 'dependencies' in cfg


def is_fixed_only_mode() -> bool:
    """
    Returns True if mode is 'fixed_only' (default).
    In 'fixed_only' mode, any dependency NOT listed in the config is treated as
    completely clean (0 CVEs, all versions safe).
    """
    cfg = get_active_config()
    if not cfg:
        return False
    mode = cfg.get('mode', 'fixed_only').lower()
    return mode in ('fixed_only', 'strict', 'isolate')


def get_dep_entry(group: str, artifact: str) -> Optional[dict]:
    """Retrieve the configuration entry for group:artifact, if present."""
    cfg = get_active_config()
    if not cfg or 'dependencies' not in cfg:
        return None
    target_ga = f"{group}:{artifact}"
    for k, v in cfg['dependencies'].items():
        if normalize_ga(k) == target_ga:
            return v
    return None


def get_fixed_cves(group: str, artifact: str, version: str) -> Optional[Set[str]]:
    """
    Returns a set of CVEs for the specified version.
    - If fixed config is enabled:
      - If package is defined in config:
        - If version has explicit CVEs in 'cves', returns set(cves).
        - If version is listed in 'vulnerable_versions', returns default CVEs.
        - Otherwise, returns empty set() (clean).
      - If package is NOT in config and mode is 'fixed_only':
        - Returns empty set() (clean).
    - If not enabled or package not handled in fallback mode: returns None.
    """
    if not is_fixed_vuln_enabled():
        return None

    entry = get_dep_entry(group, artifact)
    if entry is not None:
        # Check explicit CVEs mapping
        cves_map = entry.get('cves', {})
        if version in cves_map:
            return set(cves_map[version])

        # Check if version is listed in vulnerable_versions
        vuln_versions = set(entry.get('vulnerable_versions', []))
        if version in vuln_versions:
            default_cve = entry.get('default_cve', entry.get('default_cves', ['CVE-FIXED-DEFAULT']))
            if isinstance(default_cve, str):
                return {default_cve}
            return set(default_cve)

        # Version is not vulnerable according to the fixed definition
        return set()

    # Package is not in the configuration
    if is_fixed_only_mode():
        return set()

    return None


def get_fixed_clean_versions(group: str, artifact: str) -> Optional[Set[str]]:
    """
    Returns the set of clean (non-vulnerable) versions for group:artifact.
    - If package is defined:
      - If 'clean_versions' is explicitly given, returns set(clean_versions).
      - If 'vulnerable_versions' is given, derives: all_versions - vulnerable_versions.
    - If package is NOT in config and mode is 'fixed_only':
      - Returns all known versions as clean.
    - If not enabled or fallback mode: returns None.
    """
    if not is_fixed_vuln_enabled():
        return None

    entry = get_dep_entry(group, artifact)
    if entry is not None:
        if 'clean_versions' in entry:
            return set(entry['clean_versions'])

        if 'vulnerable_versions' in entry:
            from utils.deps_dev_api import get_all_versions_deps_dev
            vuln_vers = set(entry['vulnerable_versions'])
            all_vers = set(get_all_versions_deps_dev(group, artifact))
            if all_vers:
                return all_vers - vuln_vers
            return set()

        return set()

    if is_fixed_only_mode():
        from utils.deps_dev_api import get_all_versions_deps_dev
        return set(get_all_versions_deps_dev(group, artifact))

    return None


def get_fixed_vuln_versions(group: str, artifact: str) -> Optional[Set[str]]:
    """
    Returns the set of vulnerable versions for group:artifact.
    """
    if not is_fixed_vuln_enabled():
        return None

    entry = get_dep_entry(group, artifact)
    if entry is not None:
        if 'vulnerable_versions' in entry:
            return set(entry['vulnerable_versions'])
        if 'cves' in entry:
            return set(entry['cves'].keys())
        if 'clean_versions' in entry:
            from utils.deps_dev_api import get_all_versions_deps_dev
            clean_vers = set(entry['clean_versions'])
            all_vers = set(get_all_versions_deps_dev(group, artifact))
            if all_vers:
                return all_vers - clean_vers
        return set()

    if is_fixed_only_mode():
        return set()

    return None

