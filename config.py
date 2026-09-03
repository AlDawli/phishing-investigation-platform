"""
Configuration loader.
Reads config/config.yaml (created by the user from config/config.example.yaml)
and falls back to environment variables so API keys never need to be
hardcoded or committed to git.
"""
import os
import yaml


DEFAULT_CONFIG = {
    "virustotal": {"api_key": ""},
    "abuseipdb": {"api_key": ""},
    "otx": {"api_key": ""},
    "scoring": {
        "newly_registered_days": 30,
        "thresholds": {"HIGH": 70, "MEDIUM": 40, "LOW": 0},
    },
    "network": {
        "enable_live_lookups": True,
        "request_timeout": 10,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str = "config/config.yaml") -> dict:
    cfg = dict(DEFAULT_CONFIG)

    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            user_cfg = yaml.safe_load(f) or {}
        cfg = _deep_merge(cfg, user_cfg)

    # Environment variables take precedence over the file, so CI/CD and
    # containers can inject secrets without touching disk.
    env_map = {
        "VT_API_KEY": ("virustotal", "api_key"),
        "ABUSEIPDB_API_KEY": ("abuseipdb", "api_key"),
        "OTX_API_KEY": ("otx", "api_key"),
    }
    for env_var, (section, key) in env_map.items():
        val = os.environ.get(env_var)
        if val:
            cfg[section][key] = val

    return cfg
