import json
from pathlib import Path

DEFAULT_CONFIG = {
    "scan": {
        "start_port": 1,
        "end_port": 1024,
        "timeout": 0.5,
        "workers": 100,
    }
}


def load_config(config_file):
    path = Path(config_file)

    if not path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {config_file}"
        )

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        config = json.load(file)

    return config


def save_default_config(config_file):
    path = Path(config_file)

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            DEFAULT_CONFIG,
            file,
            indent=4,
        )


def get_scan_config(config):
    scan_config = DEFAULT_CONFIG["scan"].copy()
    scan_config.update(config.get("scan", {}))

    return scan_config