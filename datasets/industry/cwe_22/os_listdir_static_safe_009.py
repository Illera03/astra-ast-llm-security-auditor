"""Safe: os.listdir() with a hardcoded directory path.

Listing a fixed directory carries no traversal risk.
"""
import os


def list_plugins():
    plugin_dir = "/usr/lib/myapp/plugins"
    return [f for f in os.listdir(plugin_dir) if f.endswith(".py")]


def list_log_files():
    return os.listdir("/var/log/myapp")


def count_temp_files():
    entries = os.listdir("/tmp/myapp_cache")
    return len(entries)


if __name__ == "__main__":
    for plugin in list_plugins():
        print(f"Found plugin: {plugin}")
