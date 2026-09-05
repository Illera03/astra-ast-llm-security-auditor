"""Safe: importlib.resources style path resolution with static resource name.

Package resource loading with hardcoded names is not exploitable.
"""

from importlib import resources


def load_template():
    ref = resources.files("mypackage.templates").joinpath("base.html")
    return ref.read_text(encoding="utf-8")


def load_default_icon():
    ref = resources.files("mypackage.assets").joinpath("icon.png")
    return ref.read_bytes()


if __name__ == "__main__":
    html = load_template()
    print(html[:100])
