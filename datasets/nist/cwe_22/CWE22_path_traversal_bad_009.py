"""
CWE-22: Path Traversal — Vulnerable
Pattern: Django view reading template file from user-controlled parameter.
Related: CVE-2019-14234 (Django JSONField key traversal)
"""
import os

TEMPLATE_DIR = "/app/templates"


def render_custom_template(request):
    template_name = request.GET.get("template", "default.html")
    template_path = os.path.join(TEMPLATE_DIR, template_name)
    with open(template_path) as f:
        content = f.read()
    return content
