import json
import os

from jinja2 import Environment, FileSystemLoader

from curlrecon.models import ScanReport


def generate_html_report(report: ScanReport, output_path: str):
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("dashboard.html")

    # We will pass the report model dumped to dict, plus a JSON string for JS filtering
    report_dict = report.model_dump()
    report_json = json.dumps(report_dict)

    html_content = template.render(report=report, report_json=report_json)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
