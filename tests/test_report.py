import os

from curlrecon.models import ResponseData, ScanReport, TargetResult, SecurityBaseline
from curlrecon.report import generate_html_report


def test_generate_html_report(tmp_path):
    report_path = os.path.join(tmp_path, "report.html")

    target = TargetResult(
        url="https://test.com",
        success=True,
        response=ResponseData(
            status_code=200,
            content_length=123,
            content_type="text/html"
        ),
        security=SecurityBaseline()
    )

    scan_report = ScanReport(
        targets=[target], total_scanned=1, successful=1, failed=0, scan_duration=1.0
    )

    generate_html_report(scan_report, report_path)

    assert os.path.exists(report_path)
    with open(report_path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "https://test.com" in content
