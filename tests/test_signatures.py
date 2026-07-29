from curlrecon.models import ResponseData
from curlrecon.signatures import analyze_response


def test_analyze_response_cloudflare():
    resp = ResponseData(
        status_code=200,
        headers={"server": "cloudflare", "cf-ray": "some-ray"},
        content_length=100,
        content_type="text/html",
        text="<html></html>",
    )
    matches = analyze_response(resp)
    assert any(m.name == "Cloudflare" for m in matches)


def test_analyze_response_wordpress():
    resp = ResponseData(
        status_code=200,
        headers={"content-type": "text/html"},
        content_length=100,
        content_type="text/html",
        text='<html><meta name="generator" content="WordPress 6.0" /></html>',
    )
    matches = analyze_response(resp)
    assert any(m.name == "WordPress" for m in matches)
