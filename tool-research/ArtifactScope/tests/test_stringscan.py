from artifactscope.stringscan import analyze_strings


def test_analyze_strings_extracts_url_and_email():
    payload = (
        b"Visit https://example.com now\n"
        b"Contact admin@example.com\n"
        b"Use powershell -enc AAAA\n"
    )
    result = analyze_strings(payload)
    assert "https://example.com" in result["urls"]
    assert "admin@example.com" in result["emails"]
    assert any("powershell" in s.lower() for s in result["suspicious_strings"])
