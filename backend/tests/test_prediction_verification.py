from backend.ml.predict import predict_url


def test_verified_clean_page_overrides_lexical_false_positive():
    result = predict_url(
        "https://www.flipkart.com/",
        {
            "status": "verified",
            "domain_reputation": "not_configured",
            "page_content": "verified",
            "signals": ["Page content was fetched and matched the hostname"],
        },
    )
    assert result["prediction"] == "Safe"
    assert result["assessment"] == "verified_page"
    assert result["risk_score"] == 5


def test_inconclusive_verification_never_reports_unknown_url_as_safe():
    result = predict_url(
        "https://unknown-example.invalid/",
        {
            "status": "unverified",
            "domain_reputation": "unavailable",
            "page_content": "unavailable",
            "signals": ["Page could not be fetched"],
        },
    )
    assert result["prediction"] in {"Needs review", "Phishing"}
    assert result["assessment"] != "screened_safe"
