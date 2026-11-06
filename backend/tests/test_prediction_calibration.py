import pytest

from backend.ml.predict import predict_url


@pytest.mark.parametrize("domain", ["example.com", "github.com", "python.org", "nasa.gov", "apple.com", "bbc.com", "mozilla.org"])
def test_curated_safe_domains_do_not_surface_as_phishing(domain):
    result = predict_url(f"https://www.{domain}/")
    assert result["prediction"] == "Safe"
    assert result["assessment"] == "known_safe_domain"
    assert result["risk_score"] <= 5
    assert result["confidence"] < 0.9
