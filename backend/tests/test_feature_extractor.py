import pytest

from backend.ml.feature_extractor import extract_url_features


def test_legitimate_https_url_features():
    features = extract_url_features("https://www.example.com/docs?lang=en")
    assert features["uses_https"] == 1
    assert features["contains_ip_address"] == 0
    assert features["number_of_query_parameters"] == 1


def test_phishing_indicators_are_extracted():
    features = extract_url_features("http://192.168.1.5/login/verify?password=1")
    assert features["contains_ip_address"] == 1
    assert features["suspicious_keyword_count"] >= 3


@pytest.mark.parametrize("value", ["", "not a url", "ftp://example.com", "javascript:alert(1)", "http://example.com:bad", "https://"])
def test_invalid_urls_are_rejected(value):
    with pytest.raises(ValueError):
        extract_url_features(value)


def test_long_special_character_url_is_supported():
    url = "http://example.com/" + ("a@b?c=d&" * 80)
    features = extract_url_features(url)
    assert features["url_length"] > 75
    assert features["contains_suspicious_symbol"] == 1
