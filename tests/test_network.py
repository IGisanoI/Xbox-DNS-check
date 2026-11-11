"""Network labels must not expose or retain the egress IP address."""

from dnschecker import network, owners


def test_detect_org_returns_org_but_not_public_ip():
    public_ip = "203.0.113.77"
    urls = []

    def rdap(url, timeout):
        urls.append(url)
        return {"name": "EXAMPLE-NET", "country": "RU", "entities": []}

    result = network.detect_org(ip_fetch=lambda url, timeout: public_ip, rdap_fetch=rdap)
    assert result["org"] == "EXAMPLE-NET" and result["country"] == "RU"
    assert public_ip not in result.values() and public_ip not in repr(result)
    assert public_ip in urls[0]  # used in memory for RDAP, never returned


def test_detect_org_fails_closed_without_address_or_exception():
    def unavailable(url, timeout):
        raise OSError("offline")

    assert network.detect_org(ip_fetch=unavailable) == {"org": "", "country": ""}
    assert network.detect_org(ip_fetch=lambda url, timeout: "not an IP") == {"org": "", "country": ""}


def test_rdap_fallback_does_not_leak_ip_into_failure():
    def unavailable(url, timeout):
        raise OSError("offline")

    result = network.detect_org(ip_fetch=lambda url, timeout: "203.0.113.88", rdap_fetch=unavailable)
    assert result == {"org": "", "country": ""}


def test_generic_network_labels_have_no_operator_identity():
    assert set(network.TYPE_LABELS) == {"office", "home", "vpn", "other"}
    assert network.type_key(network.type_label("vpn")) == "vpn"
    assert network.type_key("unknown custom value") == "other"
    assert network.org_text({"org": "Example ISP", "country": "RU"}) == "Example ISP (RU)"
