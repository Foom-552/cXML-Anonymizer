"""Unit tests for cxml_anonymizer.py.

Run with: pytest tests/
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Make the parent directory importable without installing as a package
sys.path.insert(0, str(Path(__file__).parent.parent))

# Stub streamlit before importing the module so top-level st.* calls don't fail.
# MagicMock auto-creates attributes/methods on first access.
st_stub = MagicMock()
st_stub.session_state = MagicMock()
sys.modules["streamlit"] = st_stub

from cxml_anonymizer import (  # noqa: E402
    _looks_like_xml,
    _sanitize_stem,
    _stable_id,
    _deduplicate_log,
    detect_country,
    validate_cxml_file,
    apply_header_template,
    anonymize_elements,
    process_cxml_content,
    STABLE_ID_HEX_LENGTH,
    MAX_STEM_LENGTH,
    _SAFE_PARSER,
)
from lxml import etree as lxml_ET


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MINIMAL_CXML = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE cXML SYSTEM "http://xml.cxml.org/schemas/cXML/1.2.014/cXML.dtd">
<cXML payloadID="test-001@buyer.example.com" timestamp="2024-01-01T00:00:00Z" version="1.2.014">
  <Header>
    <From><Credential domain="NetworkId"><Identity>buyer-id</Identity></Credential></From>
    <To><Credential domain="NetworkId"><Identity>supplier-id</Identity></Credential></To>
    <Sender><Credential domain="NetworkID"><Identity>provider-id</Identity></Credential></Sender>
  </Header>
  <Request>
    <OrderRequest>
      <OrderRequestHeader orderID="PO-12345" orderDate="2024-01-01" type="new">
        <Total><Money currency="AUD">1000.00</Money></Total>
        <ShipTo>
          <Address>
            <Name xml:lang="en">Test Company</Name>
            <PostalAddress>
              <Street>123 Real St</Street>
              <City>Sydney</City>
              <State>NSW</State>
              <PostalCode>2000</PostalCode>
              <Country isoCountryCode="AU">Australia</Country>
            </PostalAddress>
          </Address>
        </ShipTo>
      </OrderRequestHeader>
    </OrderRequest>
  </Request>
</cXML>"""

CHANGE_PO_CXML = """\
<?xml version="1.0" encoding="UTF-8"?>
<cXML payloadID="change-001@buyer.example.com" timestamp="2024-01-01T00:00:00Z" version="1.2.014">
  <Header>
    <From><Credential domain="NetworkId"><Identity>buyer-id</Identity></Credential></From>
    <To><Credential domain="NetworkId"><Identity>supplier-id</Identity></Credential></To>
    <Sender><Credential domain="NetworkID"><Identity>provider-id</Identity></Credential></Sender>
  </Header>
  <Request>
    <OrderRequest>
      <OrderRequestHeader orderID="PO-12345" orderDate="2024-01-01" type="update" orderVersion="2">
        <Total><Money currency="EUR">500.00</Money></Total>
        <ShipTo>
          <Address>
            <Name xml:lang="en">Test GmbH</Name>
            <PostalAddress>
              <Country isoCountryCode="DE">Germany</Country>
            </PostalAddress>
          </Address>
        </ShipTo>
      </OrderRequestHeader>
    </OrderRequest>
  </Request>
</cXML>"""


def _parse(xml: str) -> lxml_ET._Element:
    return lxml_ET.fromstring(xml.encode(), parser=_SAFE_PARSER)


# ---------------------------------------------------------------------------
# _looks_like_xml
# ---------------------------------------------------------------------------

def test_looks_like_xml_valid_declaration():
    assert _looks_like_xml('<?xml version="1.0"?><root/>')


def test_looks_like_xml_cxml_root():
    assert _looks_like_xml('<cXML payloadID="x"/>')


def test_looks_like_xml_rejects_plain_text():
    assert not _looks_like_xml("Hello, world!")


def test_looks_like_xml_rejects_json():
    assert not _looks_like_xml('{"key": "value"}')


def test_looks_like_xml_strips_leading_whitespace():
    assert _looks_like_xml('   \n<?xml version="1.0"?><root/>')


# ---------------------------------------------------------------------------
# _sanitize_stem
# ---------------------------------------------------------------------------

def test_sanitize_stem_removes_path_traversal():
    result = _sanitize_stem("../../etc/passwd")
    assert ".." not in result
    assert "/" not in result


def test_sanitize_stem_preserves_normal_name():
    assert _sanitize_stem("my_order_file.xml") == "my_order_file"


def test_sanitize_stem_truncates_to_max_len():
    long_name = "a" * 200
    assert len(_sanitize_stem(long_name)) <= MAX_STEM_LENGTH


def test_sanitize_stem_empty_input_returns_file():
    assert _sanitize_stem("") == "file"


# ---------------------------------------------------------------------------
# _stable_id
# ---------------------------------------------------------------------------

def test_stable_id_length():
    assert len(_stable_id("hello")) == STABLE_ID_HEX_LENGTH


def test_stable_id_deterministic():
    assert _stable_id("same input") == _stable_id("same input")


def test_stable_id_different_inputs_differ():
    assert _stable_id("a") != _stable_id("b")


# ---------------------------------------------------------------------------
# _deduplicate_log
# ---------------------------------------------------------------------------

def test_deduplicate_log_removes_exact_duplicates():
    entry = {"field": "Name", "original": "Real Name", "anonymized": "Anonymized Name"}
    result = _deduplicate_log([entry, entry, entry])
    assert result == [entry]


def test_deduplicate_log_preserves_order():
    a = {"field": "A", "original": "x", "anonymized": "y"}
    b = {"field": "B", "original": "x", "anonymized": "y"}
    assert _deduplicate_log([a, b, a]) == [a, b]


def test_deduplicate_log_empty():
    assert _deduplicate_log([]) == []


# ---------------------------------------------------------------------------
# detect_country
# ---------------------------------------------------------------------------

def test_detect_country_iso_code_au():
    root = _parse(MINIMAL_CXML)
    country, region, method = detect_country(root)
    assert country == "AU"
    assert region == "APAC"
    assert "isoCountryCode" in method


def test_detect_country_iso_code_de():
    root = _parse(CHANGE_PO_CXML)
    country, region, method = detect_country(root)
    assert country == "DE"
    assert region == "EMEA"


def test_detect_country_currency_fallback():
    xml = """\
<?xml version="1.0"?>
<cXML payloadID="x" timestamp="2024-01-01T00:00:00Z" version="1.2.014">
  <Header/>
  <Request>
    <OrderRequest>
      <OrderRequestHeader orderID="1" orderDate="2024-01-01" type="new">
        <Total><Money currency="JPY">1000</Money></Total>
      </OrderRequestHeader>
    </OrderRequest>
  </Request>
</cXML>"""
    root = _parse(xml)
    country, region, method = detect_country(root)
    assert country == "JP"
    assert "currency" in method


def test_detect_country_fallback_default():
    xml = """\
<?xml version="1.0"?>
<cXML payloadID="x" timestamp="2024-01-01T00:00:00Z" version="1.2.014">
  <Header/><Request/>
</cXML>"""
    root = _parse(xml)
    _country, _region, method = detect_country(root)
    assert "fallback" in method


# ---------------------------------------------------------------------------
# validate_cxml_file
# ---------------------------------------------------------------------------

def test_validate_accepts_valid_cxml():
    is_valid, msg, meta = validate_cxml_file(MINIMAL_CXML)
    assert is_valid
    assert meta is not None
    assert meta.base_type == "OrderRequest"


def test_validate_rejects_plain_text():
    is_valid, msg, meta = validate_cxml_file("This is not XML")
    assert not is_valid
    assert meta is None


def test_validate_rejects_wrong_root():
    xml = '<?xml version="1.0"?><Invoice payloadID="x"/>'
    is_valid, msg, meta = validate_cxml_file(xml)
    assert not is_valid
    assert "cXML" in msg


def test_validate_rejects_missing_payload_id():
    xml = '<?xml version="1.0"?><cXML timestamp="2024-01-01T00:00:00Z"><Header/></cXML>'
    is_valid, msg, meta = validate_cxml_file(xml)
    assert not is_valid
    assert "payloadID" in msg


def test_validate_detects_change_po():
    is_valid, _msg, meta = validate_cxml_file(CHANGE_PO_CXML)
    assert is_valid
    assert meta.is_change_po


# ---------------------------------------------------------------------------
# apply_header_template
# ---------------------------------------------------------------------------

def test_apply_header_template_sets_payload_id():
    root = _parse(MINIMAL_CXML)
    apply_header_template(root)
    assert root.get("payloadID") == "#PAYLOADID#"


def test_apply_header_template_sets_static_timestamp():
    root = _parse(MINIMAL_CXML)
    apply_header_template(root)
    assert root.get("timestamp") == "2026-01-01T14:53:00-07:00"


def test_apply_header_template_returns_log_entries():
    root = _parse(MINIMAL_CXML)
    log = apply_header_template(root)
    fields = [e["field"] for e in log]
    assert any("payloadID" in f for f in fields)
    assert any("Identity" in f for f in fields)


def test_apply_header_template_preserves_change_po_version():
    root = _parse(CHANGE_PO_CXML)
    _is_valid, _msg, meta = validate_cxml_file(CHANGE_PO_CXML)
    log = apply_header_template(root, doc_meta=meta)
    orh = root.find(".//OrderRequestHeader")
    assert orh is not None
    assert orh.get("orderVersion") == "2"
    preserved = [e for e in log if "preserved" in e.get("anonymized", "").lower()]
    assert preserved


# ---------------------------------------------------------------------------
# anonymize_elements
# ---------------------------------------------------------------------------

def test_anonymize_elements_replaces_street():
    root = _parse(MINIMAL_CXML)
    from cxml_anonymizer import _resolve_profile, GENERIC_ANONYMIZATION_MAP
    profile = {**GENERIC_ANONYMIZATION_MAP, **_resolve_profile("AU", "APAC")}
    profile.pop("display_name", None)
    profile.pop("region", None)
    log = anonymize_elements(root, profile)
    street_el = root.find(".//Street")
    assert street_el is not None
    assert street_el.text != "123 Real St"
    assert any("Street" in e["field"] for e in log)


def test_anonymize_elements_replaces_money_currency():
    root = _parse(MINIMAL_CXML)
    from cxml_anonymizer import _resolve_profile
    profile = _resolve_profile("AU", "APAC")
    anonymize_elements(root, profile)
    money_el = root.find(".//Money")
    assert money_el is not None
    assert money_el.get("currency") == profile.get("currency", "AUD")


# ---------------------------------------------------------------------------
# process_cxml_content (integration)
# ---------------------------------------------------------------------------

def test_process_cxml_content_produces_valid_xml():
    result_xml, log, _cc, _rc, _dm = process_cxml_content(MINIMAL_CXML, country_code="AU", region_code="APAC", detection_method="test")
    assert "<?xml" in result_xml or "<!DOCTYPE" in result_xml
    assert len(log) > 0


def test_process_cxml_content_removes_real_street():
    result_xml, _log, *_ = process_cxml_content(MINIMAL_CXML, country_code="AU", region_code="APAC", detection_method="test")
    assert "123 Real St" not in result_xml


def test_process_cxml_content_removes_buyer_identity():
    result_xml, _log, *_ = process_cxml_content(MINIMAL_CXML, country_code="AU", region_code="APAC", detection_method="test")
    assert "buyer-id" not in result_xml
    assert "#SENDERID#" in result_xml or "#RECEIVERID#" in result_xml
