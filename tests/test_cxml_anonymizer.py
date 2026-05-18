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


# ---------------------------------------------------------------------------
# Value Consistency Engine — Extrinsic ↔ IdReference cross-reference
# ---------------------------------------------------------------------------

_CONSISTENCY_CXML = """\
<?xml version="1.0" encoding="UTF-8"?>
<cXML payloadID="inv-001@test.example.com" timestamp="2024-01-01T00:00:00Z" version="1.2.014">
  <Header>
    <From><Credential domain="NetworkId"><Identity>buyer</Identity></Credential></From>
    <To><Credential domain="NetworkId"><Identity>supplier</Identity></Credential></To>
    <Sender><Credential domain="NetworkID"><Identity>provider</Identity></Credential></Sender>
  </Header>
  <Request>
    <InvoiceDetailRequest>
      <InvoiceDetailRequestHeader invoiceID="INV-001" invoiceDate="2024-01-01"
          operation="new" purpose="standard">
        <InvoicePartner>
          <Contact role="buyerCorporate">
            <IdReference identifier="MR85000769" domain="vatID"/>
          </Contact>
        </InvoicePartner>
        <Extrinsic name="buyerVatID">MR85000769</Extrinsic>
      </InvoiceDetailRequestHeader>
    </InvoiceDetailRequest>
  </Request>
</cXML>"""


def test_consistency_same_vat_in_extrinsic_and_idref():
    """A VAT ID appearing in both an Extrinsic and an IdReference should produce
    the same anonymized placeholder in the output document."""
    result_xml, _log, *_ = process_cxml_content(
        _CONSISTENCY_CXML, country_code="AU", region_code="APAC", detection_method="test"
    )
    assert "MR85000769" not in result_xml, "Real VAT ID must be removed"
    # The Extrinsic maps buyerVatID → "Buyer ABN"; the IdReference must inherit that value.
    root = lxml_ET.fromstring(result_xml.encode())
    extrinsic = root.find(".//{*}Extrinsic[@name='buyerVatID']")
    id_ref = root.find(".//{*}IdReference[@domain='vatID']")
    assert extrinsic is not None and id_ref is not None
    assert extrinsic.text == id_ref.get("identifier"), (
        f"Extrinsic ({extrinsic.text!r}) and IdReference ({id_ref.get('identifier')!r}) "
        "must have the same anonymized value"
    )


def test_consistency_per_file_isolation():
    """Two calls to process_cxml_content on the same XML must produce independent
    value maps — i.e., results are deterministic but not shared across calls."""
    args = {"country_code": "AU", "region_code": "APAC", "detection_method": "test"}
    xml1, _log1, *_ = process_cxml_content(_CONSISTENCY_CXML, **args)
    xml2, _log2, *_ = process_cxml_content(_CONSISTENCY_CXML, **args)
    # Both results should be identical (deterministic map entries from the same source)
    root1 = lxml_ET.fromstring(xml1.encode())
    root2 = lxml_ET.fromstring(xml2.encode())
    ext1 = root1.find(".//{*}Extrinsic[@name='buyerVatID']")
    ext2 = root2.find(".//{*}Extrinsic[@name='buyerVatID']")
    assert ext1 is not None and ext2 is not None
    assert ext1.text == ext2.text


# ---------------------------------------------------------------------------
# invoiceSourceDocument — must be preserved (structural classifier, not PII)
# ---------------------------------------------------------------------------

_INV_SOURCE_DOC_CXML = """\
<?xml version="1.0" encoding="UTF-8"?>
<cXML payloadID="inv-002@test.example.com" timestamp="2024-01-01T00:00:00Z" version="1.2.014">
  <Header>
    <From><Credential domain="NetworkId"><Identity>buyer</Identity></Credential></From>
    <To><Credential domain="NetworkId"><Identity>supplier</Identity></Credential></To>
    <Sender><Credential domain="NetworkID"><Identity>provider</Identity></Credential></Sender>
  </Header>
  <Request>
    <InvoiceDetailRequest>
      <InvoiceDetailRequestHeader invoiceID="INV-002" invoiceDate="2024-01-01"
          operation="new" purpose="standard">
        <Extrinsic name="invoiceSourceDocument">PurchaseOrder</Extrinsic>
        <Extrinsic name="invoiceType">standard</Extrinsic>
      </InvoiceDetailRequestHeader>
    </InvoiceDetailRequest>
  </Request>
</cXML>"""


def test_extrinsic_invoiceSourceDocument_preserved():
    """invoiceSourceDocument is a structural classifier and must not be anonymized."""
    result_xml, _log, *_ = process_cxml_content(
        _INV_SOURCE_DOC_CXML, country_code="AU", region_code="APAC", detection_method="test"
    )
    root = lxml_ET.fromstring(result_xml.encode())
    ext = root.find(".//{*}Extrinsic[@name='invoiceSourceDocument']")
    assert ext is not None
    assert ext.text == "PurchaseOrder", (
        f"invoiceSourceDocument must be preserved unchanged, got {ext.text!r}"
    )


def test_extrinsic_invoiceType_preserved():
    """invoiceType ('standard', 'creditNote') is structural metadata and must not be anonymized."""
    result_xml, _log, *_ = process_cxml_content(
        _INV_SOURCE_DOC_CXML, country_code="AU", region_code="APAC", detection_method="test"
    )
    root = lxml_ET.fromstring(result_xml.encode())
    ext = root.find(".//{*}Extrinsic[@name='invoiceType']")
    assert ext is not None
    assert ext.text == "standard"


# ---------------------------------------------------------------------------
# invoicePDF structural Extrinsic — child URL elements must be anonymized
# ---------------------------------------------------------------------------

_INVOICE_PDF_CID_CXML = """\
<?xml version="1.0" encoding="UTF-8"?>
<cXML payloadID="inv-003@test.example.com" timestamp="2024-01-01T00:00:00Z" version="1.2.014">
  <Header>
    <From><Credential domain="NetworkId"><Identity>buyer</Identity></Credential></From>
    <To><Credential domain="NetworkId"><Identity>supplier</Identity></Credential></To>
    <Sender><Credential domain="NetworkID"><Identity>provider</Identity></Credential></Sender>
  </Header>
  <Request>
    <InvoiceDetailRequest>
      <InvoiceDetailRequestHeader invoiceID="INV-003" invoiceDate="2024-01-01"
          operation="new" purpose="standard">
        <Extrinsic name="invoicePDF">
          <Attachment>
            <URL>cid:1280686519.12345@cxml.org</URL>
          </Attachment>
        </Extrinsic>
      </InvoiceDetailRequestHeader>
    </InvoiceDetailRequest>
  </Request>
</cXML>"""

_INVOICE_PDF_HTTPS_CXML = _INVOICE_PDF_CID_CXML.replace(
    "cid:1280686519.12345@cxml.org", "https://real-company.example.com/invoice.pdf"
)


def test_extrinsic_invoicePDF_cid_anonymized():
    """CID attachment URLs inside an invoicePDF Extrinsic must be replaced with the
    canonical cid:anonymized@cxml.org placeholder."""
    result_xml, _log, *_ = process_cxml_content(
        _INVOICE_PDF_CID_CXML, country_code="AU", region_code="APAC", detection_method="test"
    )
    assert "cid:1280686519.12345@cxml.org" not in result_xml
    assert "cid:anonymized@cxml.org" in result_xml


def test_extrinsic_invoicePDF_https_anonymized():
    """HTTPS attachment URLs inside an invoicePDF Extrinsic must be replaced with
    https://anonymized.example.com."""
    result_xml, _log, *_ = process_cxml_content(
        _INVOICE_PDF_HTTPS_CXML, country_code="AU", region_code="APAC", detection_method="test"
    )
    assert "real-company.example.com" not in result_xml
    assert "https://anonymized.example.com" in result_xml


# ---------------------------------------------------------------------------
# New Extrinsic field mappings
# ---------------------------------------------------------------------------

def _make_extrinsic_cxml(*name_value_pairs: tuple[str, str]) -> str:
    """Build a minimal cXML with the given Extrinsic name/value pairs for testing."""
    extrinsics = "".join(
        f'        <Extrinsic name="{name}">{value}</Extrinsic>\n'
        for name, value in name_value_pairs
    )
    return f"""\
<?xml version="1.0" encoding="UTF-8"?>
<cXML payloadID="ext-test@test.example.com" timestamp="2024-01-01T00:00:00Z" version="1.2.014">
  <Header>
    <From><Credential domain="NetworkId"><Identity>buyer</Identity></Credential></From>
    <To><Credential domain="NetworkId"><Identity>supplier</Identity></Credential></To>
    <Sender><Credential domain="NetworkID"><Identity>provider</Identity></Credential></Sender>
  </Header>
  <Request>
    <InvoiceDetailRequest>
      <InvoiceDetailRequestHeader invoiceID="INV-EXT" invoiceDate="2024-01-01"
          operation="new" purpose="standard">
{extrinsics}      </InvoiceDetailRequestHeader>
    </InvoiceDetailRequest>
  </Request>
</cXML>"""


def test_new_extrinsic_banking_fields():
    """Banking Extrinsic fields (iban, swiftCode, bankAccountNumber) must be replaced."""
    xml = _make_extrinsic_cxml(
        ("iban", "DE89370400440532013000"),
        ("swiftCode", "DEUTDEDB"),
        ("bankAccountNumber", "12345678"),
    )
    result_xml, _log, *_ = process_cxml_content(
        xml, country_code="DE", region_code="EMEA", detection_method="test"
    )
    assert "DE89370400440532013000" not in result_xml
    assert "DEUTDEDB" not in result_xml
    assert "12345678" not in result_xml
    assert "ANON-IBAN" in result_xml
    assert "ANONBICX" in result_xml
    assert "ANON-BANK-ACCT" in result_xml


def test_new_extrinsic_legal_fields():
    """Legal entity Extrinsic fields must be replaced with anonymized placeholders."""
    xml = _make_extrinsic_cxml(
        ("legalEntityName", "Real Company GmbH"),
        ("legalEntityID", "HRB-123456"),
    )
    result_xml, _log, *_ = process_cxml_content(
        xml, country_code="DE", region_code="EMEA", detection_method="test"
    )
    assert "Real Company GmbH" not in result_xml
    assert "HRB-123456" not in result_xml
    assert "Anonymized Legal Entity" in result_xml
    assert "ANON-LEGAL-ID" in result_xml


def test_new_extrinsic_invoice_doc_refs():
    """Invoice document reference Extrinsic fields must be replaced."""
    xml = _make_extrinsic_cxml(
        ("invoiceNumber", "INV-2024-001"),
        ("deliveryNoteNo", "DN-98765"),
    )
    result_xml, _log, *_ = process_cxml_content(
        xml, country_code="AU", region_code="APAC", detection_method="test"
    )
    assert "INV-2024-001" not in result_xml
    assert "DN-98765" not in result_xml
    assert "ANON-INVOICE-NO" in result_xml
    assert "ANON-DELIVERY-NO" in result_xml


def test_new_extrinsic_invoice_contacts():
    """Invoice contact Extrinsic fields must be replaced with anonymized placeholders."""
    xml = _make_extrinsic_cxml(
        ("submitterEmail", "john.doe@real-company.com"),
        ("submitterName", "John Doe"),
    )
    result_xml, _log, *_ = process_cxml_content(
        xml, country_code="AU", region_code="APAC", detection_method="test"
    )
    assert "john.doe@real-company.com" not in result_xml
    assert "John Doe" not in result_xml
    assert "submitter@anonymized.com" in result_xml
    assert "Anonymized Submitter" in result_xml


# ---------------------------------------------------------------------------
# Substitution log — Category column
# ---------------------------------------------------------------------------

def test_substitution_log_has_category_column():
    """Every entry in the substitution log must be passable to _log_category()
    and produce a non-empty string result."""
    from cxml_anonymizer import _log_category
    _result_xml, log, *_ = process_cxml_content(
        MINIMAL_CXML, country_code="AU", region_code="APAC", detection_method="test"
    )
    assert log, "Log must not be empty"
    for entry in log:
        cat = _log_category(entry)
        assert isinstance(cat, str) and cat, (
            f"_log_category returned {cat!r} for entry {entry!r}"
        )


# ---------------------------------------------------------------------------
# Distinct profile-field anonymization (Name, Email, Number, Street)
# ---------------------------------------------------------------------------

def _two_contact_cxml(number1: str, number2: str, name1: str = "Acme Corp",
                      name2: str = "Different Corp", email1: str = "",
                      email2: str = "") -> str:
    """Minimal cXML with ShipTo and BillTo contacts carrying the given values."""
    email_block1 = f"<Email>{email1}</Email>" if email1 else ""
    email_block2 = f"<Email>{email2}</Email>" if email2 else ""
    return f"""\
<?xml version="1.0" encoding="UTF-8"?>
<cXML payloadID="tc@test.example.com" timestamp="2024-01-01T00:00:00Z" version="1.2.014">
  <Header>
    <From><Credential domain="NetworkId"><Identity>b</Identity></Credential></From>
    <To><Credential domain="NetworkId"><Identity>s</Identity></Credential></To>
    <Sender><Credential domain="NetworkID"><Identity>p</Identity></Credential></Sender>
  </Header>
  <Request>
    <OrderRequest>
      <OrderRequestHeader orderID="PO-1" orderDate="2024-01-01" type="new">
        <Total><Money currency="AUD">100.00</Money></Total>
        <ShipTo>
          <Address>
            <Name xml:lang="en">{name1}</Name>
            <PostalAddress>
              <Country isoCountryCode="AU">Australia</Country>
            </PostalAddress>
            {email_block1}
            <Phone>
              <TelephoneNumber>
                <CountryCode isoCountryCode="AU">61</CountryCode>
                <AreaOrCityCode>8</AreaOrCityCode>
                <Number>{number1}</Number>
              </TelephoneNumber>
            </Phone>
          </Address>
        </ShipTo>
        <BillTo>
          <Address>
            <Name xml:lang="en">{name2}</Name>
            <PostalAddress>
              <Country isoCountryCode="AU">Australia</Country>
            </PostalAddress>
            {email_block2}
            <Phone>
              <TelephoneNumber>
                <CountryCode isoCountryCode="AU">61</CountryCode>
                <AreaOrCityCode>8</AreaOrCityCode>
                <Number>{number2}</Number>
              </TelephoneNumber>
            </Phone>
          </Address>
        </BillTo>
      </OrderRequestHeader>
    </OrderRequest>
  </Request>
</cXML>"""


def test_two_different_numbers_get_distinct_anonymized_values():
    """Two different original phone numbers must produce two different anonymized values."""
    xml = _two_contact_cxml("65418630", "65421197")
    result_xml, _log, *_ = process_cxml_content(
        xml, country_code="AU", region_code="APAC", detection_method="test"
    )
    assert "65418630" not in result_xml
    assert "65421197" not in result_xml
    root = lxml_ET.fromstring(result_xml.encode())
    numbers = [el.text for el in root.iter()
               if lxml_ET.QName(el.tag).localname == "Number" and el.text]
    assert len(numbers) == 2, f"Expected 2 <Number> elements, found {numbers}"
    assert numbers[0] != numbers[1], (
        f"Two different original numbers must produce distinct anonymized values, got {numbers}"
    )


def test_same_number_appears_twice_gets_consistent_value():
    """The same original phone number in two contacts must anonymize to the same value."""
    xml = _two_contact_cxml("65418630", "65418630")
    result_xml, _log, *_ = process_cxml_content(
        xml, country_code="AU", region_code="APAC", detection_method="test"
    )
    root = lxml_ET.fromstring(result_xml.encode())
    numbers = [el.text for el in root.iter()
               if lxml_ET.QName(el.tag).localname == "Number" and el.text]
    assert len(numbers) == 2, f"Expected 2 <Number> elements, found {numbers}"
    assert numbers[0] == numbers[1], (
        f"The same original number must anonymize consistently, got {numbers}"
    )


def test_two_different_names_get_distinct_values():
    """Two different original <Name> elements must produce distinct anonymized values."""
    xml = _two_contact_cxml("11111111", "22222222",
                            name1="Real Company A", name2="Real Company B")
    result_xml, _log, *_ = process_cxml_content(
        xml, country_code="AU", region_code="APAC", detection_method="test"
    )
    assert "Real Company A" not in result_xml
    assert "Real Company B" not in result_xml
    root = lxml_ET.fromstring(result_xml.encode())
    names = [el.text for el in root.iter()
             if lxml_ET.QName(el.tag).localname == "Name" and el.text]
    assert len(set(names)) >= 2, (
        f"Two different original names must produce distinct anonymized values, got {names}"
    )


def test_two_different_emails_get_distinct_values():
    """Two different original <Email> elements must produce distinct anonymized values."""
    xml = _two_contact_cxml(
        "11111111", "22222222",
        email1="alice@realcompany.com",
        email2="bob@anothercompany.com",
    )
    result_xml, _log, *_ = process_cxml_content(
        xml, country_code="AU", region_code="APAC", detection_method="test"
    )
    assert "alice@realcompany.com" not in result_xml
    assert "bob@anothercompany.com" not in result_xml
    root = lxml_ET.fromstring(result_xml.encode())
    emails = [el.text for el in root.iter()
              if lxml_ET.QName(el.tag).localname == "Email" and el.text]
    assert len(emails) == 2, f"Expected 2 <Email> elements, found {emails}"
    assert emails[0] != emails[1], (
        f"Two different original emails must produce distinct values, got {emails}"
    )

